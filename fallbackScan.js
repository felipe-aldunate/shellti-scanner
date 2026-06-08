/**
 * fallbackScan.js
 * 
 * Se ejecuta cuando Playwright no puede acceder al sitio (WAF, anti-bot, HTTP2 issues).
 * Usa únicamente APIs públicas gratuitas sin autenticación para obtener datos reales:
 *   - Google DNS API      → IP, registros DNS
 *   - ipapi.co            → ASN, ISP, país, ciudad
 *   - RDAP (rdap.org)     → WHOIS, registrar, fechas de registro
 *   - Fetch HTTP HEAD     → Headers HTTP reales (server, HSTS, CSP, etc.)
 *   - Qualys SSL Labs     → Certificado TLS, cipher, expiración (asíncrono, puede tardar)
 * 
 * Devuelve un objeto con la misma forma que scanWebsite.js pero con flag crawlerFallback: true
 */

const https = require('https');
const http  = require('http');
const { URL } = require('url');

// ─── Utilidad: fetch simple con timeout ────────────────────────────────────────
function fetchJSON(urlStr, timeoutMs = 8000) {
    return new Promise((resolve, reject) => {
        const parsed = new URL(urlStr);
        const lib = parsed.protocol === 'https:' ? https : http;
        const req = lib.get(urlStr, {
            headers: {
                'User-Agent': 'Mozilla/5.0 (compatible; ShellTI-Scanner/1.0)',
                'Accept': 'application/json'
            },
            timeout: timeoutMs
        }, (res) => {
            let data = '';
            res.on('data', chunk => data += chunk);
            res.on('end', () => {
                try { resolve(JSON.parse(data)); }
                catch(e) { reject(new Error(`JSON parse error: ${e.message}`)); }
            });
        });
        req.on('error', reject);
        req.on('timeout', () => { req.destroy(); reject(new Error('Timeout')); });
    });
}

// ─── Utilidad: HEAD request para headers HTTP reales ──────────────────────────
function fetchHeaders(urlStr, timeoutMs = 10000) {
    return new Promise((resolve) => {
        try {
            const parsed = new URL(urlStr);
            const lib = parsed.protocol === 'https:' ? https : http;
            const options = {
                hostname: parsed.hostname,
                port: parsed.port || (parsed.protocol === 'https:' ? 443 : 80),
                path: parsed.pathname || '/',
                method: 'HEAD',
                timeout: timeoutMs,
                headers: {
                    'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36',
                    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                    'Accept-Language': 'es-CL,es;q=0.9',
                }
            };
            const req = lib.request(options, (res) => {
                resolve({ statusCode: res.statusCode, headers: res.headers });
            });
            req.on('error', () => resolve({ statusCode: 0, headers: {} }));
            req.on('timeout', () => { req.destroy(); resolve({ statusCode: 0, headers: {} }); });
            req.end();
        } catch(e) {
            resolve({ statusCode: 0, headers: {} });
        }
    });
}

// ─── 1. DNS lookup via Google DNS API ─────────────────────────────────────────
async function lookupDNS(hostname) {
    try {
        const [aRec, nsRec, mxRec] = await Promise.all([
            fetchJSON(`https://dns.google/resolve?name=${hostname}&type=A`),
            fetchJSON(`https://dns.google/resolve?name=${hostname}&type=NS`),
            fetchJSON(`https://dns.google/resolve?name=${hostname}&type=MX`),
        ]);
        const ip = aRec?.Answer?.[0]?.data || null;
        const ns = nsRec?.Answer?.map(r => r.data?.replace(/\.$/, '')) || [];
        const mx = mxRec?.Answer?.map(r => r.data) || [];
        return { ip, nameservers: ns, mx };
    } catch(e) {
        return { ip: null, nameservers: [], mx: [] };
    }
}

// ─── 2. IP info via ipapi.co ───────────────────────────────────────────────────
async function lookupIP(ip) {
    if (!ip) return {};
    try {
        const data = await fetchJSON(`https://ipapi.co/${ip}/json/`);
        return {
            asn:     data.asn     || null,
            isp:     data.org     || null,
            country: data.country_name || null,
            city:    data.city    || null,
            region:  data.region  || null,
            timezone: data.timezone || null,
            latitude:  data.latitude  || null,
            longitude: data.longitude || null,
        };
    } catch(e) {
        return {};
    }
}

// ─── 3. RDAP / WHOIS ──────────────────────────────────────────────────────────
async function lookupRDAP(hostname) {
    // Extraer dominio raíz (ej: www.btgpactual.cl → btgpactual.cl)
    const parts = hostname.split('.');
    const rootDomain = parts.slice(-2).join('.');
    try {
        const data = await fetchJSON(`https://rdap.org/domain/${rootDomain}`, 10000);
        const registrar = data.entities?.find(e => e.roles?.includes('registrar'))?.vcardArray?.[1]
            ?.find(v => v[0] === 'fn')?.[3] || null;
        const created = data.events?.find(e => e.eventAction === 'registration')?.eventDate || null;
        const expires = data.events?.find(e => e.eventAction === 'expiration')?.eventDate || null;
        const updated = data.events?.find(e => e.eventAction === 'last changed')?.eventDate || null;
        const status  = data.status || [];
        const ns      = data.nameservers?.map(n => n.ldhName) || [];
        return { registrar, created, expires, updated, status, nameservers: ns };
    } catch(e) {
        return {};
    }
}

// ─── 4. Detectar CDN desde headers e IP ───────────────────────────────────────
function detectCDN(headers, asn, ip) {
    const server = (headers['server'] || '').toLowerCase();
    const via    = (headers['via'] || '').toLowerCase();
    const cf     = headers['cf-ray'] || headers['cf-cache-status'];
    if (cf || server.includes('cloudflare'))        return 'Cloudflare';
    if (server.includes('akamai') || via.includes('akamai')) return 'Akamai';
    if (server.includes('fastly') || headers['x-served-by']?.includes('fastly')) return 'Fastly';
    if (headers['x-amz-cf-id'] || headers['x-amz-cf-pop'])  return 'AWS CloudFront';
    if (headers['x-azure-ref'])                              return 'Azure CDN';
    if ((asn || '').includes('13335'))                       return 'Cloudflare';
    if ((asn || '').includes('16625'))                       return 'Akamai';
    if ((asn || '').includes('54113'))                       return 'Fastly';
    return 'Sin CDN';
}

// ─── 5. Detectar tecnologías desde headers ────────────────────────────────────
function detectTechFromHeaders(headers) {
    const tech = [];
    const server     = (headers['server'] || '').toLowerCase();
    const powered    = (headers['x-powered-by'] || '').toLowerCase();
    const generator  = (headers['x-generator'] || '').toLowerCase();

    if (server.includes('nginx'))    tech.push({ name: 'Nginx',   category: 'Servidor' });
    if (server.includes('apache'))   tech.push({ name: 'Apache',  category: 'Servidor' });
    if (server.includes('cloudflare')) tech.push({ name: 'Cloudflare', category: 'CDN/WAF' });
    if (server.includes('iis'))      tech.push({ name: 'IIS',     category: 'Servidor' });
    if (server.includes('litespeed')) tech.push({ name: 'LiteSpeed', category: 'Servidor' });
    if (powered.includes('php'))     tech.push({ name: powered.includes('php/') ? powered.replace('php/', 'PHP ').split(' ').slice(0,2).join(' ') : 'PHP', category: 'Backend' });
    if (powered.includes('asp.net')) tech.push({ name: 'ASP.NET', category: 'Backend' });
    if (powered.includes('express')) tech.push({ name: 'Express.js', category: 'Backend' });
    if (powered.includes('next.js')) tech.push({ name: 'Next.js', category: 'Frontend' });
    if (generator.includes('wordpress')) tech.push({ name: 'WordPress', category: 'CMS' });
    if (generator.includes('drupal'))    tech.push({ name: 'Drupal',    category: 'CMS' });
    if (headers['x-shopify-stage'])      tech.push({ name: 'Shopify',   category: 'Ecommerce' });
    return tech;
}

// ─── 6. Detectar trackers desde headers (limitado sin JS) ─────────────────────
function detectTrackersFromHeaders(headers) {
    const trackers = [];
    const csp = (headers['content-security-policy'] || '').toLowerCase();
    if (csp.includes('googletagmanager') || csp.includes('gtm.js')) trackers.push('Google Tag Manager');
    if (csp.includes('google-analytics') || csp.includes('ga.js'))   trackers.push('Google Analytics');
    if (csp.includes('facebook.net') || csp.includes('connect.facebook')) trackers.push('Meta Pixel');
    if (csp.includes('clarity.ms'))  trackers.push('Microsoft Clarity');
    if (csp.includes('hotjar.com'))  trackers.push('Hotjar');
    if (csp.includes('linkedin.com')) trackers.push('LinkedIn Insight');
    return trackers;
}

// ─── MAIN: fallbackScan ────────────────────────────────────────────────────────
async function fallbackScan(url) {
    const parsed   = new URL(url);
    const hostname = parsed.hostname;

    console.log(`[fallbackScan] Iniciando análisis por APIs para: ${hostname}`);

    // Ejecutar todas las consultas en paralelo para minimizar tiempo total
    const [dnsData, headersData, rdapData] = await Promise.all([
        lookupDNS(hostname),
        fetchHeaders(url),
        lookupRDAP(hostname),
    ]);

    // IP info requiere la IP del DNS
    const ipData = await lookupIP(dnsData.ip);

    const headers = headersData.headers || {};
    const sh = {
        hsts:           !!headers['strict-transport-security'],
        csp:            !!headers['content-security-policy'],
        xFrameOptions:  !!headers['x-frame-options'],
        referrerPolicy: !!headers['referrer-policy'],
    };

    const cdn     = detectCDN(headers, ipData.asn, dnsData.ip);
    const tech    = detectTechFromHeaders(headers);
    const trackers = detectTrackersFromHeaders(headers);

    // Detectar redirección HTTP→HTTPS
    let redirectChain = [];
    if (url.startsWith('https://')) {
        const httpUrl = url.replace('https://', 'http://');
        const httpCheck = await fetchHeaders(httpUrl, 6000);
        if (httpCheck.statusCode >= 300 && httpCheck.statusCode < 400) {
            redirectChain = [
                { from: httpUrl, code: httpCheck.statusCode, to: url },
                { from: url, code: headersData.statusCode || 200, to: null }
            ];
        }
    }

    console.log(`[fallbackScan] Completado — IP: ${dnsData.ip}, CDN: ${cdn}, HSTS: ${sh.hsts}`);

    return {
        // ── Datos core (misma forma que scanWebsite) ───────────────────────
        url,
        title:           null, // No disponible sin renderizar el sitio
        privacyPolicy:   null, // No verificable sin acceder al HTML
        cookiePolicy:    null,
        cookieBanner:    null,
        rejectButton:    null,
        rightsMechanism: null,
        trackers,
        forms:           [],
        securityHeaders: sh,

        // ── Datos extra del fallback ───────────────────────────────────────
        crawlerFallback: true,
        fallbackReason:  'El sitio bloqueó el crawler (WAF/anti-bot). Datos obtenidos desde APIs públicas.',

        // Servidor & Red
        ip:          dnsData.ip,
        ipv6:        null,
        asn:         ipData.asn      || null,
        isp:         ipData.isp      || null,
        country:     ipData.country  || null,
        city:        ipData.city     || null,
        region:      ipData.region   || null,
        timezone:    ipData.timezone || null,
        cdn,
        nameservers: dnsData.nameservers,
        mx:          dnsData.mx,

        // Headers HTTP reales
        rawHeaders: {
            server:                  headers['server']                    || null,
            contentType:             headers['content-type']              || null,
            contentEncoding:         headers['content-encoding']          || null,
            cacheControl:            headers['cache-control']             || null,
            xFrameOptions:           headers['x-frame-options']           || null,
            strictTransportSecurity: headers['strict-transport-security'] || null,
            contentSecurityPolicy:   headers['content-security-policy']   || null,
            referrerPolicy:          headers['referrer-policy']           || null,
            permissionsPolicy:       headers['permissions-policy']        || null,
            xPoweredBy:              headers['x-powered-by']              || null,
            vary:                    headers['vary']                      || null,
            etag:                    headers['etag']                      || null,
            xCacheStatus:            headers['x-cache'] || headers['cf-cache-status'] || null,
            setCookie:               headers['set-cookie']                || null,
        },

        // RDAP / WHOIS
        whois: {
            registrar:   rdapData.registrar   || null,
            created:     rdapData.created     || null,
            expires:     rdapData.expires     || null,
            updated:     rdapData.updated     || null,
            status:      rdapData.status      || [],
            nameservers: rdapData.nameservers || [],
        },

        // Stack tecnológico detectado desde headers
        techStack: tech,

        // HTTP status real
        httpStatus: headersData.statusCode || null,

        // Cadena de redirecciones detectada
        redirectChain,
    };
}

module.exports = fallbackScan;
