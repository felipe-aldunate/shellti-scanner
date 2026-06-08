const { chromium }  = require('playwright');
const fallbackScan  = require('./fallbackScan');

async function scanWebsite(url) {

  let browser;
  try {
    browser = await chromium.launch({
        headless: true,
        args: [
            '--no-sandbox',
            '--disable-setuid-sandbox',
            '--disable-dev-shm-usage',
            '--disable-http2',                               // Fix ERR_HTTP2_PROTOCOL_ERROR en sitios bancarios
            '--disable-blink-features=AutomationControlled', // Ocultar detección headless
        ]
    });

    const page = await browser.newPage();

    // User-agent realista + headers anti-detección WAF
    await page.setExtraHTTPHeaders({
        'Accept-Language': 'es-CL,es;q=0.9,en-US;q=0.8',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'sec-ch-ua': '"Chromium";v="125", "Google Chrome";v="125", "Not-A.Brand";v="99"',
        'sec-ch-ua-mobile': '?0',
        'sec-ch-ua-platform': '"macOS"',
    });
    await page.setViewportSize({ width: 1280, height: 800 });
    await page.addInitScript(() => {
        Object.defineProperty(navigator, 'webdriver', { get: () => undefined });
    });

    // Intentar primero con domcontentloaded, fallback a load
    let response = null;
    try {
        response = await page.goto(url, { waitUntil: 'domcontentloaded', timeout: 25000 });
    } catch (e1) {
        try {
            response = await page.goto(url, { waitUntil: 'load', timeout: 35000 });
        } catch (e2) {
            await browser.close();
            console.log(`[scanWebsite] Playwright bloqueado (${e1.message}). Usando fallbackScan...`);
            return await fallbackScan(url);
        }
    }

    // Dar tiempo al JS para ejecutarse
    await page.waitForTimeout(2000);

    const headers = response ? response.headers() : {};
    const title   = await page.title();

    const links = await page.$$eval('a', links =>
        links.map(link => ({
            text: (link.innerText || '').trim(),
            href: link.href
        }))
    );

    const forms = await page.$$eval('form', forms =>
        forms.map(form => {
            const fields = [];
            form.querySelectorAll('input, textarea, select')
                .forEach(field => {
                    fields.push({
                        name: field.name || '',
                        type: field.type || field.tagName
                    });
                });
            return { action: form.action || '', fields };
        })
    );

    const pageText   = (await page.textContent('body')).toLowerCase();
    const scripts    = await page.$$eval('script', scripts => scripts.map(s => s.src || s.innerHTML));
    const scriptText = scripts.join(' ');

    await browser.close();

    const trackers = [];
    if (scriptText.includes('googletagmanager'))                       trackers.push('Google Tag Manager');
    if (scriptText.includes('gtag(') || scriptText.includes('google-analytics')) trackers.push('Google Analytics');
    if (scriptText.includes('facebook.net') || scriptText.includes('fbq('))      trackers.push('Meta Pixel');
    if (scriptText.includes('clarity'))   trackers.push('Microsoft Clarity');
    if (scriptText.includes('hotjar'))    trackers.push('Hotjar');
    if (scriptText.includes('linkedin'))  trackers.push('LinkedIn Insight');

    return {
        url,
        title,
        privacyPolicy:   links.some(l => l.text.toLowerCase().includes('privacidad')),
        cookiePolicy:    links.some(l => l.text.toLowerCase().includes('cookie')),
        cookieBanner:    pageText.includes('cookie'),
        rejectButton:    pageText.includes('rechazar') || pageText.includes('reject'),
        rightsMechanism:
            pageText.includes('portabilidad')    ||
            pageText.includes('rectificación')   ||
            pageText.includes('eliminación')     ||
            pageText.includes('supresión'),
        trackers,
        forms,
        securityHeaders: {
            hsts:           !!headers['strict-transport-security'],
            csp:            !!headers['content-security-policy'],
            xFrameOptions:  !!headers['x-frame-options'],
            referrerPolicy: !!headers['referrer-policy']
        }
    };

  } catch (err) {
    if (browser) { try { await browser.close(); } catch(e) {} }
    console.log(`[scanWebsite] Error inesperado (${err.message}). Usando fallbackScan...`);
    return await fallbackScan(url);
  }
}

module.exports = scanWebsite;

if (require.main === module) {
    (async () => {
        const result = await scanWebsite('https://shellti.com');
        console.log(JSON.stringify(result, null, 2));
    })();
}
