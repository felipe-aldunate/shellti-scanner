require('dotenv').config();

const express = require('express');
const cors    = require('cors');
const path    = require('path');
const Groq    = require('groq-sdk');

const scanWebsite = require('./scanWebsite');
const analyze     = require('./analyze');

const app  = express();
const PORT = process.env.PORT || 3000;  // Railway inyecta PORT automáticamente

const groq = new Groq({ apiKey: process.env.GROQ_API_KEY });

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname)));

// Ruta raíz → dashboard
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'dashboard.html'));
});

// ── helpers ─────────────────────────────────────────────────────────────────
function extractJSON(raw) {
  const fenced = raw.match(/```json\s*([\s\S]*?)\s*```/);
  if (fenced) { try { return JSON.parse(fenced[1]); } catch(e) {} }
  const fenced2 = raw.match(/```\s*([\s\S]*?)\s*```/);
  if (fenced2) { try { return JSON.parse(fenced2[1]); } catch(e) {} }
  const brace = raw.match(/\{[\s\S]*\}/);
  if (brace) { try { return JSON.parse(brace[0]); } catch(e) {} }
  try { return JSON.parse(raw); } catch(e) {}
  throw new Error('No se pudo extraer JSON de la respuesta del modelo');
}

// ── POST /scan  (auditoría de privacidad) ────────────────────────────────────
app.post('/scan', async (req, res) => {
  let { url } = req.body;
  if (!url) return res.status(400).json({ error: 'URL requerida' });
  if (!/^https?:\/\//i.test(url)) url = 'https://' + url;

  try {
    const crawlerData = await scanWebsite(url);
    const raw         = await analyze(crawlerData);

    console.log('\n=== /scan RAW ===\n', raw.slice(0, 600), '\n=================\n');

    const json = extractJSON(raw);

    if (!json.madurezTecnologica) json.madurezTecnologica = {};
    if (!json.madurezTecnologica.puntuacion) {
      const mapa = { incipiente: 20, basico: 40, intermedio: 60, avanzado: 85 };
      json.madurezTecnologica.puntuacion =
        mapa[(json.madurezTecnologica.nivel || '').toLowerCase()] || 30;
    }
    if (!json.madurezTecnologica.semaforo) {
      const p = json.madurezTecnologica.puntuacion;
      json.madurezTecnologica.semaforo = p >= 70 ? 'verde' : p >= 40 ? 'amarillo' : 'rojo';
    }

    res.json({ success: true, data: json, crawlerData });
  } catch (err) {
    console.error('/scan error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// ── POST /performance  (análisis de performance web) ─────────────────────────
app.post('/performance', async (req, res) => {
  let { url } = req.body;
  if (!url) return res.status(400).json({ error: 'URL requerida' });
  if (!/^https?:\/\//i.test(url)) url = 'https://' + url;

  const prompt = `Eres un analizador de performance web experto. Analiza técnicamente el sitio: ${url}

Genera un objeto JSON con datos técnicos REALISTAS y CONSISTENTES para este dominio.
Sé determinístico: dado el mismo dominio, tus valores deben ser estables.
Basa tus estimaciones en lo que conoces del dominio, su hosting típico, CDN, stack tecnológico probable.
Devuelve SOLO JSON válido, sin markdown, sin texto extra:

{
  "domain": "dominio.com",
  "ip": "X.X.X.X",
  "ipv6": null,
  "asn": "AS12345",
  "isp": "Nombre del ISP",
  "country": "País",
  "city": "Ciudad",
  "cdn": "Cloudflare o Sin CDN",
  "hosting": "Proveedor",
  "httpVersion": "HTTP/2",
  "serverSoftware": "nginx/1.24",
  "ttfb": 180,
  "dnsResolution": 28,
  "tcpHandshake": 45,
  "tlsHandshake": 92,
  "firstByte": 180,
  "fullyLoaded": 2400,
  "domContentLoaded": 1100,
  "transferSize": 850,
  "resourceCount": 42,
  "compressionRatio": 74,
  "cacheHitRate": 82,
  "redirectCount": 1,
  "redirectChain": [
    {"from": "http://dominio.com", "code": 301, "to": "https://dominio.com"},
    {"from": "https://dominio.com", "code": 200, "to": null}
  ],
  "dnsChain": ["8.8.8.8 (DNS Resolver)", "ns1.dominio.com", "X.X.X.X (A record)"],
  "tls": {
    "version": "TLS 1.3",
    "cipher": "TLS_AES_256_GCM_SHA384",
    "certIssuer": "Let's Encrypt",
    "certExpiry": "2026-09-14",
    "certDaysLeft": 101,
    "hsts": true,
    "ocspStapling": true,
    "certTransparency": true
  },
  "headers": {
    "server": "cloudflare",
    "contentEncoding": "gzip",
    "cacheControl": "public, max-age=31536000",
    "xCacheStatus": "HIT",
    "contentSecurityPolicy": "ausente",
    "xFrameOptions": "SAMEORIGIN",
    "strictTransportSecurity": "max-age=31536000; includeSubDomains",
    "referrerPolicy": "strict-origin-when-cross-origin",
    "permissionsPolicy": "ausente",
    "vary": "Accept-Encoding",
    "etag": "presente"
  },
  "techStack": [
    {"name": "WordPress", "category": "CMS", "color": "#cyan"},
    {"name": "PHP 8.1", "category": "Backend", "color": "#purple"},
    {"name": "Nginx", "category": "Servidor", "color": "#muted"}
  ],
  "waterfall": [
    {"resource": "HTML principal", "type": "document", "ms": 180, "color": "#00D4FF"},
    {"resource": "CSS crítico", "type": "stylesheet", "ms": 120, "color": "#A78BFA"},
    {"resource": "main.js bundle", "type": "script", "ms": 340, "color": "#F59E0B"},
    {"resource": "hero-image.webp", "type": "image", "ms": 210, "color": "#34D399"},
    {"resource": "Google Fonts", "type": "font", "ms": 280, "color": "#FF6B6B"},
    {"resource": "analytics.js", "type": "script", "ms": 190, "color": "#F59E0B"}
  ],
  "performanceScore": 72,
  "performanceGrade": "C",
  "recommendations": [
    {
      "level": "critical",
      "title": "TTFB elevado",
      "description": "El tiempo al primer byte supera 200ms. Considerar CDN o caché de servidor.",
      "impact": "alto"
    },
    {
      "level": "warning",
      "title": "Sin compresión Brotli",
      "description": "El servidor usa gzip. Brotli ofrece 15-20% mejor compresión.",
      "impact": "medio"
    },
    {
      "level": "info",
      "title": "Optimizar imágenes",
      "description": "Usar WebP o AVIF puede reducir el peso de imágenes 30-40%.",
      "impact": "medio"
    }
  ],
  "analysisNote": "Estimación basada en patrones técnicos conocidos del dominio.",
  "lighthouseEstimates": {
    "lcp": 2.4,
    "fid": 45,
    "cls": 0.08,
    "fcp": 1.2,
    "tti": 3.8,
    "tbt": 180
  }
}`;

  try {
    const response = await groq.chat.completions.create({
      model: 'llama-3.3-70b-versatile',
      temperature: 0,
      max_tokens: 3000,
      messages: [
        {
          role: 'system',
          content: 'Eres un analizador de performance web. Responde SOLO con JSON válido, sin markdown, sin texto adicional.'
        },
        { role: 'user', content: prompt }
      ]
    });

    const raw  = response.choices[0].message.content;
    console.log('\n=== /performance RAW ===\n', raw.slice(0, 400), '\n========================\n');

    const json = extractJSON(raw);
    res.json({ success: true, data: json });

  } catch (err) {
    console.error('/performance error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// Railway escucha en 0.0.0.0 para aceptar conexiones externas
app.listen(PORT, '0.0.0.0', () => {
  console.log(`Scanner corriendo en http://0.0.0.0:${PORT}`);
});
