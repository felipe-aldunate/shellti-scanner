require('dotenv').config({ override: false });

const express      = require('express');
const cors         = require('cors');
const path         = require('path');
const Groq         = require('groq-sdk');
const nodemailer   = require('nodemailer');
const auth         = require('./auth');
const scanWebsite  = require('./scanWebsite');
const analyze      = require('./analyze');

const app  = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());

const PUBLIC_DIR = process.env.RAILWAY_ENVIRONMENT ? '/app' : __dirname;
app.use(express.static(PUBLIC_DIR));

app.get('/', (req, res) => res.sendFile(path.join(PUBLIC_DIR, 'index.html')));
app.get('/auth/logout', (req, res) => res.sendFile(path.join(PUBLIC_DIR, 'logout.html')));
app.get('/admin.html', (req, res) => res.sendFile(path.join(PUBLIC_DIR, 'admin.html')));
app.get('/dashboard.html', (req, res) => res.sendFile(path.join(PUBLIC_DIR, 'dashboard.html')));
app.get('/performance.html', (req, res) => res.sendFile(path.join(PUBLIC_DIR, 'performance.html')));

// ── Mailer ────────────────────────────────────────────────────────────────────
// App Password de Google se genera con espacios (ej: "nfrm rzdd eixl vsru")
// nodemailer necesita la password sin espacios para SMTP
const gmailPass = (process.env.GMAIL_APP_PASSWORD || '').replace(/\s+/g, '');

const transporter = nodemailer.createTransport({
  host: 'smtp.gmail.com',
  port: 465,
  secure: true,
  auth: { user: process.env.GMAIL_USER, pass: gmailPass }
});

async function sendMail(to, subject, html) {
  try {
    await transporter.sendMail({ from: `ShellTI Scanner <${process.env.GMAIL_USER}>`, to, subject, html });
    console.log(`[mail] Enviado a ${to}: ${subject}`);
  } catch(e) { console.error('[mail] ERROR:', e.message); }
}

// ── helpers ───────────────────────────────────────────────────────────────────
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

// ── AUTH ──────────────────────────────────────────────────────────────────────
app.post('/auth/request', async (req, res) => {
  const { name, company, email, reason } = req.body;
  if (!name || !company || !email || !reason)
    return res.status(400).json({ error: 'Todos los campos son requeridos' });
  const r = auth.createRequest({ name, company, email, reason });
  // Responder de inmediato — email en background (fallo de SMTP no bloquea)
  res.json({ success: true, id: r.id });
  sendMail(
    process.env.ADMIN_GOOGLE_EMAIL || process.env.GMAIL_USER,
    `Nueva solicitud de acceso: ${name} (${company})`,
    `<h2>Nueva solicitud ShellTI Scanner</h2>
     <p><b>Nombre:</b> ${name}<br><b>Empresa:</b> ${company}<br><b>Email:</b> ${email}<br><b>Motivo:</b> ${reason}</p>
     <p><a href="${process.env.BASE_URL}/admin.html">Revisar en el panel admin →</a></p>`
  ).catch(() => {});
});

app.post('/auth/validate', (req, res) => {
  const { token, strict } = req.body;
  const user = auth.validateToken(token, { strict: strict !== false });
  res.json(user
    ? { valid: true, name: user.name, expiresAt: user.expiresAt,
        maxScans: user.maxScans ?? null, scansUsed: user.scansUsed ?? 0,
        canScan: user.canScan !== false, expired: !!user.expired, scansDone: !!user.scansDone }
    : { valid: false }
  );
});

// ── ADMIN middleware ──────────────────────────────────────────────────────────
function requireAdmin(req, res, next) {
  const token = req.headers['x-admin-token'];
  if (token && auth.validateAdminSession(token)) return next();
  const pwd = req.headers['x-admin-password'];
  if (pwd && pwd === process.env.ADMIN_PASSWORD) {
    const session = auth.createAdminSession();
    res.setHeader('x-admin-token', session);
    return next();
  }
  res.status(401).json({ error: 'No autorizado' });
}

app.post('/admin/login', (req, res) => {
  const { password } = req.body;
  if (password !== process.env.ADMIN_PASSWORD)
    return res.status(401).json({ error: 'Contraseña incorrecta' });
  const token = auth.createAdminSession();
  res.json({ success: true, token });
});

app.get('/admin/requests', requireAdmin, (req, res) => {
  res.json({ requests: auth.getRequests() });
});

app.get('/admin/users', requireAdmin, (req, res) => {
  res.json({ users: auth.getUsers() });
});

app.post('/admin/approve/:id', requireAdmin, async (req, res) => {
  const { durationMs, durationLabel, maxScans } = req.body;
  if (!durationMs) return res.status(400).json({ error: 'Duración requerida' });
  const r = auth.approveRequest(req.params.id, durationMs, durationLabel, maxScans ? parseInt(maxScans) : null);
  if (!r) return res.status(404).json({ error: 'Solicitud no encontrada' });
  const scansTxt = maxScans ? ` con límite de ${maxScans} consultas` : '';
  const accessUrl = `${process.env.BASE_URL}/dashboard.html?token=${r.accessToken}`;
  await sendMail(
    r.email,
    'Tu acceso a ShellTI Scanner ha sido aprobado',
    `<h2>¡Acceso aprobado!</h2>
     <p>Hola ${r.name}, tu solicitud ha sido aprobada por <b>${durationLabel}</b>${scansTxt}.</p>
     <p><a href="${accessUrl}" style="background:#00D4FF;color:#020617;padding:12px 24px;text-decoration:none;font-weight:bold">Acceder al Scanner →</a></p>
     <p style="color:#666;font-size:12px">O copia este enlace: ${accessUrl}</p>`
  );
  res.json({ success: true, request: r });
});

app.post('/admin/reject/:id', requireAdmin, async (req, res) => {
  const requests = auth.getRequests();
  const r = requests.find(x => x.id === req.params.id);
  if (!r) return res.status(404).json({ error: 'Solicitud no encontrada' });
  r.status = 'rejected';
  await sendMail(r.email, 'Solicitud de acceso a ShellTI Scanner',
    `<p>Hola ${r.name}, tu solicitud de acceso no fue aprobada en esta ocasión.</p>`);
  res.json({ success: true });
});

app.post('/admin/revoke', requireAdmin, (req, res) => {
  const { email } = req.body;
  const user = auth.revokeUser(email);
  if (!user) return res.status(404).json({ error: 'Usuario no encontrado' });
  res.json({ success: true });
});

// ── SCAN ──────────────────────────────────────────────────────────────────────
// ── Caché de resultados de auditoría por dominio (evita alucinaciones) ────────
const scanCache = new Map(); // domain → { data, crawlerData, ts }
const CACHE_TTL = 24 * 60 * 60 * 1000; // 24 horas

app.post('/scan', async (req, res) => {
  let { url } = req.body;
  if (!url) return res.status(400).json({ error: 'URL requerida' });
  if (!/^https?:\/\//i.test(url)) url = 'https://' + url;

  // Verificar token si viene
  const userToken = req.headers['x-user-token'];
  if (userToken) {
    const user = auth.validateToken(userToken, { strict: true });
    if (!user) return res.status(403).json({ error: 'Sesión expirada o sin consultas disponibles.', code: 'NO_ACCESS' });
    auth.incrementScan(userToken);
    // Guardar URL en caché para que Performance no cuente otra consulta
    req.app.locals.lastCrawl = req.app.locals.lastCrawl || {};
    const domain = new URL(url).hostname;
    req.app.locals.lastCrawl[userToken] = { url, domain, ts: Date.now() };
  }

  try {
    const domain = new URL(url).hostname;
    const cached = scanCache.get(domain);

    // Si hay caché válido del mismo dominio, retornar sin llamar a Groq
    if (cached && (Date.now() - cached.ts) < CACHE_TTL) {
      console.log(`[/scan] Cache hit: ${domain}`);
      return res.json({ success: true, data: cached.data, crawlerData: cached.crawlerData, fromCache: true });
    }

    const crawlerData = await scanWebsite(url);
    const raw         = await analyze(crawlerData);
    const json        = extractJSON(raw);
    if (!json.madurezTecnologica) json.madurezTecnologica = {};
    if (!json.madurezTecnologica.puntuacion) {
      const mapa = { incipiente: 20, basico: 40, intermedio: 60, avanzado: 85 };
      json.madurezTecnologica.puntuacion = mapa[(json.madurezTecnologica.nivel || '').toLowerCase()] || 30;
    }
    if (!json.madurezTecnologica.semaforo) {
      const p = json.madurezTecnologica.puntuacion;
      json.madurezTecnologica.semaforo = p >= 70 ? 'verde' : p >= 40 ? 'amarillo' : 'rojo';
    }
    // Guardar en caché del servidor
    scanCache.set(domain, { data: json, crawlerData, ts: Date.now() });
    res.json({ success: true, data: json, crawlerData });
  } catch (err) {
    console.error('/scan error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// ── PERFORMANCE ───────────────────────────────────────────────────────────────
app.post('/performance', async (req, res) => {
  let { url } = req.body;
  if (!url) return res.status(400).json({ error: 'URL requerida' });
  if (!/^https?:\/\//i.test(url)) url = 'https://' + url;

  const userToken = req.headers['x-user-token'];
  // Performance NUNCA cuenta consulta — es parte del mismo análisis que Auditoría
  // Solo verificar que el token sea válido (no expirado)
  if (userToken) {
    const user = auth.validateToken(userToken, { strict: false });
    if (!user) return res.status(403).json({ error: 'Token inválido.', code: 'NO_ACCESS' });
  }

  const perfPrompt = `Eres un analizador de performance web experto. Analiza técnicamente el sitio: ${url}
Genera un objeto JSON con datos técnicos REALISTAS y CONSISTENTES para este dominio.
Devuelve SOLO JSON válido, sin markdown, sin texto extra:
{"domain":"dominio.com","ip":"X.X.X.X","ipv6":null,"asn":"AS12345","isp":"ISP","country":"País","city":"Ciudad","cdn":"Cloudflare","hosting":"Proveedor","httpVersion":"HTTP/2","serverSoftware":"nginx","ttfb":180,"dnsResolution":28,"tcpHandshake":45,"tlsHandshake":92,"firstByte":180,"fullyLoaded":2400,"domContentLoaded":1100,"transferSize":850,"resourceCount":42,"compressionRatio":74,"cacheHitRate":82,"redirectCount":1,"redirectChain":[{"from":"http://dominio.com","code":301,"to":"https://dominio.com"}],"dnsChain":["8.8.8.8","ns1.dominio.com"],"tls":{"version":"TLS 1.3","cipher":"TLS_AES_256_GCM_SHA384","certIssuer":"Let's Encrypt","certExpiry":"2026-09-14","certDaysLeft":101,"hsts":true,"ocspStapling":true,"certTransparency":true},"headers":{"server":"cloudflare","contentEncoding":"gzip","cacheControl":"public, max-age=31536000","xCacheStatus":"HIT","contentSecurityPolicy":"ausente","xFrameOptions":"SAMEORIGIN","strictTransportSecurity":"max-age=31536000","referrerPolicy":"strict-origin-when-cross-origin","permissionsPolicy":"ausente","vary":"Accept-Encoding","etag":"presente"},"techStack":[{"name":"Nginx","category":"Servidor"}],"waterfall":[{"resource":"HTML principal","type":"document","ms":180,"color":"#00D4FF"},{"resource":"CSS crítico","type":"stylesheet","ms":120,"color":"#A78BFA"},{"resource":"main.js","type":"script","ms":340,"color":"#F59E0B"},{"resource":"hero-image.webp","type":"image","ms":210,"color":"#34D399"}],"performanceScore":72,"performanceGrade":"C","recommendations":[{"level":"warning","title":"TTFB elevado","description":"Considerar CDN.","impact":"alto"}],"lighthouseEstimates":{"lcp":2.4,"fid":45,"cls":0.08,"fcp":1.2,"tti":3.8,"tbt":180}}`;

  try {
    const groq = new Groq({ apiKey: process.env.GROQ_API_KEY });
    const response = await groq.chat.completions.create({
      model: 'llama-3.3-70b-versatile', temperature: 0, max_tokens: 3000,
      messages: [
        { role: 'system', content: 'Responde SOLO con JSON válido, sin markdown.' },
        { role: 'user', content: perfPrompt }
      ]
    });
    const json = extractJSON(response.choices[0].message.content);
    res.json({ success: true, data: json });
  } catch (err) {
    console.error('/performance error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`Scanner corriendo en http://0.0.0.0:${PORT}`);
  console.log(`GROQ_API_KEY: ${process.env.GROQ_API_KEY ? 'OK (' + process.env.GROQ_API_KEY.slice(0,8) + '...)' : 'MISSING'}`);
});
