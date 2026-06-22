require('dotenv').config();

const express        = require('express');
const cors           = require('cors');
const path           = require('path');
const session        = require('express-session');
const passport       = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const Groq           = require('groq-sdk');
const nodemailer     = require('nodemailer');
const auth           = require('./auth');
const scanWebsite    = require('./scanWebsite');
const analyze        = require('./analyze');

const app  = express();
const PORT = process.env.PORT || 3000;

// ── Log de variables al arrancar ──────────────────────────────────────────────
console.log('[env] GMAIL_USER:', process.env.GMAIL_USER || 'NO CONFIGURADO');
console.log('[env] GMAIL_APP_PASSWORD:', process.env.GMAIL_APP_PASSWORD ? 'OK' : 'NO CONFIGURADO');
console.log('[env] GROQ_API_KEY:', process.env.GROQ_API_KEY ? 'OK' : 'NO CONFIGURADO');
console.log('[env] GOOGLE_CLIENT_ID:', process.env.GOOGLE_CLIENT_ID ? 'OK' : 'NO CONFIGURADO');
console.log('[env] BASE_URL:', process.env.BASE_URL || 'NO CONFIGURADO');

// ── CORS ──────────────────────────────────────────────────────────────────────
const ALLOWED_ORIGINS = [
  'https://shellti.com',
  'https://www.shellti.com'
];

app.use(cors({
  origin: function(origin, callback) {
    // Permitir requests sin origin (Railway health checks, same-origin del scanner)
    if (!origin) return callback(null, true);
    if (ALLOWED_ORIGINS.includes(origin)) return callback(null, true);
    console.warn('[cors] Bloqueado origin:', origin);
    callback(new Error('CORS: origen no permitido'));
  },
  credentials: true,
  methods: ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'x-user-token', 'x-admin-token']
}));

app.use(express.json());
app.use(session({
  secret: process.env.SESSION_SECRET || 'shellti-secret-2024',
  resave: false,
  saveUninitialized: false,
  cookie: { secure: process.env.RAILWAY_ENVIRONMENT ? true : false, maxAge: 24 * 60 * 60 * 1000 }
}));
app.use(passport.initialize());
app.use(passport.session());

// ── Google OAuth ──────────────────────────────────────────────────────────────
if (process.env.GOOGLE_CLIENT_ID) {
  passport.use(new GoogleStrategy({
      clientID:     process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL:  `${process.env.BASE_URL}/auth/google/callback`
    },
    (accessToken, refreshToken, profile, done) => {
      const email = profile.emails?.[0]?.value;
      if (email !== process.env.ADMIN_GOOGLE_EMAIL) return done(null, false);
      return done(null, { id: profile.id, name: profile.displayName, email, photo: profile.photos?.[0]?.value });
    }
  ));
  passport.serializeUser((user, done)   => done(null, user));
  passport.deserializeUser((user, done) => done(null, user));
}

// ── Mailer ────────────────────────────────────────────────────────────────────
function canEmail() {
  return !!(process.env.GMAIL_USER && process.env.GMAIL_APP_PASSWORD);
}

function getMailer() {
  const pass = (process.env.GMAIL_APP_PASSWORD || '').replace(/\s+/g, '');
  return nodemailer.createTransport({
    host: 'smtp.gmail.com',
    port: 465,
    secure: true,
    auth: { user: process.env.GMAIL_USER, pass }
  });
}

async function sendMail(to, subject, html) {
  if (!canEmail()) {
    console.warn('[mail] Gmail no configurado — email no enviado a:', to);
    return;
  }
  try {
    const info = await getMailer().sendMail({
      from: `"ShellTI Scanner" <${process.env.GMAIL_USER}>`,
      to, subject, html
    });
    console.log('[mail] Enviado a:', to, '| MessageId:', info.messageId);
  } catch(e) {
    console.error('[mail] ERROR:', e.message);
    console.error('[mail] SMTP config:', {
      user: process.env.GMAIL_USER,
      passLength: process.env.GMAIL_APP_PASSWORD?.length
    });
  }
}

function getBase(req) {
  return process.env.BASE_URL || `${req.protocol}://${req.get('host')}`;
}

// ── Helpers ───────────────────────────────────────────────────────────────────
function extractJSON(raw) {
  const f1 = raw.match(/```json\s*([\s\S]*?)\s*```/);
  if (f1) { try { return JSON.parse(f1[1]); } catch(e) {} }
  const f2 = raw.match(/```\s*([\s\S]*?)\s*```/);
  if (f2) { try { return JSON.parse(f2[1]); } catch(e) {} }
  const b  = raw.match(/\{[\s\S]*\}/);
  if (b)  { try { return JSON.parse(b[0]);  } catch(e) {} }
  try { return JSON.parse(raw); } catch(e) {}
  throw new Error('No se pudo extraer JSON');
}

function buildStatus(user) {
  const expired   = new Date(user.expiresAt) < new Date();
  const scansLeft = user.maxScans != null
    ? Math.max(0, user.maxScans - (user.scansUsed || 0))
    : null;
  return {
    name:      user.name,
    email:     user.email,
    expiresAt: user.expiresAt,
    maxScans:  user.maxScans ?? null,
    scansUsed: user.scansUsed || 0,
    scansLeft,
    expired,
    canScan:   !expired && (scansLeft === null || scansLeft > 0),
    resources: user.resources || []
  };
}

// ── Middleware admin ──────────────────────────────────────────────────────────
function requireAdmin(req, res, next) {
  if (req.isAuthenticated()) return next();
  const token = req.headers['x-admin-token'];
  if (token && auth.validateAdminSession(token)) return next();
  res.status(401).json({ error: 'No autorizado' });
}

// ── Rutas estáticas ───────────────────────────────────────────────────────────
const PUBLIC_DIR = process.env.RAILWAY_ENVIRONMENT ? '/app' : __dirname;

app.get('/', (req, res) => {
  const token = req.query.token;
  if (token) {
    const user = auth.validateToken(token, { strict: false });
    if (user) return res.redirect('/dashboard.html?token=' + token);
  }
  res.sendFile(path.join(PUBLIC_DIR, 'index.html'));
});
app.get('/dashboard.html',   (req, res) => res.sendFile(path.join(PUBLIC_DIR, 'dashboard.html')));
app.get('/performance.html', (req, res) => res.sendFile(path.join(PUBLIC_DIR, 'performance.html')));
app.get('/admin',            (req, res) => res.sendFile(path.join(PUBLIC_DIR, 'admin.html')));
app.get('/admin.html',       (req, res) => res.sendFile(path.join(PUBLIC_DIR, 'admin.html')));
app.use(express.static(PUBLIC_DIR));

// ── Google OAuth routes ───────────────────────────────────────────────────────
app.get('/auth/google', (req, res, next) => {
  if (!process.env.GOOGLE_CLIENT_ID) return res.redirect('/admin?error=oauth_not_configured');
  passport.authenticate('google', { scope: ['profile', 'email'] })(req, res, next);
});

app.get('/auth/google/callback',
  passport.authenticate('google', { failureRedirect: '/admin?error=unauthorized' }),
  (req, res) => res.redirect(`/admin?adminToken=${auth.createAdminSession()}`)
);

app.get('/auth/google/status', (req, res) => {
  if (req.isAuthenticated())
    res.json({ authenticated: true, user: req.user, adminToken: auth.createAdminSession() });
  else
    res.json({ authenticated: false });
});

app.get('/auth/logout', (req, res) => {
  req.logout(() => res.redirect('/'));
});

// ── Auth usuario ──────────────────────────────────────────────────────────────
app.post('/auth/request', async (req, res) => {
  const { name, company, email, reason } = req.body;
  if (!name || !company || !email || !reason)
    return res.status(400).json({ error: 'Todos los campos son requeridos' });

  const r = auth.createRequest({ name, company, email, reason });
  console.log(`[auth] Nueva solicitud: ${name} <${email}>`);

  await sendMail(
    process.env.GMAIL_USER,
    `[Scanner] Nueva solicitud — ${name} (${company})`,
    `<div style="font-family:Arial,sans-serif;max-width:560px">
      <div style="background:#020617;padding:20px;border-bottom:3px solid #00D4FF">
        <h2 style="color:#00D4FF;margin:0">ShellTI Scanner</h2>
      </div>
      <div style="padding:20px;background:#f8fafc;border:1px solid #e2e8f0;border-top:none">
        <p><strong>${name}</strong> (${company}) solicita acceso.</p>
        <p>Email: <a href="mailto:${email}">${email}</a></p>
        <p>Motivo: ${reason}</p>
        <p><a href="${getBase(req)}/admin" style="background:#00D4FF;color:#020617;padding:10px 24px;text-decoration:none;font-weight:700;display:inline-block;margin-top:8px">IR AL ADMIN →</a></p>
      </div>
    </div>`
  );

  res.json({ id: r.id, success: true });
});

app.post('/auth/validate', (req, res) => {
  const { token } = req.body;
  const user = auth.validateToken(token, { strict: false });
  if (!user) return res.json({ valid: false });
  res.json({ valid: true, ...buildStatus(user) });
});

// ── Admin ─────────────────────────────────────────────────────────────────────
app.post('/admin/login', (req, res) => {
  const { password } = req.body;
  if (password !== (process.env.ADMIN_PASSWORD || 'ShellTI2024!'))
    return res.status(401).json({ error: 'Contraseña incorrecta' });
  res.json({ token: auth.createAdminSession() });
});

app.get('/admin/requests', requireAdmin, (req, res) => {
  res.json({ requests: auth.getRequests(), users: auth.getUsers() });
});

app.get('/admin/users', requireAdmin, (req, res) => {
  res.json({ users: auth.getUsers() });
});

app.post('/admin/approve/:id', requireAdmin, async (req, res) => {
  const { durationMs, durationLabel, maxScans, resources } = req.body;
  if (!durationMs) return res.status(400).json({ error: 'Duración requerida' });

  const resourceList = Array.isArray(resources) ? resources : [];
  const r = auth.approveRequest(
    req.params.id, durationMs, durationLabel,
    maxScans ? parseInt(maxScans) : null,
    resourceList
  );
  if (!r) return res.status(404).json({ error: 'Solicitud no encontrada' });

  console.log(`[admin] Aprobado: ${r.email} por ${durationLabel}${maxScans ? ` · ${maxScans} consultas` : ''} · recursos: ${resourceList.join(',') || 'ninguno'}`);

  const accessUrl = `${getBase(req)}/?token=${r.accessToken}`;
  const expires   = new Date(r.expiresAt).toLocaleString('es-CL', {
    dateStyle: 'full', timeStyle: 'short', timeZone: 'America/Santiago'
  });
  const scansInfo = maxScans
    ? `<p style="color:#475569">Consultas disponibles: <strong>${maxScans}</strong></p>`
    : `<p style="color:#475569">Consultas: <strong>ilimitadas</strong></p>`;

  await sendMail(
    r.email,
    `[ShellTI] Tu acceso ha sido aprobado`,
    `<div style="font-family:Arial,sans-serif;max-width:560px">
      <div style="background:#020617;padding:20px;border-bottom:3px solid #00D4FF">
        <h2 style="color:#00D4FF;margin:0">ShellTI Scanner</h2>
      </div>
      <div style="padding:20px;background:#f8fafc;border:1px solid #e2e8f0;border-top:none">
        <p>Hola <strong>${r.name}</strong>,</p>
        <p>Tu solicitud ha sido aprobada por <strong>${durationLabel}</strong>.</p>
        ${scansInfo}
        <div style="background:#f1f5f9;border-left:3px solid #00D4FF;padding:12px 16px;margin:16px 0">
          <p style="margin:0;font-size:11px;color:#64748b;text-transform:uppercase">Acceso válido hasta</p>
          <p style="margin:4px 0 0;font-weight:700;font-size:15px">${expires}</p>
        </div>
        <div style="text-align:center;margin:20px 0">
          <a href="${accessUrl}" style="background:#00D4FF;color:#020617;padding:14px 36px;text-decoration:none;font-weight:700;font-size:14px;display:inline-block">ACCEDER →</a>
        </div>
        <p style="font-size:11px;color:#94a3b8;text-align:center;word-break:break-all">
          <a href="${accessUrl}" style="color:#0284c7">${accessUrl}</a>
        </p>
        <p style="font-size:11px;color:#e05a5a;text-align:center">Enlace personal e intransferible.</p>
      </div>
    </div>`
  );

  res.json({ success: true, emailSent: canEmail() });
});

app.post('/admin/reject/:id', requireAdmin, async (req, res) => {
  const r = auth.getRequest(req.params.id);
  if (!r) return res.status(404).json({ error: 'No encontrada' });
  r.status = 'rejected';
  await sendMail(r.email, '[ShellTI] Solicitud de acceso',
    `<p>Hola ${r.name}, en esta oportunidad no fue posible aprobar tu solicitud. Contacto: <a href="mailto:contacto@shellti.com">contacto@shellti.com</a></p>`
  );
  res.json({ success: true });
});

app.post('/admin/extend-user', requireAdmin, (req, res) => {
  const { email, durationMs, durationLabel, maxScans } = req.body;
  if (!email || !durationMs) return res.status(400).json({ error: 'email y durationMs requeridos' });
  const user = auth.getUsers().find(u => u.email === email);
  if (!user) return res.status(404).json({ error: 'Usuario no encontrado' });
  user.expiresAt = new Date(Date.now() + Number(durationMs)).toISOString();
  if (maxScans != null) { user.maxScans = parseInt(maxScans); user.scansUsed = 0; }
  console.log(`[admin] Acceso extendido: ${email} por ${durationLabel}`);
  res.json({ success: true });
});

app.post('/admin/revoke', requireAdmin, (req, res) => {
  const user = auth.revokeUser(req.body.email);
  if (!user) return res.status(404).json({ error: 'No encontrado' });
  res.json({ success: true });
});

app.post('/admin/update-resources', requireAdmin, (req, res) => {
  const { email, resources } = req.body;
  if (!email) return res.status(400).json({ error: 'email requerido' });
  const user = auth.updateUserResources(email, Array.isArray(resources) ? resources : []);
  if (!user) return res.status(404).json({ error: 'Usuario no encontrado' });
  console.log(`[admin] Recursos actualizados: ${email} → ${(user.resources||[]).join(',')}`);
  res.json({ success: true, resources: user.resources });
});

// ── Verificar acceso para scan ────────────────────────────────────────────────
function checkScanAccess(req, res, next) {
  const token = req.headers['x-user-token'];
  if (!token) return res.status(401).json({ error: 'Token requerido' });
  const user = auth.validateToken(token, { strict: false });
  if (!user) return res.status(401).json({ error: 'Token inválido' });
  const status = buildStatus(user);
  if (status.expired) return res.status(403).json({ error: 'Acceso expirado', code: 'EXPIRED', status });
  if (status.scansLeft !== null && status.scansLeft <= 0)
    return res.status(403).json({ error: 'Consultas agotadas', code: 'NO_SCANS', status });
  req.userToken = token;
  next();
}

// ── Scan ──────────────────────────────────────────────────────────────────────
const scanCache = new Map();
const CACHE_TTL = 24 * 60 * 60 * 1000;

app.post('/scan', checkScanAccess, async (req, res) => {
  let { url } = req.body;
  if (!url) return res.status(400).json({ error: 'URL requerida' });
  if (!/^https?:\/\//i.test(url)) url = 'https://' + url;

  try {
    const domain = new URL(url).hostname;
    const cached = scanCache.get(domain);
    if (cached && (Date.now() - cached.ts) < CACHE_TTL) {
      console.log(`[/scan] Cache hit: ${domain}`);
      auth.incrementScan(req.userToken);
      const updatedUser = auth.validateToken(req.userToken, { strict: false });
      return res.json({ success: true, data: cached.data, crawlerData: cached.crawlerData, fromCache: true, status: updatedUser ? buildStatus(updatedUser) : null });
    }

    auth.incrementScan(req.userToken);

    const crawlerData = await scanWebsite(url);
    const raw         = await analyze(crawlerData);
    const json        = extractJSON(raw);

    if (!json.madurezTecnologica) json.madurezTecnologica = {};
    if (!json.madurezTecnologica.puntuacion) {
      const mapa = { incipiente: 20, basico: 40, intermedio: 60, avanzado: 85 };
      json.madurezTecnologica.puntuacion = mapa[(json.madurezTecnologica.nivel||'').toLowerCase()] || 30;
    }
    if (!json.madurezTecnologica.semaforo) {
      const p = json.madurezTecnologica.puntuacion;
      json.madurezTecnologica.semaforo = p >= 70 ? 'verde' : p >= 40 ? 'amarillo' : 'rojo';
    }

    scanCache.set(domain, { data: json, crawlerData, ts: Date.now() });

    const updatedUser = auth.validateToken(req.userToken, { strict: false });
    res.json({ success: true, data: json, crawlerData, status: updatedUser ? buildStatus(updatedUser) : null });
  } catch(err) {
    console.error('/scan error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// ── Performance (NO cuenta consulta) ─────────────────────────────────────────
app.post('/performance', checkScanAccess, async (req, res) => {
  let { url } = req.body;
  if (!url) return res.status(400).json({ error: 'URL requerida' });
  if (!/^https?:\/\//i.test(url)) url = 'https://' + url;

  const prompt = `Eres un analizador de performance web experto. Analiza técnicamente el sitio: ${url}
Genera datos técnicos REALISTAS y CONSISTENTES. Sé determinístico para el mismo dominio.
Devuelve SOLO JSON válido con: domain, ip, ipv6, asn, isp, country, city, cdn, hosting, httpVersion, serverSoftware, ttfb, dnsResolution, tcpHandshake, tlsHandshake, firstByte, fullyLoaded, domContentLoaded, transferSize, resourceCount, compressionRatio, cacheHitRate, redirectCount, redirectChain, dnsChain, tls (version, cipher, certIssuer, certExpiry, certDaysLeft, hsts, ocspStapling, certTransparency), headers, techStack, waterfall, performanceScore, performanceGrade, recommendations, lighthouseEstimates.`;

  try {
    const groq = new Groq({ apiKey: process.env.GROQ_API_KEY });
    const response = await groq.chat.completions.create({
      model: 'llama-3.3-70b-versatile', temperature: 0, max_tokens: 3000,
      messages: [
        { role: 'system', content: 'Responde SOLO con JSON válido, sin markdown.' },
        { role: 'user', content: prompt }
      ]
    });
    const json = extractJSON(response.choices[0].message.content);
    const updatedUser = auth.validateToken(req.userToken, { strict: false });
    res.json({ success: true, data: json, status: updatedUser ? buildStatus(updatedUser) : null });
  } catch(err) {
    console.error('/performance error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`\nShellTI Scanner corriendo en puerto ${PORT}`);
  console.log(`Admin: ${process.env.BASE_URL || 'http://localhost:' + PORT}/admin`);
  if (!canEmail()) console.warn('Gmail no configurado — emails desactivados');
  if (!process.env.GOOGLE_CLIENT_ID) console.warn('Google OAuth no configurado');
});
