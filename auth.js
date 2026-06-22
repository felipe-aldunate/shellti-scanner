// ── auth.js ──────────────────────────────────────────────────────────────────
const crypto = require('crypto');
const fs     = require('fs');
const path   = require('path');

// Persistencia en archivo JSON (sobrevive reinicios del servidor)
const DB_PATH = path.join(__dirname, 'data', 'db.json');

function loadDB() {
  try {
    fs.mkdirSync(path.dirname(DB_PATH), { recursive: true });
    if (fs.existsSync(DB_PATH)) {
      return JSON.parse(fs.readFileSync(DB_PATH, 'utf8'));
    }
  } catch(e) { console.error('[auth] loadDB error:', e.message); }
  return { requests: [], users: [], sessions: [] };
}

function saveDB(db) {
  try {
    fs.mkdirSync(path.dirname(DB_PATH), { recursive: true });
    fs.writeFileSync(DB_PATH, JSON.stringify(db, null, 2), 'utf8');
  } catch(e) { console.error('[auth] saveDB error:', e.message); }
}

// db en memoria + persistencia en disco
let db = loadDB();

function generateToken(length = 32) {
  return crypto.randomBytes(length).toString('hex');
}

function createRequest({ name, company, email, reason }) {
  const id = generateToken(8);
  const r  = { id, name, company, email, reason,
    status: 'pending', createdAt: new Date().toISOString(),
    approvedAt: null, expiresAt: null, accessToken: null, durationLabel: null };
  db.requests.unshift(r);
  saveDB(db);
  return r;
}

function getRequests() { return db.requests; }
function getRequest(id) { return db.requests.find(r => r.id === id); }

function approveRequest(id, durationMs, durationLabel, maxScans, resources) {
  const req = getRequest(id);
  if (!req) return null;
  const token = generateToken(24);
  const now   = new Date();
  req.status        = 'approved';
  req.approvedAt    = now.toISOString();
  req.expiresAt     = new Date(now.getTime() + durationMs).toISOString();
  req.accessToken   = token;
  req.durationLabel = durationLabel;
  req.maxScans      = maxScans || null;
  req.resources     = resources || [];

  const existing = db.users.find(u => u.email === req.email);
  if (existing) {
    existing.token      = token;
    existing.expiresAt  = req.expiresAt;
    existing.active     = true;
    existing.maxScans   = maxScans || null;
    existing.scansUsed  = 0;
    existing.resources  = resources || [];
  } else {
    db.users.push({
      email: req.email, name: req.name, company: req.company,
      token, expiresAt: req.expiresAt, active: true,
      createdAt: now.toISOString(),
      maxScans: maxScans || null,
      scansUsed: 0,
      resources: resources || []
    });
  }
  saveDB(db);
  return req;
}

function revokeUser(email) {
  const user = db.users.find(u => u.email === email);
  if (user) { user.active = false; user.expiresAt = new Date().toISOString(); }
  saveDB(db);
  return user;
}

function validateToken(token, { strict = true } = {}) {
  if (!token) return null;
  db = loadDB();
  const user = db.users.find(u => u.token === token && u.active);
  if (!user) return null;

  const expired  = new Date(user.expiresAt) < new Date();
  const scansDone = user.maxScans != null && (user.scansUsed || 0) >= user.maxScans;

  if (strict) {
    // Modo estricto (checkAuth al entrar): bloquea si tiempo o consultas agotados
    if (expired) { user.active = false; saveDB(db); return null; }
    if (scansDone) { user.active = false; saveDB(db); return null; }
  }

  // Siempre retornar el usuario con estado real para que el frontend decida
  return {
    ...user,
    expired,
    scansDone,
    canScan: !expired && !scansDone,
    resources: user.resources || []
  };
}

function incrementScan(token) {
  db = loadDB();
  const user = db.users.find(u => u.token === token && u.active);
  if (!user) return null;
  user.scansUsed = (user.scansUsed || 0) + 1;
  // NO desactivar aquí — el usuario puede seguir viendo resultados
  saveDB(db);
  return user;
}

function createAdminSession() {
  const token = generateToken(32);
  db.sessions.push({ token, createdAt: new Date().toISOString() });
  if (db.sessions.length > 20) db.sessions.shift();
  saveDB(db);
  return token;
}

function validateAdminSession(token) {
  db = loadDB();
  return db.sessions.some(s => s.token === token);
}

function getUsers() { return db.users; }

function updateUserResources(email, resources) {
  db = loadDB();
  const user = db.users.find(u => u.email === email);
  if (!user) return null;
  user.resources = resources || [];
  saveDB(db);
  return user;
}

module.exports = {
  createRequest, getRequests, getRequest, approveRequest,
  revokeUser, validateToken, incrementScan, createAdminSession, validateAdminSession, getUsers, updateUserResources
};
