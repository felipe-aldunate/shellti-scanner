// ── auth.js ──────────────────────────────────────────────────────────────────
const crypto = require('crypto');

const SUPABASE_URL    = process.env.SUPABASE_URL    || 'https://hdaawdodhdgpojkqmlbm.supabase.co';
const SUPABASE_KEY    = process.env.SUPABASE_KEY    || '';
const HEADERS = {
  'Content-Type':  'application/json',
  'apikey':        SUPABASE_KEY,
  'Authorization': `Bearer ${SUPABASE_KEY}`,
  'Prefer':        'return=representation'
};

async function sb(method, table, params = {}, body = null) {
  const { filter, select, order, limit } = params;
  let url = `${SUPABASE_URL}/rest/v1/${table}`;
  const qs = [];
  if (select) qs.push(`select=${select}`);
  if (order)  qs.push(`order=${order}`);
  if (limit)  qs.push(`limit=${limit}`);
  if (filter) qs.push(filter);
  if (qs.length) url += '?' + qs.join('&');

  const opts = { method, headers: { ...HEADERS } };
  if (body) opts.body = JSON.stringify(body);
  if (method === 'PATCH' || method === 'DELETE') {
    opts.headers['Prefer'] = 'return=representation';
  }

  const res = await fetch(url, opts);
  const text = await res.text();
  if (!res.ok) throw new Error(`Supabase ${method} ${table}: ${res.status} ${text}`);
  return text ? JSON.parse(text) : [];
}

function generateToken(length = 32) {
  return crypto.randomBytes(length).toString('hex');
}

// ── REQUESTS ──────────────────────────────────────────────────────────────────
async function createRequest({ name, company, email, reason }) {
  const id = generateToken(8);
  const rows = await sb('POST', 'requests', {}, {
    id, name, company, email, reason,
    status: 'pending', created_at: new Date().toISOString(),
    approved_at: null, expires_at: null, access_token: null, duration_label: null,
    max_scans: null, resources: []
  });
  return rows[0];
}

async function getRequests() {
  const rows = await sb('GET', 'requests', { select: '*', order: 'created_at.desc' });
  return rows.map(toRequest);
}

async function getRequest(id) {
  const rows = await sb('GET', 'requests', { select: '*', filter: `id=eq.${id}` });
  return rows[0] ? toRequest(rows[0]) : null;
}

function toRequest(r) {
  return {
    id: r.id, name: r.name, company: r.company, email: r.email, reason: r.reason,
    status: r.status, createdAt: r.created_at, approvedAt: r.approved_at,
    expiresAt: r.expires_at, accessToken: r.access_token, durationLabel: r.duration_label,
    maxScans: r.max_scans, resources: r.resources || []
  };
}

async function approveRequest(id, durationMs, durationLabel, maxScans, resources) {
  const req = await getRequest(id);
  if (!req) return null;
  const token = generateToken(24);
  const now   = new Date();
  const expiresAt = new Date(now.getTime() + durationMs).toISOString();

  await sb('PATCH', 'requests', { filter: `id=eq.${id}` }, {
    status: 'approved', approved_at: now.toISOString(), expires_at: expiresAt,
    access_token: token, duration_label: durationLabel,
    max_scans: maxScans || null, resources: resources || []
  });

  const existing = await sb('GET', 'users', { select: '*', filter: `email=eq.${req.email}` });
  const userData = {
    email: req.email, name: req.name, company: req.company,
    token, expires_at: expiresAt, active: true,
    created_at: now.toISOString(), max_scans: maxScans || null,
    scans_used: 0, resources: resources || []
  };
  if (existing.length) {
    await sb('PATCH', 'users', { filter: `email=eq.${req.email}` }, userData);
  } else {
    await sb('POST', 'users', {}, userData);
  }
  return { ...req, status: 'approved', expiresAt, accessToken: token, durationLabel };
}

async function rejectRequest(id) {
  const rows = await sb('PATCH', 'requests', { filter: `id=eq.${id}` }, { status: 'rejected' });
  return rows[0] ? toRequest(rows[0]) : null;
}

// ── USERS ─────────────────────────────────────────────────────────────────────
async function getUsers() {
  const rows = await sb('GET', 'users', { select: '*' });
  return rows.map(toUser);
}

function toUser(u) {
  return {
    email: u.email, name: u.name, company: u.company,
    token: u.token, expiresAt: u.expires_at, active: u.active,
    createdAt: u.created_at, maxScans: u.max_scans,
    scansUsed: u.scans_used || 0, resources: u.resources || []
  };
}

async function revokeUser(email) {
  const rows = await sb('PATCH', 'users', { filter: `email=eq.${email}` }, {
    active: false, expires_at: new Date().toISOString()
  });
  return rows[0] ? toUser(rows[0]) : null;
}

async function updateUserResources(email, resources) {
  const rows = await sb('PATCH', 'users', { filter: `email=eq.${email}` }, { resources });
  return rows[0] ? toUser(rows[0]) : null;
}

async function validateToken(token, { strict = true } = {}) {
  if (!token) return null;
  const rows = await sb('GET', 'users', { select: '*', filter: `token=eq.${token}&active=eq.true` });
  if (!rows.length) return null;
  const u = toUser(rows[0]);
  const expired   = new Date(u.expiresAt) < new Date();
  const scansDone = u.maxScans != null && (u.scansUsed || 0) >= u.maxScans;
  if (strict) {
    if (expired || scansDone) {
      await sb('PATCH', 'users', { filter: `token=eq.${token}` }, { active: false });
      return null;
    }
  }
  return { ...u, expired, scansDone, canScan: !expired && !scansDone };
}

async function incrementScan(token) {
  const rows = await sb('GET', 'users', { select: '*', filter: `token=eq.${token}&active=eq.true` });
  if (!rows.length) return null;
  const u = rows[0];
  const newCount = (u.scans_used || 0) + 1;
  await sb('PATCH', 'users', { filter: `token=eq.${token}` }, { scans_used: newCount });
  return toUser({ ...u, scans_used: newCount });
}

// ── ADMIN SESSIONS (en memoria — son efímeras) ────────────────────────────────
const _sessions = new Set();

function createAdminSession() {
  const token = generateToken(32);
  _sessions.add(token);
  setTimeout(() => _sessions.delete(token), 24 * 3600 * 1000);
  return token;
}

async function validateAdminSession(token) {
  return _sessions.has(token);
}

module.exports = {
  createRequest, getRequests, getRequest, approveRequest, rejectRequest,
  revokeUser, validateToken, incrementScan,
  createAdminSession, validateAdminSession,
  getUsers, updateUserResources
};
