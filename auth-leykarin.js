// ── auth-leykarin.js ──────────────────────────────────────────────────────────
const crypto = require('crypto');

const SUPABASE_URL = process.env.SUPABASE_URL || 'https://hdaawdodhdgpojkqmlbm.supabase.co';
const SUPABASE_KEY = process.env.SUPABASE_KEY || '';

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

  const res  = await fetch(url, opts);
  const text = await res.text();
  if (!res.ok) throw new Error(`Supabase ${method} ${table}: ${res.status} ${text}`);
  return text ? JSON.parse(text) : [];
}

function generateToken(length = 32) {
  return crypto.randomBytes(length).toString('hex');
}

// ── REQUESTS ──────────────────────────────────────────────────────────────────
async function createRequest({ name, organization, cargo, email, context }) {
  const id   = generateToken(8);
  const rows = await sb('POST', 'leykarin_requests', {}, {
    id, name, organization, cargo, email,
    context: context || null,
    status: 'pending',
    created_at: new Date().toISOString(),
    approved_at: null, expires_at: null,
    access_token: null, duration_label: null
  });
  return rows[0];
}

async function getRequests() {
  const rows = await sb('GET', 'leykarin_requests', { select: '*', order: 'created_at.desc' });
  return rows.map(toRequest);
}

async function getRequest(id) {
  const rows = await sb('GET', 'leykarin_requests', { select: '*', filter: `id=eq.${id}` });
  return rows[0] ? toRequest(rows[0]) : null;
}

function toRequest(r) {
  return {
    id: r.id, name: r.name, organization: r.organization,
    cargo: r.cargo, email: r.email, context: r.context,
    status: r.status, createdAt: r.created_at, approvedAt: r.approved_at,
    expiresAt: r.expires_at, accessToken: r.access_token,
    durationLabel: r.duration_label
  };
}

async function approveRequest(id, durationMs, durationLabel) {
  const req = await getRequest(id);
  if (!req) return null;

  const token     = generateToken(24);
  const now       = new Date();
  const expiresAt = new Date(now.getTime() + durationMs).toISOString();

  await sb('PATCH', 'leykarin_requests', { filter: `id=eq.${id}` }, {
    status: 'approved',
    approved_at: now.toISOString(),
    expires_at: expiresAt,
    access_token: token,
    duration_label: durationLabel
  });

  const existing = await sb('GET', 'leykarin_users', {
    select: '*', filter: `email=eq.${req.email}`
  });

  const userData = {
    email: req.email, name: req.name,
    organization: req.organization, cargo: req.cargo,
    token, expires_at: expiresAt,
    active: true, created_at: now.toISOString(),
    sessions_used: 0
  };

  if (existing.length) {
    await sb('PATCH', 'leykarin_users', { filter: `email=eq.${req.email}` }, userData);
  } else {
    await sb('POST', 'leykarin_users', {}, userData);
  }

  return { ...req, status: 'approved', expiresAt, accessToken: token, durationLabel };
}

async function rejectRequest(id) {
  const rows = await sb('PATCH', 'leykarin_requests', { filter: `id=eq.${id}` }, { status: 'rejected' });
  return rows[0] ? toRequest(rows[0]) : null;
}

// ── USERS ─────────────────────────────────────────────────────────────────────
async function getUsers() {
  const rows = await sb('GET', 'leykarin_users', { select: '*', order: 'created_at.desc' });
  return rows.map(toUser);
}

function toUser(u) {
  return {
    email: u.email, name: u.name,
    organization: u.organization, cargo: u.cargo,
    token: u.token, expiresAt: u.expires_at,
    active: u.active, createdAt: u.created_at,
    sessionsUsed: u.sessions_used || 0
  };
}

async function revokeUser(email) {
  const rows = await sb('PATCH', 'leykarin_users', { filter: `email=eq.${email}` }, {
    active: false, expires_at: new Date().toISOString()
  });
  return rows[0] ? toUser(rows[0]) : null;
}

async function validateToken(token) {
  if (!token) return null;
  const rows = await sb('GET', 'leykarin_users', {
    select: '*', filter: `token=eq.${token}&active=eq.true`
  });
  if (!rows.length) return null;
  const u       = toUser(rows[0]);
  const expired = new Date(u.expiresAt) < new Date();
  if (expired) {
    await sb('PATCH', 'leykarin_users', { filter: `token=eq.${token}` }, { active: false });
    return null;
  }
  return { ...u, expired: false };
}

async function incrementSession(token) {
  const rows = await sb('GET', 'leykarin_users', {
    select: '*', filter: `token=eq.${token}&active=eq.true`
  });
  if (!rows.length) return null;
  const u        = rows[0];
  const newCount = (u.sessions_used || 0) + 1;
  await sb('PATCH', 'leykarin_users', { filter: `token=eq.${token}` }, { sessions_used: newCount });
  return toUser({ ...u, sessions_used: newCount });
}

module.exports = {
  createRequest, getRequests, getRequest,
  approveRequest, rejectRequest,
  getUsers, revokeUser, validateToken, incrementSession
};
