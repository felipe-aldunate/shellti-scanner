// ── auth.js ──────────────────────────────────────────────────────────────────
const crypto = require('crypto');
const { initializeApp, getApps, cert } = require('firebase-admin/app');
const { getFirestore } = require('firebase-admin/firestore');

// ── Firebase init ─────────────────────────────────────────────────────────────
if (!getApps().length) {
  initializeApp({
    credential: cert({
      projectId:   process.env.FIREBASE_PROJECT_ID,
      clientEmail: process.env.FIREBASE_CLIENT_EMAIL,
      privateKey:  process.env.FIREBASE_PRIVATE_KEY?.replace(/\\n/g, '\n')
    })
  });
}

const db = getFirestore();
const COL = {
  requests: 'requests',
  users:    'users',
  sessions: 'sessions'
};

function generateToken(length = 32) {
  return crypto.randomBytes(length).toString('hex');
}

// ── REQUESTS ──────────────────────────────────────────────────────────────────
async function createRequest({ name, company, email, reason }) {
  const id = generateToken(8);
  const r  = {
    id, name, company, email, reason,
    status: 'pending', createdAt: new Date().toISOString(),
    approvedAt: null, expiresAt: null, accessToken: null, durationLabel: null
  };
  await db.collection(COL.requests).doc(id).set(r);
  return r;
}

async function getRequests() {
  const snap = await db.collection(COL.requests).orderBy('createdAt', 'desc').get();
  return snap.docs.map(d => d.data());
}

async function getRequest(id) {
  const doc = await db.collection(COL.requests).doc(id).get();
  return doc.exists ? doc.data() : null;
}

async function approveRequest(id, durationMs, durationLabel, maxScans, resources) {
  const req = await getRequest(id);
  if (!req) return null;
  const token = generateToken(24);
  const now   = new Date();
  const updated = {
    ...req,
    status:        'approved',
    approvedAt:    now.toISOString(),
    expiresAt:     new Date(now.getTime() + durationMs).toISOString(),
    accessToken:   token,
    durationLabel,
    maxScans:      maxScans || null,
    resources:     resources || []
  };
  await db.collection(COL.requests).doc(id).set(updated);

  const userSnap = await db.collection(COL.users).where('email', '==', req.email).limit(1).get();
  const userData = {
    email:     req.email,
    name:      req.name,
    company:   req.company,
    token,
    expiresAt: updated.expiresAt,
    active:    true,
    createdAt: now.toISOString(),
    maxScans:  maxScans || null,
    scansUsed: 0,
    resources: resources || []
  };
  if (!userSnap.empty) {
    await userSnap.docs[0].ref.set(userData);
  } else {
    await db.collection(COL.users).add(userData);
  }
  return updated;
}

async function rejectRequest(id) {
  const req = await getRequest(id);
  if (!req) return null;
  await db.collection(COL.requests).doc(id).update({ status: 'rejected' });
  return { ...req, status: 'rejected' };
}

// ── USERS ─────────────────────────────────────────────────────────────────────
async function getUsers() {
  const snap = await db.collection(COL.users).get();
  return snap.docs.map(d => d.data());
}

async function revokeUser(email) {
  const snap = await db.collection(COL.users).where('email', '==', email).limit(1).get();
  if (snap.empty) return null;
  const ref = snap.docs[0].ref;
  await ref.update({ active: false, expiresAt: new Date().toISOString() });
  return snap.docs[0].data();
}

async function updateUserResources(email, resources) {
  const snap = await db.collection(COL.users).where('email', '==', email).limit(1).get();
  if (snap.empty) return null;
  await snap.docs[0].ref.update({ resources: resources || [] });
  return snap.docs[0].data();
}

async function validateToken(token, { strict = true } = {}) {
  if (!token) return null;
  const snap = await db.collection(COL.users)
    .where('token', '==', token)
    .where('active', '==', true)
    .limit(1).get();
  if (snap.empty) return null;
  const user = snap.docs[0].data();
  const ref  = snap.docs[0].ref;

  const expired   = new Date(user.expiresAt) < new Date();
  const scansDone = user.maxScans != null && (user.scansUsed || 0) >= user.maxScans;

  if (strict) {
    if (expired)   { await ref.update({ active: false }); return null; }
    if (scansDone) { await ref.update({ active: false }); return null; }
  }
  return { ...user, expired, scansDone, canScan: !expired && !scansDone, resources: user.resources || [] };
}

async function incrementScan(token) {
  const snap = await db.collection(COL.users)
    .where('token', '==', token)
    .where('active', '==', true)
    .limit(1).get();
  if (snap.empty) return null;
  const user = snap.docs[0].data();
  const newCount = (user.scansUsed || 0) + 1;
  await snap.docs[0].ref.update({ scansUsed: newCount });
  return { ...user, scansUsed: newCount };
}

// ── ADMIN SESSIONS ────────────────────────────────────────────────────────────
function createAdminSession() {
  const token = generateToken(32);
  // Sessions son efímeras — las guardamos en memoria + Firestore como backup
  db.collection(COL.sessions).add({
    token, createdAt: new Date().toISOString()
  }).catch(() => {});
  _sessions.add(token);
  setTimeout(() => _sessions.delete(token), 24 * 3600 * 1000); // 24h
  return token;
}

const _sessions = new Set();

async function validateAdminSession(token) {
  if (_sessions.has(token)) return true;
  // fallback: buscar en Firestore
  const snap = await db.collection(COL.sessions).where('token', '==', token).limit(1).get();
  if (!snap.empty) { _sessions.add(token); return true; }
  return false;
}

module.exports = {
  createRequest, getRequests, getRequest, approveRequest, rejectRequest,
  revokeUser, validateToken, incrementScan,
  createAdminSession, validateAdminSession,
  getUsers, updateUserResources
};
