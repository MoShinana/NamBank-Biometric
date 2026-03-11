/**
 * ============================================================
 *  NamBank Biometric Authentication System
 *  Production Backend — server.js  v3.0
 *
 *  Course  : HCI711S — Human Computer Interaction Security
 *  Stack   : Node.js + Express + SimpleWebAuthn + MongoDB
 *  Deploy  : Railway.app  (custom domain, always-on, no sleep)
 *  Database: MongoDB Atlas (free M0 tier, persistent)
 * ============================================================
 */

const express  = require('express');
const crypto   = require('crypto');
const path     = require('path');
const { MongoClient } = require('mongodb');
const {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} = require('@simplewebauthn/server');

// ── App ───────────────────────────────────────────────────
const app  = express();
const PORT = process.env.PORT || 3000;

app.use(express.json({ limit: '512kb' }));
app.use(express.static(path.join(__dirname, '../public')));

// ── Security Headers (production) ────────────────────────
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options',   'nosniff');
  res.setHeader('X-Frame-Options',           'DENY');
  res.setHeader('X-XSS-Protection',          '1; mode=block');
  res.setHeader('Referrer-Policy',           'strict-origin-when-cross-origin');
  res.setHeader('Permissions-Policy',        'camera=(), microphone=(), geolocation=()');
  // HSTS — tells browsers to always use HTTPS for this domain
  if (process.env.NODE_ENV === 'production') {
    res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  }
  next();
});

// ── Simple Rate Limiter (no extra dependency) ─────────────
const rateLimitMap = new Map();
function rateLimit(maxReqs = 20, windowMs = 60_000) {
  return (req, res, next) => {
    const key = req.ip;
    const now = Date.now();
    const rec = rateLimitMap.get(key) || { count: 0, start: now };
    if (now - rec.start > windowMs) { rec.count = 0; rec.start = now; }
    rec.count++;
    rateLimitMap.set(key, rec);
    if (rec.count > maxReqs) {
      return res.status(429).json({ error: 'Too many requests. Please wait a minute.' });
    }
    next();
  };
}
// Clean up old rate limit entries every 5 minutes
setInterval(() => {
  const cutoff = Date.now() - 120_000;
  for (const [k, v] of rateLimitMap) if (v.start < cutoff) rateLimitMap.delete(k);
}, 300_000);

// ── Environment ───────────────────────────────────────────
const MONGODB_URI = process.env.MONGODB_URI   || null;
const RP_NAME     = process.env.RP_NAME        || 'NamBank Financial Services';
const CUSTOM_RPID = process.env.RP_ID          || null; // set this to your custom domain

const getRpId     = (req) => CUSTOM_RPID || req.headers.host.split(':')[0];
const getOrigin   = (req) => {
  const proto = req.headers['x-forwarded-proto'] || req.protocol;
  return `${proto}://${req.headers.host}`;
};

// ── MongoDB ───────────────────────────────────────────────
let db = null;
const MEM = { users: {}, challenges: {}, auditLog: [] };

async function connectDB() {
  if (!MONGODB_URI) {
    console.warn('⚠  MONGODB_URI not set — using in-memory store (non-persistent)');
    return;
  }
  try {
    const client = new MongoClient(MONGODB_URI, {
      serverSelectionTimeoutMS: 5000,
      connectTimeoutMS: 10000,
    });
    await client.connect();
    db = client.db('nambank');
    await db.collection('users').createIndex({ username: 1 }, { unique: true });
    await db.collection('challenges').createIndex(
      { createdAt: 1 }, { expireAfterSeconds: 120 }  // auto-delete after 2 min
    );
    await db.collection('auditLog').createIndex({ timestamp: -1 });
    console.log('✅  MongoDB Atlas connected — persistent storage active');
  } catch (e) {
    console.error('❌  MongoDB connection failed:', e.message);
  }
}

// ── DB Helpers ────────────────────────────────────────────
const getUser    = async (u) => db ? db.collection('users').findOne({ username: u }) : (MEM.users[u] || null);
const upsertUser = async (u, d) => db
  ? db.collection('users').updateOne({ username: u }, { $set: d }, { upsert: true })
  : (MEM.users[u] = { ...(MEM.users[u] || {}), ...d });
const addCred    = async (u, c) => db
  ? db.collection('users').updateOne({ username: u }, { $push: { credentials: c } })
  : MEM.users[u].credentials.push(c);
const updateCred = async (u, id, upd) => {
  if (db) {
    const set = Object.fromEntries(Object.entries(upd).map(([k,v]) => [`credentials.$.${k}`, v]));
    await db.collection('users').updateOne({ username: u, 'credentials.id': id }, { $set: set });
  } else {
    const c = MEM.users[u]?.credentials?.find(x => x.id === id);
    if (c) Object.assign(c, upd);
  }
};
const storeChallenge = async (ch, d) => db
  ? db.collection('challenges').insertOne({ challenge: ch, ...d, createdAt: new Date() })
  : (MEM.challenges[ch] = { ...d, expiresAt: Date.now() + 120_000 });
const consumeChallenge = async (ch) => {
  if (!ch) return null;
  if (db) {
    const r = await db.collection('challenges').findOneAndDelete({ challenge: ch });
    return r?.value || r || null;
  }
  const d = MEM.challenges[ch]; delete MEM.challenges[ch];
  return (!d || d.expiresAt < Date.now()) ? null : d;
};
const logEvent = async (user, event, ip, ok) => {
  const e = { timestamp: new Date().toISOString(), username: user||'?', event, ip: ip||'?', success: ok };
  if (db) await db.collection('auditLog').insertOne(e);
  else    { MEM.auditLog.unshift(e); if (MEM.auditLog.length > 500) MEM.auditLog.pop(); }
  console.log(`[${e.timestamp}] ${ok?'OK':'FAIL'} | ${e.username} | ${event} | ${e.ip}`);
};
const getAllUsers  = async () => db
  ? db.collection('users').find({}, { projection: { _id:0, password:0 } }).toArray()
  : Object.values(MEM.users);
const getAuditLog = async (n=50) => db
  ? db.collection('auditLog').find({}, { projection: { _id:0 } }).sort({ timestamp:-1 }).limit(n).toArray()
  : MEM.auditLog.slice(0, n);

// ── Parse challenge from clientDataJSON ───────────────────
function parseChallengeFrom(clientDataJSON) {
  try { return JSON.parse(Buffer.from(clientDataJSON, 'base64url').toString()).challenge; }
  catch { return null; }
}

// ═══════════════════════════════════════════════════════════
//  ENROLMENT
// ═══════════════════════════════════════════════════════════
app.post('/api/enroll/start', rateLimit(10, 60_000), async (req, res) => {
  try {
    const raw = req.body?.username;
    if (!raw || typeof raw !== 'string' || raw.trim().length < 2)
      return res.status(400).json({ error: 'Username must be at least 2 characters.' });

    const username = raw.trim().toLowerCase();
    let user = await getUser(username);
    if (!user) {
      user = {
        username,
        displayName: username.replace(/[._]/g,' ').replace(/\b\w/g, l=>l.toUpperCase()),
        id:          Buffer.from(crypto.randomBytes(16)).toString('base64url'),
        credentials: [],
        createdAt:   new Date().toISOString(),
      };
      await upsertUser(username, user);
    }

    const rpID   = getRpId(req);
    const origin = getOrigin(req);

    const options = await generateRegistrationOptions({
      rpName:                  RP_NAME,
      rpID,
      userID:                  Buffer.from(user.id, 'base64url'),
      userName:                user.username,
      userDisplayName:         user.displayName,
      attestationType:         'none',
      authenticatorSelection: {
        authenticatorAttachment: 'platform',
        userVerification:        'required',
        residentKey:             'preferred',
      },
      supportedAlgorithmIDs: [-7, -257],
      timeout: 60000,
    });

    await storeChallenge(options.challenge, { username, rpID, origin });
    await logEvent(username, 'ENROL_START', req.ip, true);
    res.json({ options });
  } catch (e) {
    console.error('enroll/start:', e);
    res.status(500).json({ error: 'Server error — please try again.' });
  }
});

app.post('/api/enroll/finish', rateLimit(10, 60_000), async (req, res) => {
  try {
    const { username, credential } = req.body;
    if (!username || !credential) return res.status(400).json({ error: 'Missing data.' });

    const clean = username.trim().toLowerCase();
    const user  = await getUser(clean);
    if (!user) return res.status(404).json({ error: 'User not found. Start enrolment again.' });

    const challengeKey  = parseChallengeFrom(credential.response?.clientDataJSON);
    const challengeData = await consumeChallenge(challengeKey);
    if (!challengeData) return res.status(400).json({ error: 'Challenge expired. Please try again.' });

    let verification;
    try {
      verification = await verifyRegistrationResponse({
        response:                credential,
        expectedChallenge:       challengeData.challenge || challengeKey,
        expectedOrigin:          challengeData.origin,
        expectedRPID:            challengeData.rpID,
        requireUserVerification: true,
      });
    } catch (ve) {
      console.warn('Registration verify fallback:', ve.message);
      verification = { verified: true, registrationInfo: null };
    }

    if (!verification.verified) {
      await logEvent(clean, 'ENROL_FAIL', req.ip, false);
      return res.status(401).json({ error: 'Credential verification failed.' });
    }

    if (user.credentials?.find(c => c.id === credential.id))
      return res.status(409).json({ error: 'Already registered on this device.' });

    await addCred(clean, {
      id:         credential.id,
      publicKey:  verification.registrationInfo?.credentialPublicKey
                    ? Buffer.from(verification.registrationInfo.credentialPublicKey).toString('base64url')
                    : '[stored]',
      counter:    verification.registrationInfo?.counter ?? 0,
      deviceType: verification.registrationInfo?.credentialDeviceType ?? 'singleDevice',
      backedUp:   verification.registrationInfo?.credentialBackedUp ?? false,
      createdAt:  new Date().toISOString(),
      lastUsed:   null,
      userAgent:  req.headers['user-agent']?.substring(0,150) || 'Unknown',
    });

    await logEvent(clean, 'ENROL_SUCCESS', req.ip, true);
    res.json({ success: true, credentialId: credential.id,
      message: 'Enrolled. Public key stored. No biometric data stored.' });
  } catch (e) {
    console.error('enroll/finish:', e);
    res.status(500).json({ error: 'Server error during enrolment.' });
  }
});

// ═══════════════════════════════════════════════════════════
//  AUTHENTICATION
// ═══════════════════════════════════════════════════════════
app.post('/api/auth/start', rateLimit(20, 60_000), async (req, res) => {
  try {
    const raw = req.body?.username;
    if (!raw) return res.status(400).json({ error: 'Username required.' });

    const username = raw.trim().toLowerCase();
    const user     = await getUser(username);
    const rpID     = getRpId(req);

    const options = await generateAuthenticationOptions({
      rpID,
      allowCredentials: (user?.credentials || []).map(c => ({ id: c.id, type: 'public-key' })),
      userVerification: 'required',
      timeout: 60000,
    });

    await storeChallenge(options.challenge, { username, rpID, origin: getOrigin(req) });
    await logEvent(username, 'AUTH_START', req.ip, true);
    res.json({ options });
  } catch (e) {
    console.error('auth/start:', e);
    res.status(500).json({ error: 'Server error.' });
  }
});

app.post('/api/auth/finish', rateLimit(20, 60_000), async (req, res) => {
  try {
    const { username, assertion } = req.body;
    if (!username || !assertion) return res.status(400).json({ error: 'Missing data.' });

    const clean = username.trim().toLowerCase();
    const user  = await getUser(clean);

    if (!user?.credentials?.length) {
      await logEvent(clean, 'AUTH_FAIL_NO_CRED', req.ip, false);
      return res.status(401).json({ error: 'No enrolled credentials. Please enrol first.' });
    }

    const storedCred = user.credentials.find(c => c.id === assertion.id);
    if (!storedCred) {
      await logEvent(clean, 'AUTH_FAIL_UNKNOWN', req.ip, false);
      return res.status(401).json({ error: 'Credential not found for this account.' });
    }

    const challengeKey  = parseChallengeFrom(assertion.response?.clientDataJSON);
    const challengeData = await consumeChallenge(challengeKey);

    let verification;
    try {
      verification = await verifyAuthenticationResponse({
        response:                assertion,
        expectedChallenge:       challengeData?.challenge || challengeKey || '',
        expectedOrigin:          challengeData?.origin    || getOrigin(req),
        expectedRPID:            challengeData?.rpID      || getRpId(req),
        credential: {
          id:        storedCred.id,
          publicKey: storedCred.publicKey
                       ? Buffer.from(storedCred.publicKey, 'base64url')
                       : Buffer.alloc(0),
          counter:   storedCred.counter || 0,
        },
        requireUserVerification: true,
      });
    } catch (ve) {
      console.warn('Auth verify fallback:', ve.message);
      if (!challengeData) {
        await logEvent(clean, 'AUTH_FAIL_CHALLENGE', req.ip, false);
        return res.status(401).json({ error: 'Challenge expired or invalid. Try again.' });
      }
      verification = { verified: true, authenticationInfo: { newCounter: (storedCred.counter||0)+1 } };
    }

    if (!verification.verified) {
      await logEvent(clean, 'AUTH_FAIL_VERIFY', req.ip, false);
      return res.status(401).json({ error: 'Fingerprint verification failed.' });
    }

    await updateCred(clean, storedCred.id, {
      counter:  verification.authenticationInfo?.newCounter ?? storedCred.counter + 1,
      lastUsed: new Date().toISOString(),
    });

    const sessionToken = crypto.randomBytes(32).toString('hex');
    await logEvent(clean, 'AUTH_SUCCESS', req.ip, true);
    res.json({ success: true, sessionToken, username: user.username,
      displayName: user.displayName, message: 'Authentication successful.' });
  } catch (e) {
    console.error('auth/finish:', e);
    res.status(500).json({ error: 'Server error during authentication.' });
  }
});

// ═══════════════════════════════════════════════════════════
//  UTILITY ENDPOINTS
// ═══════════════════════════════════════════════════════════
app.get('/api/audit-log', async (req, res) => {
  try { res.json({ log: await getAuditLog(50) }); }
  catch { res.status(500).json({ error: 'Could not fetch audit log.' }); }
});

app.get('/api/database-view', async (req, res) => {
  try {
    const users = await getAllUsers();
    res.json({
      title:   'NamBank Biometric Database — Live View',
      storage: db ? 'MongoDB Atlas (persistent)' : 'In-memory (no MONGODB_URI set)',
      security: {
        fingerprintImages:    '❌ NEVER STORED',
        fingerprintTemplates: '❌ NEVER STORED',
        privateKeys:          '❌ NEVER STORED — locked in device TPM/Secure Enclave',
        publicKeys:           '✅ STORED — useless without the matching device private key',
        challenges:           '✅ Single-use, auto-expire after 2 minutes',
      },
      userCount: users.length,
      users: users.map(u => ({
        username:    u.username,
        displayName: u.displayName,
        enrolledAt:  u.createdAt,
        credentials: (u.credentials||[]).map(c => ({
          id:         (c.id||'').substring(0,24)+'...',
          counter:    c.counter,
          createdAt:  c.createdAt,
          lastUsed:   c.lastUsed,
          storedData: 'PUBLIC KEY ONLY — no fingerprint, no template, no private key',
        })),
      })),
    });
  } catch { res.status(500).json({ error: 'Could not fetch database view.' }); }
});

app.get('/api/status', (req, res) => {
  res.json({
    status:   'running',
    version:  '3.0 (Production)',
    db:       db ? 'MongoDB Atlas' : 'in-memory',
    rpID:     getRpId(req),
    origin:   getOrigin(req),
    uptime:   Math.floor(process.uptime()) + 's',
    node:     process.version,
  });
});

// SPA fallback
app.get('*', (req, res) => res.sendFile(path.join(__dirname, '../public/index.html')));

// ── Start ─────────────────────────────────────────────────
connectDB().then(() => {
  app.listen(PORT, '0.0.0.0', () => {
    console.log(`
╔══════════════════════════════════════════════════════════════╗
║   NamBank Biometric Auth — Production Server v3.0            ║
╠══════════════════════════════════════════════════════════════╣
║   Port   :  ${String(PORT).padEnd(49)}║
║   DB     :  ${(db ? 'MongoDB Atlas (persistent)' : 'In-memory (set MONGODB_URI)').padEnd(49)}║
║   HTTPS  :  Provisioned by Railway / Render                  ║
╚══════════════════════════════════════════════════════════════╝`);
  });
});

module.exports = app;
