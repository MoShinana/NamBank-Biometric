/**
 * NamBank Biometric Authentication System
 * Frontend JavaScript — app.js (Cloud Edition v2.0)
 */
'use strict';

// Load SimpleWebAuthn browser library from CDN
let SWA = null;
async function loadSWA() {
  if (SWA) return SWA;
  return new Promise(resolve => {
    const s = document.createElement('script');
    s.src = 'https://unpkg.com/@simplewebauthn/browser@9.0.1/dist/bundle/index.umd.min.js';
    s.onload  = () => { SWA = window.SimpleWebAuthnBrowser; resolve(SWA); };
    s.onerror = () => resolve(null);
    document.head.appendChild(s);
  });
}

// App state
const AppState = {
  currentUser:  null,
  sessionToken: null,
  authMethod:   null,
  credId:       localStorage.getItem('nb_cred_id')   || null,
  credName:     localStorage.getItem('nb_cred_name') || null,
};

// Base64url helpers
function decodeBase64url(b64url) {
  if (!b64url) return new Uint8Array(0);
  const b64 = b64url.replace(/-/g, '+').replace(/_/g, '/');
  const padded = b64.padEnd(b64.length + (4 - b64.length % 4) % 4, '=');
  const bin = atob(padded);
  return Uint8Array.from(bin, ch => ch.charCodeAt(0));
}

function encodeBase64url(buf) {
  const arr = buf instanceof ArrayBuffer ? new Uint8Array(buf)
            : ArrayBuffer.isView(buf) ? new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength)
            : new Uint8Array(buf);
  let bin = '';
  arr.forEach(b => bin += String.fromCharCode(b));
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

function serialize(val) {
  if (val == null) return val;
  if (val instanceof ArrayBuffer) return encodeBase64url(val);
  if (ArrayBuffer.isView(val)) return encodeBase64url(val);
  if (typeof val !== 'object') return val;
  const out = {};
  for (const k of Object.keys(val)) {
    if (typeof val[k] === 'function') { out[k] = {}; continue; }
    out[k] = serialize(val[k]);
  }
  return out;
}

function classifyError(err) {
  const n = err?.name || '', m = err?.message || '';
  if (n === 'NotAllowedError') return 'Fingerprint scan cancelled or timed out. Please try again.';
  if (n === 'SecurityError')   return 'Security error — site must be served over HTTPS.';
  if (n === 'InvalidStateError') return 'Credential already registered on this device.';
  if (n === 'NotFoundError')   return 'No fingerprint credential found. Please enrol first.';
  if (n === 'AbortError')      return 'Authentication was cancelled.';
  return `Error: ${m || n || 'Unknown error'}`;
}

async function apiPost(url, body) {
  const r = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  const d = await r.json();
  if (!r.ok) throw new Error(d.error || `HTTP ${r.status}`);
  return d;
}

async function checkWebAuthnSupport() {
  if (!window.PublicKeyCredential) return { supported: false, reason: 'WebAuthn not supported' };
  try {
    const p = await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
    return { supported: true, platformAuth: p };
  } catch { return { supported: true, platformAuth: false }; }
}

// Enrolment
async function enrollFingerprint(username) {
  try {
    const lib = await loadSWA();
    const { options } = await apiPost('/api/enroll/start', { username });
    let credential;

    if (lib?.startRegistration) {
      credential = await lib.startRegistration({ optionsJSON: options });
    } else {
      const pk = {
        ...options,
        challenge: decodeBase64url(options.challenge),
        user: { ...options.user, id: decodeBase64url(options.user.id) },
        excludeCredentials: (options.excludeCredentials||[]).map(c=>({...c,id:decodeBase64url(c.id)})),
      };
      const raw = await navigator.credentials.create({ publicKey: pk });
      credential = serialize({
        id: raw.id, rawId: raw.rawId, type: raw.type,
        response: {
          clientDataJSON: raw.response.clientDataJSON,
          attestationObject: raw.response.attestationObject,
          publicKey: raw.response.getPublicKey?.() || null,
          publicKeyAlgorithm: raw.response.getPublicKeyAlgorithm?.() || null,
        },
        authenticatorAttachment: raw.authenticatorAttachment,
        clientExtensionResults: {},
      });
    }

    const result = await apiPost('/api/enroll/finish', { username, credential });
    localStorage.setItem('nb_cred_id', credential.id);
    localStorage.setItem('nb_cred_name', username);
    AppState.credId   = credential.id;
    AppState.credName = username;
    return { success: true, credentialId: credential.id, ...result };
  } catch (err) {
    throw new Error(classifyError(err));
  }
}

// Authentication
async function authenticateFingerprint(username) {
  try {
    const lib = await loadSWA();
    const { options } = await apiPost('/api/auth/start', { username });
    let assertion;

    if (lib?.startAuthentication) {
      assertion = await lib.startAuthentication({ optionsJSON: options });
    } else {
      const pk = {
        ...options,
        challenge: decodeBase64url(options.challenge),
        allowCredentials: (options.allowCredentials||[]).map(c=>({...c,id:decodeBase64url(c.id)})),
      };
      const raw = await navigator.credentials.get({ publicKey: pk });
      assertion = serialize({
        id: raw.id, rawId: raw.rawId, type: raw.type,
        response: {
          clientDataJSON: raw.response.clientDataJSON,
          authenticatorData: raw.response.authenticatorData,
          signature: raw.response.signature,
          userHandle: raw.response.userHandle,
        },
        clientExtensionResults: {},
      });
    }

    const result = await apiPost('/api/auth/finish', { username, assertion });
    AppState.currentUser  = result.username;
    AppState.sessionToken = result.sessionToken;
    AppState.authMethod   = 'WebAuthn Fingerprint';
    return { success: true, ...result };
  } catch (err) {
    throw new Error(classifyError(err));
  }
}

window.NamBankAuth = { enrollFingerprint, authenticateFingerprint, checkWebAuthnSupport, AppState };

// Backwards-compatible aliases for index.html
window.NamBankAuth.classifyWebAuthnError = classifyError;
window.NamBankAuth.apiGet = async (url) => {
  const r = await fetch(url);
  return r.json();
};
