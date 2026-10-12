// Browser lifecycle: an emailed code, then a passkey, refresh in an HttpOnly cookie,
// access in memory, one refresh at a time across tabs (Web Locks), results shared with the other tabs
// (BroadcastChannel). No framework and no storage: nothing here can leak a secret to
// localStorage, to the URL or to the log.
'use strict';

// A passkey is bound to a domain, never to an IP address: use localhost, not 127.0.0.1. On localhost
// the API is on port 8080; on any other host (a tunnel in front of scripts/devfront.py) the page and the
// API share one origin.
const LOCAL = ['localhost', '127.0.0.1'].includes(location.hostname);
const API = new URLSearchParams(location.search).get('api') || (LOCAL ? 'http://localhost:8080' : location.origin);
const tabId = Math.random().toString(36).slice(2, 8);
const channel = new BroadcastChannel('airlance-auth');
const REFRESH_MARGIN_MS = 30_000;

// The access token of this tab. It is replaced only by a token that expires later, so a
// late response of an older exchange can never overwrite a newer state.
let access = null; // { token, expiresAt: ms since the epoch }
let flow = null; // { id, resendAfter: ms }
let step = null; // what the server asked for after the email was proven: { next, ticket }

const $ = (id) => document.getElementById(id);
$('tab').textContent = tabId;
$('api').textContent = API;

function log(message) {
  const line = `${new Date().toISOString().slice(11, 23)} [${tabId}] ${message}`;
  $('log').textContent += line + '\n';
  $('log').scrollTop = $('log').scrollHeight;
}

function render() {
  const live = access && access.expiresAt > Date.now();
  $('state').textContent = live ? 'signed in' : 'signed out';
  $('signin').disabled = !!live;
  $('session').disabled = !live && !access;
}

function setAccess(token, expiresAtIso, announce) {
  const expiresAt = Date.parse(expiresAtIso);
  if (access && access.expiresAt >= expiresAt) return false; // not newer: ignore
  access = { token, expiresAt };
  render();
  if (announce) channel.postMessage({ type: 'access', token, expiresAt: expiresAtIso });
  return true;
}

function signedOut(announce) {
  if (access) cancelDeviceSignIn();
  access = null;
  render();
  if (announce) channel.postMessage({ type: 'signedout' });
}

channel.onmessage = ({ data }) => {
  if (data.type === 'access' && setAccess(data.token, data.expiresAt, false)) {
    cancelDeviceSignIn();
    log('took the access token another tab refreshed');
  }
  if (data.type === 'signedout') {
    log('another tab signed out');
    signedOut(false);
  }
};

async function call(method, path, { body, token, stepUp } = {}) {
  const headers = {};
  if (body !== undefined) headers['Content-Type'] = 'application/json';
  if (token) headers.Authorization = `Bearer ${token}`;
  if (stepUp) headers['X-Step-Up'] = stepUp;
  const response = await fetch(API + path, {
    method, headers, credentials: 'include', body: body === undefined ? undefined : JSON.stringify(body),
  });
  const text = await response.text();
  let json = null;
  try { json = text ? JSON.parse(text) : null; } catch { /* not JSON */ }
  return { status: response.status, json };
}

const needsRefresh = () => !access || access.expiresAt - Date.now() < REFRESH_MARGIN_MS;

// ensureAccess returns a usable access token or null. One tab refreshes at a time; a tab that
// waited for the lock first checks whether the tab before it already did the work. A refusal
// ends the session locally: there is no retry loop, the user signs in again.
async function ensureAccess(force = false) {
  if (!force && !needsRefresh()) return access.token;
  return navigator.locks.request('px-refresh', async () => {
    if (!force && !needsRefresh()) return access.token; // another tab refreshed while we waited
    const response = await call('POST', '/v1/token/refresh');
    if (response.status === 200) {
      setAccess(response.json.access_token, response.json.expires_at, true);
      log('refreshed: a new access token and a new cookie');
      return access.token;
    }
    log(`refresh refused (${response.status} ${response.json && response.json.code}): signed out`);
    signedOut(true);
    return null;
  });
}

async function authed(method, path, options = {}) {
  const token = await ensureAccess();
  if (!token) return null;
  return call(method, path, { ...options, token });
}

$('start').onclick = async () => {
  const response = await call('POST', '/v1/auth/email/start', { body: { email: $('email').value.trim() } });
  if (response.status !== 202) return log(`start refused: ${response.status} ${response.json && response.json.code}`);
  flow = { id: response.json.flow_id, resendAfter: Date.parse(response.json.resend_after) };
  log('code sent; the binding cookie was set by the server, not readable here');
};

$('resend').onclick = async () => {
  if (!flow) return log('start first');
  const response = await call('POST', '/v1/auth/email/resend', { body: { flow_id: flow.id } });
  log(`resend: ${response.status} ${response.json && (response.json.code || 'sent')}`);
  if (response.status === 202) flow.resendAfter = Date.parse(response.json.resend_after);
};

// --- WebAuthn plumbing -----------------------------------------------------------------------

const toBytes = (text) => Uint8Array.from(atob(text.replace(/-/g, '+').replace(/_/g, '/')), (c) => c.charCodeAt(0)).buffer;
const toText = (buffer) => btoa(String.fromCharCode(...new Uint8Array(buffer))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

// Browsers that know the JSON forms use them; the others get a small conversion of the fields
// the server sends.
let passkeyRPID = new URL(API).hostname;

function creationOptions(options) {
  passkeyRPID = options.publicKey.rp.id;
  if (PublicKeyCredential.parseCreationOptionsFromJSON) return { publicKey: PublicKeyCredential.parseCreationOptionsFromJSON(options.publicKey) };
  const key = { ...options.publicKey, challenge: toBytes(options.publicKey.challenge) };
  key.user = { ...key.user, id: toBytes(key.user.id) };
  key.excludeCredentials = (key.excludeCredentials || []).map((c) => ({ ...c, id: toBytes(c.id) }));
  return { publicKey: key };
}

function requestOptions(options) {
  passkeyRPID = options.publicKey.rpId || passkeyRPID;
  if (PublicKeyCredential.parseRequestOptionsFromJSON) return { publicKey: PublicKeyCredential.parseRequestOptionsFromJSON(options.publicKey) };
  const key = { ...options.publicKey, challenge: toBytes(options.publicKey.challenge) };
  key.allowCredentials = (key.allowCredentials || []).map((c) => ({ ...c, id: toBytes(c.id) }));
  return { publicKey: key };
}

function credentialJSON(credential) {
  if (credential.toJSON) return credential.toJSON();
  const r = credential.response;
  const response = { clientDataJSON: toText(r.clientDataJSON) };
  if (r.attestationObject) {
    response.attestationObject = toText(r.attestationObject);
    response.transports = r.getTransports ? r.getTransports() : [];
  } else {
    response.authenticatorData = toText(r.authenticatorData);
    response.signature = toText(r.signature);
    if (r.userHandle) response.userHandle = toText(r.userHandle);
  }
  return { id: credential.id, rawId: toText(credential.rawId), type: credential.type, response, clientExtensionResults: credential.getClientExtensionResults() };
}

// ceremony runs a begin route and the browser's own prompt. It returns what the finish route
// needs, or null when the server or the user refused.
async function ceremony(beginPath, body, run, stepUpToken) {
  if (!window.PublicKeyCredential) { log('this browser has no WebAuthn'); return null; }
  // A signed-in route (adding a key) takes the access token and the step-up token.
  const begun = stepUpToken ? await authed('POST', beginPath, { body, stepUp: stepUpToken }) : await call('POST', beginPath, { body });
  if (!begun) return null;
  if (begun.status !== 200) { log(`${beginPath} refused: ${begun.status} ${begun.json && begun.json.code}`); return null; }
  try {
    const credential = await run(begun.json.options);
    return { challenge_id: begun.json.challenge_id, credential: credentialJSON(credential) };
  } catch (error) {
    log(`the passkey prompt ended: ${error.name}`);
    return null;
  }
}

// --- sign-in steps ---------------------------------------------------------------------------

function renderStep() {
  $('next').hidden = !step;
  if (!step) return;
  const enroll = step.next === 'enroll_passkey';
  $('nextTitle').textContent = enroll ? 'Create a passkey to finish signing in' : 'Prove your passkey to finish signing in';
  $('createPasskey').hidden = !enroll;
  $('usePasskey').hidden = enroll;
  $('recoveryBox').hidden = enroll;
}

// The account's stable user handle is the 16 UUID bytes (domain/passkey.UserHandle),
// not its email. Updating the provider's label must never affect authentication.
async function updatePasskeyDetails(user) {
  if (typeof window.PublicKeyCredential?.signalCurrentUserDetails !== 'function') return;
  try {
    const userHandle = Uint8Array.from(user.id.replace(/-/g, '').match(/../g), (byte) => parseInt(byte, 16));
    await PublicKeyCredential.signalCurrentUserDetails({
      rpId: passkeyRPID, userId: toText(userHandle.buffer), name: user.email, displayName: user.email,
    });
  } catch (_) {
    log('the passkey provider could not update its account label; your passkey still works');
  }
}

function signedIn(json, how) {
  cancelDeviceSignIn();
  step = null;
  flow = null;
  renderStep();
  setAccess(json.access_token, json.expires_at, true);
  log(`signed in as ${json.user.email} (${how})`);
  void updatePasskeyDetails(json.user);
}

function showRecoveryCodes(codes) {
  $('codeList').textContent = codes.join('\n');
  $('codes').hidden = false;
}

$('codesSaved').onclick = () => {
  $('codeList').textContent = '';
  $('codes').hidden = true;
};

$('verify').onclick = async () => {
  if (!flow) return log('start first');
  const code = $('code').value.replace(/\s+/g, '');
  const response = await call('POST', '/v1/auth/email/verify', { body: { flow_id: flow.id, code } });
  if (response.status !== 200) return log(`verify refused: ${response.status} ${response.json && response.json.code}`);
  flow = null;
  step = { next: response.json.next, ticket: response.json.ticket };
  renderStep();
  log(`the email is proven; next: ${step.next}. No session yet: a passkey opens it`);
};

$('createPasskey').onclick = async () => {
  const done = await ceremony('/v1/auth/passkey/register/options', { ticket: step.ticket }, (options) => navigator.credentials.create(creationOptions(options)));
  if (!done) return;
  const response = await call('POST', '/v1/auth/passkey/register/verify', {
    body: { ticket: step.ticket, ...done, name: `passkey of tab ${tabId}`, device_name: `browser ${tabId}` },
  });
  if (response.status !== 200) return log(`registration refused: ${response.status} ${response.json && response.json.code}`);
  signedIn(response.json, 'new passkey');
  showRecoveryCodes(response.json.recovery_codes);
};

async function assertPasskey(ticket) {
  const done = await ceremony('/v1/auth/passkey/login/options', undefined, (options) => navigator.credentials.get(requestOptions(options)));
  if (!done) return;
  const response = await call('POST', '/v1/auth/passkey/login/verify', { body: { ...done, ...(ticket ? { ticket } : {}), device_name: `browser ${tabId}` } });
  if (response.status !== 200) {
    log(`passkey refused: ${response.status} ${response.json && response.json.code}`);
    if (response.json?.code === 'invalid_proof') log('choose another saved passkey: a key from a deleted account no longer works; or use your current email and a recovery code');
    return;
  }
  signedIn(response.json, ticket ? 'email and passkey' : 'passkey alone');
}

$('usePasskey').onclick = () => assertPasskey(step.ticket);
$('passkeyLogin').onclick = () => assertPasskey(null);

$('useRecovery').onclick = async () => {
  const response = await call('POST', '/v1/auth/recovery/verify', { body: { ticket: step.ticket, code: $('recoveryCode').value.trim() } });
  $('recoveryCode').value = '';
  if (response.status !== 200) {
    step = null; // a wrong code spends the ticket: prove the email again
    renderStep();
    return log(`recovery code refused: ${response.status} ${response.json && response.json.code}; prove the email again`);
  }
  step = { next: response.json.next, ticket: response.json.ticket };
  renderStep();
  log('recovery code accepted: register a new passkey');
};

// --- my passkeys: sensitive operations ask for a fresh proof first ---------------------------

// stepUp proves a passkey now, for one operation. The token it returns works once, for that
// operation of this session, for five minutes.
async function stepUp(operation) {
  const options = await authed('POST', '/v1/me/step-up/options', { body: { operation } });
  if (!options || options.status !== 200) { log(`step-up refused: ${options && options.status}`); return null; }
  let credential;
  try {
    credential = await navigator.credentials.get(requestOptions(options.json.options));
  } catch (error) {
    log(`the passkey prompt ended: ${error.name}`);
    return null;
  }
  const proof = await authed('POST', '/v1/me/step-up/verify', { body: { challenge_id: options.json.challenge_id, credential: credentialJSON(credential) } });
  if (!proof || proof.status !== 200) { log(`step-up proof refused: ${proof && proof.status}`); return null; }
  log(`fresh proof for ${operation}`);
  return proof.json.step_up_token;
}

async function listKeys() {
  const response = await authed('GET', '/v1/me/passkeys');
  if (!response || response.status !== 200) return;
  const list = $('keyList');
  list.textContent = '';
  for (const key of response.json.passkeys) {
    const item = document.createElement('li');
    item.textContent = `${key.name} (added ${key.created_at.slice(0, 10)}${key.last_used_at ? `, used ${key.last_used_at.slice(0, 10)}` : ''}${key.backed_up ? ', synced' : ''}) `;
    const rename = document.createElement('button');
    rename.textContent = 'Rename';
    rename.onclick = async () => {
      const name = prompt('New name', key.name);
      if (name === null) return;
      const done = await authed('PATCH', `/v1/me/passkeys/${key.id}`, { body: { name } });
      log(`rename: ${done && done.status}`);
      listKeys();
    };
    const remove = document.createElement('button');
    remove.textContent = 'Delete';
    remove.onclick = async () => {
      const token = await stepUp('delete_passkey');
      if (!token) return;
      const done = await authed('DELETE', `/v1/me/passkeys/${key.id}`, { stepUp: token });
      log(`delete: ${done && done.status} ${(done && done.json && done.json.code) || ''}`);
      listKeys();
    };
    item.append(rename, ' ', remove);
    list.append(item);
  }
}

$('listKeys').onclick = listKeys;

$('addKey').onclick = async () => {
  const token = await stepUp('add_passkey');
  if (!token) return;
  const done = await ceremony('/v1/me/passkeys/options', undefined, (options) => navigator.credentials.create(creationOptions(options)), token);
  if (!done) return;
  const response = await authed('POST', '/v1/me/passkeys', { body: { ...done, name: `passkey of tab ${tabId}` }, stepUp: token });
  log(`add passkey: ${response && response.status} ${(response && response.json && response.json.code) || ''}`);
  listKeys();
};

$('newCodes').onclick = async () => {
  const token = await stepUp('regenerate_recovery_codes');
  if (!token) return;
  const response = await authed('POST', '/v1/me/recovery-codes', { stepUp: token });
  if (response && response.status === 200) showRecoveryCodes(response.json.recovery_codes);
  else log(`new codes: ${response && response.status}`);
};

// --- my email: a step-up, a code to the new address, then the move ---------------------------

let emailChange = null; // the flow id of the change in progress

$('changeEmail').onclick = async () => {
  const email = $('newEmail').value.trim();
  if (!email) return;
  const token = await stepUp('change_email');
  if (!token) return;
  const response = await authed('POST', '/v1/me/email/change', { body: { email }, stepUp: token });
  if (response && response.status === 202) {
    emailChange = response.json.flow_id;
    log('a code was mailed to the new address');
  } else {
    log(`change email: ${response && response.status} ${(response && response.json && response.json.code) || ''}`);
  }
};

$('confirmEmail').onclick = async () => {
  if (!emailChange) { log('ask for a code first'); return; }
  const code = $('changeCode').value.replace(/\s+/g, '');
  const response = await authed('POST', '/v1/me/email/change/confirm', { body: { flow_id: emailChange, code } });
  if (response && response.status === 200) {
    emailChange = null;
    $('changeCode').value = '';
    log(`the account now has ${response.json.email}`);
    const me = await authed('GET', '/v1/me');
    if (me?.status === 200) await updatePasskeyDetails(me.json.user);
  } else {
    log(`confirm email: ${response && response.status} ${(response && response.json && response.json.code) || ''}`);
  }
};

// --- sign in with another device: this tab asks, a signed-in phone approves ------------------

let deviceAttempt = null;

function cancelDeviceSignIn() {
  if (!deviceAttempt || deviceAttempt.redeeming) return false;
  deviceAttempt.cancelled = true;
  deviceAttempt.wake?.();
  $('devicePending').hidden = true;
  return true;
}

function drawDeviceQR(link) {
  const qr = qrcodegen.QrCode.encodeText(link, qrcodegen.QrCode.Ecc.MEDIUM);
  const canvas = $('deviceQR');
  const scale = 6;
  const border = 4; // A four-module quiet zone stays white even in dark mode.
  canvas.width = canvas.height = (qr.size + border * 2) * scale;
  const ctx = canvas.getContext('2d');
  ctx.fillStyle = '#fff';
  ctx.fillRect(0, 0, canvas.width, canvas.height);
  ctx.fillStyle = '#000';
  for (let y = 0; y < qr.size; y++) {
    for (let x = 0; x < qr.size; x++) {
      if (qr.getModule(x, y)) ctx.fillRect((x + border) * scale, (y + border) * scale, scale, scale);
    }
  }
  canvas.hidden = false;
}

function waitForDevicePoll(attempt) {
  return new Promise((resolve) => {
    const timer = setTimeout(resolve, 2000);
    attempt.wake = () => { clearTimeout(timer); resolve(); };
  });
}

$('deviceStart').onclick = async () => {
  if (deviceAttempt) return log('a device sign-in is already in progress in this tab');
  if (!navigator.locks) return log('this browser needs Web Locks for device sign-in');
  // The poll-secret cookie belongs to the browser, not the tab. Hold the lock through all
  // responses, including a cancelled start, so a late Set-Cookie cannot replace a newer request.
  await navigator.locks.request('px-device-sign-in', { ifAvailable: true }, async (lock) => {
    if (!lock) return log('another tab is waiting for device sign-in; finish or cancel it first');
    const attempt = { cancelled: false, redeeming: false, wake: null };
    deviceAttempt = attempt;
    $('deviceStart').disabled = true;
    $('deviceCancel').disabled = false;
    $('deviceDetails').hidden = true;
    $('deviceQR').hidden = true;
    $('deviceMessage').textContent = 'Preparing a sign-in request…';
    $('devicePending').hidden = false;
    try {
      const response = await call('POST', '/v1/auth/device/start', { body: { device_name: `browser ${tabId}` } });
      if (attempt.cancelled) return;
      if (response.status !== 200) return log(`device sign-in refused: ${response.status} ${response.json && response.json.code}`);
      const { request_id: id, pairing_code: code, expires_at: expiresAt } = response.json;
      const link = new URL(location.pathname, location.origin);
      if (new URLSearchParams(location.search).has('api')) link.searchParams.set('api', API);
      link.hash = `device=${id}`;
      $('deviceLink').textContent = link.href;
      $('deviceLink').href = link.href;
      $('deviceCode').textContent = code;
      try { drawDeviceQR(link.href); } catch (_) { log('QR could not be drawn; open the link instead'); }
      $('deviceDetails').hidden = false;
      $('deviceMessage').textContent = 'Waiting for approval on your signed-in device.';
      log('asked for a session; the poll secret stays in the browser cookie');
      while (!attempt.cancelled) {
        await waitForDevicePoll(attempt);
        attempt.wake = null;
        if (attempt.cancelled) return;
        if (Date.parse(expiresAt) <= Date.now()) return log('the request expired: ask again');
        const status = await call('POST', '/v1/auth/device/status', { body: { request_id: id } });
        if (attempt.cancelled) return;
        const state = status.status === 200 ? status.json.state : 'refused';
        if (state === 'pending') continue;
        if (state !== 'approved') return log(`device sign-in ended: ${state}`);
        // Redeem has side effects: once sent it cannot be cancelled by hiding the UI.
        attempt.redeeming = true;
        $('deviceCancel').disabled = true;
        $('deviceMessage').textContent = 'Approval received. Finishing sign-in…';
        const signed = await call('POST', '/v1/auth/device/redeem', { body: { request_id: id } });
        if (signed.status !== 200) return log(`device sign-in refused: ${signed.status} ${signed.json && signed.json.code}`);
        signedIn(signed.json, 'another device');
        return;
      }
    } catch (_) {
      if (!attempt.cancelled) log('device sign-in connection failed; start a new request');
    } finally {
      deviceAttempt = null;
      $('devicePending').hidden = true;
      $('deviceStart').disabled = false;
      $('deviceCode').textContent = '';
      $('deviceLink').textContent = '';
      $('deviceLink').removeAttribute('href');
      $('deviceQR').hidden = true;
      $('deviceQR').width = $('deviceQR').height = 0;
    }
  });
};

$('deviceCancel').onclick = () => {
  if (cancelDeviceSignIn()) log('stopped asking; the request lapses by itself');
};

// A link from the new device opens this page with the request id in the fragment, which no server sees.
const linked = /^#device=([A-Za-z0-9_-]{22})$/.exec(location.hash);
if (linked) $('deviceRequest').value = linked[1];

const deviceId = () => $('deviceRequest').value.trim();

$('deviceLook').onclick = async () => {
  const response = await authed('GET', `/v1/device/requests/${encodeURIComponent(deviceId())}`);
  if (response) log(response.status === 200 ? `request from "${response.json.device_name}", valid until ${response.json.expires_at}` : `look: ${response.status} ${response.json && response.json.code}`);
};

$('deviceApprove').onclick = async () => {
  const id = deviceId();
  const code = $('devicePairing').value.trim();
  const token = await stepUp('approve_device');
  if (!token) return;
  const response = await authed('POST', `/v1/device/requests/${encodeURIComponent(id)}/approve`, {
    body: { pairing_code: code }, stepUp: token,
  });
  if (!response) return;
  log(response.status === 204 ? 'approved: the other device is signing in' : `approve: ${response.status} ${response.json && response.json.code}`);
  if (response.status === 204) $('devicePairing').value = '';
};

$('deviceDeny').onclick = async () => {
  const response = await authed('POST', `/v1/device/requests/${encodeURIComponent(deviceId())}/deny`);
  if (response) log(`refuse: ${response.status} ${response.json && response.json.code || ''}`);
};

$('refresh').onclick = () => ensureAccess(true);

$('me').onclick = async () => {
  const response = await authed('GET', '/v1/me');
  if (response) log(`me: ${response.status} ${JSON.stringify(response.json)}`);
};

$('sessions').onclick = async () => {
  const response = await authed('GET', '/v1/sessions');
  if (response) log(`sessions: ${response.status} ${response.json && response.json.sessions.map((s) => `${s.device_name}${s.current ? ' (this)' : ''}`).join(', ')}`);
};

async function signOut(body) {
  const response = await authed('POST', '/v1/signout', { body });
  if (!response) return;
  log(`sign out: ${response.status}`);
  if (response.status === 204) signedOut(true);
}

$('signout').onclick = () => signOut({});
$('signoutAll').onclick = () => signOut({ scope: 'all' });

render();
// A reloaded tab has no access token but may still hold the refresh cookie: try once.
ensureAccess(true).then((token) => log(token ? 'restored the session from the cookie' : 'no session'));

$('deleteAccount').onclick = async () => {
  if (!window.confirm('Permanently delete your account, all sessions and passkeys?')) return;
  const token = await stepUp('delete_account');
  if (!token) return;
  const response = await authed('DELETE', '/v1/me', { stepUp: token });
  if (!response) return;
  log(`delete account: ${response.status}`);
  if (response.status === 204) {
    signedOut(true);
    $('keyList').replaceChildren();
    $('codeList').textContent = '';
    $('codes').hidden = true;
  }
};
