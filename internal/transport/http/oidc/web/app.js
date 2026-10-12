// The sign-in page of the provider. It signs the user in with the browser profile of the /v1 API (an emailed code,
// then a passkey), and hands the access token of that sign-in to /oauth2/login/complete, which answers with where to
// send the browser next. No framework, no storage: the token lives in this closure and the address of this page holds
// only the opaque id of the request.
'use strict';

const $ = (id) => document.getElementById(id);
const requestID = new URLSearchParams(location.search).get('request');
let flowID = null; // the emailed-code flow
let step = null; // what the server asked for after the email was proven: { next, ticket }
let pending = null; // an access token waiting for the user to save their recovery codes

function say(text) { $('message').textContent = text || ''; }
function show(...ids) {
  for (const id of ['choose', 'codeStep', 'nextStep', 'codesStep']) $(id).hidden = !ids.includes(id);
}

async function call(method, path, { body, token } = {}) {
  const headers = {};
  if (body !== undefined) headers['Content-Type'] = 'application/json';
  if (token) headers.Authorization = `Bearer ${token}`;
  const response = await fetch(path, { method, headers, credentials: 'same-origin', body: body === undefined ? undefined : JSON.stringify(body) });
  const text = await response.text();
  let json = null;
  try { json = text ? JSON.parse(text) : null; } catch { /* not JSON */ }
  return { status: response.status, json };
}

// --- WebAuthn plumbing: the JSON forms where the browser has them, a small conversion where it does not ------------

const toBytes = (text) => Uint8Array.from(atob(text.replace(/-/g, '+').replace(/_/g, '/')), (c) => c.charCodeAt(0)).buffer;
const toText = (buffer) => btoa(String.fromCharCode(...new Uint8Array(buffer))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

function creationOptions(options) {
  if (PublicKeyCredential.parseCreationOptionsFromJSON) return { publicKey: PublicKeyCredential.parseCreationOptionsFromJSON(options.publicKey) };
  const key = { ...options.publicKey, challenge: toBytes(options.publicKey.challenge) };
  key.user = { ...key.user, id: toBytes(key.user.id) };
  key.excludeCredentials = (key.excludeCredentials || []).map((c) => ({ ...c, id: toBytes(c.id) }));
  return { publicKey: key };
}

function requestOptions(options) {
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

// ceremony runs a begin route and the browser's own prompt; it returns what the finish route needs, or null.
async function ceremony(beginPath, body, run) {
  if (!window.PublicKeyCredential) { say('This browser cannot use passkeys.'); return null; }
  const begun = await call('POST', beginPath, { body });
  if (begun.status !== 200) { say('That did not work. Try again.'); return null; }
  try {
    const credential = await run(begun.json.options);
    return { challenge_id: begun.json.challenge_id, credential: credentialJSON(credential) };
  } catch (error) {
    say(error.name === 'NotAllowedError' ? 'The passkey prompt was cancelled.' : 'The passkey prompt failed.');
    return null;
  }
}

// --- finishing -------------------------------------------------------------------------------------------------------

async function complete(token) {
  if (!requestID) { say('This page was opened without a sign-in request. Start again from the application.'); return; }
  const done = await call('POST', '/oauth2/login/complete', { token, body: { request_id: requestID } });
  if (done.status === 200 && done.json && done.json.redirect_to) {
    location.replace(done.json.redirect_to);
    return;
  }
  say('The sign-in request expired or does not belong to this browser. Start again from the application.');
}

function showStep(next) {
  step = next;
  const enroll = next.next === 'enroll_passkey';
  show('nextStep');
  $('nextText').textContent = enroll ? 'Create a passkey to finish signing in.' : 'Use your passkey to finish signing in.';
  $('createPasskey').hidden = !enroll;
  $('usePasskey').hidden = enroll;
  $('recoveryForm').hidden = enroll;
}

// --- actions ---------------------------------------------------------------------------------------------------------

async function usePasskey(ticket) {
  say('');
  const done = await ceremony('/v1/auth/passkey/login/options', undefined, (options) => navigator.credentials.get(requestOptions(options)));
  if (!done) return;
  const response = await call('POST', '/v1/auth/passkey/login/verify', { body: { ...done, ...(ticket ? { ticket } : {}), device_name: 'browser' } });
  if (response.status !== 200) { say('That passkey was not accepted. Try another one, or use a recovery code.'); return; }
  await complete(response.json.access_token);
}

$('passkey').onclick = () => usePasskey(null);
$('usePasskey').onclick = () => usePasskey(step && step.ticket);

$('emailForm').onsubmit = async (event) => {
  event.preventDefault();
  say('');
  const response = await call('POST', '/v1/auth/email/start', { body: { email: $('email').value.trim() } });
  if (response.status !== 202) { say(response.status === 429 ? 'Too many tries. Wait a little and try again.' : 'That did not work. Check the address.'); return; }
  flowID = response.json.flow_id;
  show('codeStep');
};

$('codeForm').onsubmit = async (event) => {
  event.preventDefault();
  say('');
  const code = $('code').value.replace(/\s+/g, '');
  const response = await call('POST', '/v1/auth/email/verify', { body: { flow_id: flowID, code } });
  $('code').value = '';
  if (response.status !== 200) { say('That code was not accepted.'); return; }
  flowID = null;
  showStep({ next: response.json.next, ticket: response.json.ticket });
};

$('createPasskey').onclick = async () => {
  say('');
  const done = await ceremony('/v1/auth/passkey/register/options', { ticket: step.ticket }, (options) => navigator.credentials.create(creationOptions(options)));
  if (!done) return;
  const response = await call('POST', '/v1/auth/passkey/register/verify', { body: { ticket: step.ticket, ...done, name: 'passkey', device_name: 'browser' } });
  if (response.status !== 200) { say('The passkey was not accepted. Start again.'); return; }
  // A new account gets recovery codes. They are shown once, so the user is asked to save them before going on.
  pending = response.json.access_token;
  if (response.json.recovery_codes && response.json.recovery_codes.length) {
    $('codeList').textContent = response.json.recovery_codes.join('\n');
    show('codesStep');
  } else {
    await complete(pending);
  }
};

$('codesSaved').onclick = async () => {
  $('codeList').textContent = '';
  const token = pending;
  pending = null;
  await complete(token);
};

$('recoveryForm').onsubmit = async (event) => {
  event.preventDefault();
  say('');
  const response = await call('POST', '/v1/auth/recovery/verify', { body: { ticket: step.ticket, code: $('recovery').value.trim() } });
  $('recovery').value = '';
  if (response.status !== 200) { step = null; show('choose'); say('That recovery code was not accepted. Prove your email again.'); return; }
  showStep({ next: response.json.next, ticket: response.json.ticket });
};

show('choose');
