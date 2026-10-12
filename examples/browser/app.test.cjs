'use strict';

// Run the shipped scripts, with controllable responses and browser-wide locks. No network,
// wall-clock sleeps, storage or production tokens are used by these regressions.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const { test } = require('node:test');

const source = fs.readFileSync(`${__dirname}/app.js`, 'utf8');
const encoder = fs.readFileSync(`${__dirname}/qrcodegen.js`, 'utf8');
const requestID = 'AAECAwQFBgcICQoLDA0ODw';
const started = { request_id: requestID, pairing_code: '123456', expires_at: new Date(Date.now() + 300000).toISOString() };
const signed = { access_token: 'test-access', expires_at: new Date(Date.now() + 60000).toISOString(), user: { email: 'alice@example.test' } };
const tick = () => new Promise(setImmediate);
const deferred = () => {
  let resolve, reject;
  const promise = new Promise((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
};

function browser(locks = new Set(), reply = async (path) => {
  if (path.endsWith('/start')) return { status: 200, json: started };
  if (path.endsWith('/status')) return { status: 200, json: { state: 'pending' } };
  if (path.endsWith('/redeem')) return { status: 200, json: signed };
  return { status: 400, json: {} };
}) {
  const elements = new Map(), timers = new Map(), requests = [], paints = [], broadcasts = [];
  let timerID = 0;
  const ctx = { fillStyle: '', fillRect(...rect) { paints.push({ color: this.fillStyle, rect }); } };
  const node = (id) => {
    if (!elements.has(id)) elements.set(id, {
      hidden: false, disabled: false, textContent: '', value: '',
      removeAttribute(name) { delete this[name]; }, getContext() { return ctx; },
    });
    return elements.get(id);
  };
  const location = new URL('https://auth.example.test/login?api=https%3A%2F%2Fauth.example.test&debug=discard#old');
  const context = vm.createContext({
    document: { getElementById: node }, location, URL, URLSearchParams, Date,
    window: {},
    BroadcastChannel: class { postMessage(value) { broadcasts.push(value); } },
    navigator: { locks: { async request(name, options, callback) {
      const run = callback || options;
      if (locks.has(name)) return run(null);
      locks.add(name);
      try { return await run({ name }); } finally { locks.delete(name); }
    } } },
    setTimeout(fn) { const id = ++timerID; timers.set(id, fn); return id; },
    clearTimeout(id) { timers.delete(id); },
    async fetch(url, options) {
      const path = new URL(url).pathname;
      requests.push({ path, options });
      const response = await reply(path, options);
      return { status: response.status, text: async () => JSON.stringify(response.json) };
    },
  });
  vm.runInContext(encoder, context);
  vm.runInContext(source, context);
  return {
    node, context, locks, requests, paints, broadcasts, timers,
    start: () => node('deviceStart').onclick(),
    cancel: () => node('deviceCancel').onclick(),
    async poll() {
      assert.equal(timers.size, 1, 'exactly one poll is scheduled');
      const [id, fn] = timers.entries().next().value;
      timers.delete(id);
      fn();
      await tick();
    },
  };
}

test('cancelled start holds the cookie lock until its response and never shows a stale QR', async () => {
  const locks = new Set(), startResponse = deferred();
  const page = browser(locks, async (path) => path.endsWith('/start') ? startResponse.promise : { status: 400, json: {} });
  const other = browser(locks);
  await tick();
  const run = page.start();
  await tick();
  page.cancel();
  await other.start();
  assert.equal(other.requests.filter(r => r.path.endsWith('/start')).length, 0);
  startResponse.resolve({ status: 200, json: started });
  await run;
  assert.equal(page.node('devicePending').hidden, true);
  assert.equal(page.timers.size, 0);
  assert.equal(page.paints.length, 0);
  assert.equal(locks.size, 0);
});

test('cancel during status ignores a late approval and does not redeem', async () => {
  const statusResponse = deferred();
  const page = browser(new Set(), async (path) => {
    if (path.endsWith('/start')) return { status: 200, json: started };
    if (path.endsWith('/status')) return statusResponse.promise;
    return { status: 400, json: {} };
  });
  await tick();
  const run = page.start();
  await tick();
  await page.poll();
  page.cancel();
  statusResponse.resolve({ status: 200, json: { state: 'approved' } });
  await run;
  assert.equal(page.requests.filter(r => r.path.endsWith('/redeem')).length, 0);
  assert.equal(page.broadcasts.filter(m => m.type === 'access').length, 0);
  assert.equal(page.timers.size, 0);
  assert.equal(page.node('devicePending').hidden, true);
});

test('one tab owns the request until cancellation, then another can start', async () => {
  const locks = new Set(), page = browser(locks), other = browser(locks);
  await tick();
  const run = page.start();
  await tick();
  await other.start();
  assert.equal(other.requests.filter(r => r.path.endsWith('/start')).length, 0);
  assert.match(other.node('log').textContent, /another tab/);
  page.cancel();
  await run;
  assert.equal(page.timers.size, 0);
  const next = other.start();
  await tick();
  assert.equal(other.requests.filter(r => r.path.endsWith('/start')).length, 1);
  other.cancel();
  await next;
});

test('repeated clicks cannot replace the active request', async () => {
  const page = browser();
  await tick();
  const run = page.start();
  await tick();
  await page.start();
  assert.equal(page.requests.filter(r => r.path.endsWith('/start')).length, 1);
  page.cancel();
  await run;
});

test('approved request redeems once and cancellation is disabled while redeem is in flight', async () => {
  const redemption = deferred();
  const page = browser(new Set(), async (path) => {
    if (path.endsWith('/start')) return { status: 200, json: started };
    if (path.endsWith('/status')) return { status: 200, json: { state: 'approved' } };
    if (path.endsWith('/redeem')) return redemption.promise;
    return { status: 400, json: {} };
  });
  await tick();
  const run = page.start();
  await tick();
  await page.poll();
  assert.equal(page.node('deviceCancel').disabled, true);
  assert.equal(page.locks.has('px-device-sign-in'), true);
  page.cancel();
  redemption.resolve({ status: 200, json: signed });
  await run;
  assert.equal(page.requests.filter(r => r.path.endsWith('/redeem')).length, 1);
  assert.equal(page.broadcasts.filter(m => m.type === 'access').length, 1);
  assert.equal(page.locks.size, 0);
  assert.equal(page.timers.size, 0);
});

test('network failure releases the request and allows retry', async () => {
  let fail = true;
  const page = browser(new Set(), async (path) => {
    if (path.endsWith('/start')) return { status: 200, json: started };
    if (path.endsWith('/status') && fail) throw new Error('offline');
    return { status: 400, json: {} };
  });
  await tick();
  const run = page.start();
  await tick();
  await page.poll();
  await run;
  assert.equal(page.node('deviceStart').disabled, false);
  assert.equal(page.locks.size, 0);
  fail = false;
  const retry = page.start();
  await tick();
  page.cancel();
  await retry;
  assert.equal(page.requests.filter(r => r.path.endsWith('/start')).length, 2);
});

test('denial and expiry finish without redeeming', async () => {
  for (const state of ['denied', 'expired']) {
    const page = browser(new Set(), async (path) => {
      if (path.endsWith('/start')) return { status: 200, json: started };
      if (path.endsWith('/status')) return { status: 200, json: { state } };
      return { status: 400, json: {} };
    });
    await tick();
    const run = page.start();
    await tick();
    await page.poll();
    await run;
    assert.equal(page.requests.filter(r => r.path.endsWith('/redeem')).length, 0);
    assert.equal(page.locks.size, 0);
  }
});

test('QR and fallback link contain only the request reference and explicit API configuration', async () => {
  const page = browser();
  await tick();
  const run = page.start();
  await tick();
  const link = new URL(page.node('deviceLink').href);
  assert.equal(link.hash, `#device=${requestID}`);
  assert.deepEqual([...link.searchParams.keys()], ['api']);
  assert.equal(link.href.includes(started.pairing_code), false);
  assert.equal(page.paints[0].color, '#fff');
  assert.ok(page.paints.slice(1).every(p => p.color === '#000' && p.rect[0] >= 24 && p.rect[1] >= 24));
  assert.equal(page.node('deviceQR').hidden, false);
  page.cancel();
  await run;
  assert.equal(page.node('deviceQR').width, 0);
  assert.equal(page.node('deviceLink').href, undefined);
});

test('sign-in broadcast from another tab stops a pending device request', async () => {
  const page = browser();
  await tick();
  const run = page.start();
  await tick();
  page.context.message = { type: 'access', token: signed.access_token, expiresAt: signed.expires_at };
  vm.runInContext('channel.onmessage({ data: message })', page.context);
  await run;
  assert.equal(page.timers.size, 0);
  assert.equal(page.locks.size, 0);
  assert.equal(page.requests.filter(r => r.path.endsWith('/redeem')).length, 0);
});

test('another signed-out tab checking its refresh cookie does not cancel QR sign-in', async () => {
  const page = browser();
  await tick();
  const run = page.start();
  await tick();
  vm.runInContext("channel.onmessage({ data: { type: 'signedout' } })", page.context);
  assert.equal(page.node('devicePending').hidden, false);
  assert.equal(page.locks.has('px-device-sign-in'), true);
  page.cancel();
  await run;
});

test('approval stays bound to the request and code chosen before the passkey prompt', async () => {
  const proof = deferred();
  const page = browser(new Set(), async (path) => {
    if (path.endsWith('/refresh')) return { status: 200, json: signed };
    return { status: 204, json: null };
  });
  await tick();
  page.context.proof = proof.promise;
  vm.runInContext('stepUp = async () => proof', page.context);
  page.node('deviceRequest').value = requestID;
  page.node('devicePairing').value = '123456';
  const approve = page.node('deviceApprove').onclick();
  page.node('deviceRequest').value = 'another-request';
  page.node('devicePairing').value = '654321';
  proof.resolve('test-proof');
  await approve;
  const sent = page.requests.find(r => r.path.endsWith('/approve'));
  assert.equal(sent.path, `/v1/device/requests/${requestID}/approve`);
  assert.equal(JSON.parse(sent.options.body).pairing_code, '123456');
});
