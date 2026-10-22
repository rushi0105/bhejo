// End-to-end test for the browser UI.
//
// Two real receivers, two real discovery sockets and two real UI servers. One
// UI stages a file and sends it; the other UI receives the request, accepts it
// from the HTTP API, and the bytes are compared afterwards.
//
// Also asserts the two attacks a localhost UI has to survive: a cross-origin
// POST from a hostile web page, and a DNS-rebinding request with a forged Host.

import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { after, before, describe, it } from 'node:test';

import { Discovery } from '../src/discovery.mjs';
import { loadIdentity } from '../src/identity.mjs';
import { Receiver } from '../src/receiver.mjs';
import { TrustStore } from '../src/trust.mjs';
import { UiServer } from '../src/ui.mjs';
import { sleep } from '../src/util.mjs';

const state = {
  dirs: [],
  receivers: [],
  discoveries: [],
  uis: [],
  udpPort: 0,
};

const tmp = (prefix) => fs.mkdtempSync(path.join(os.tmpdir(), prefix));

async function waitFor(check, { timeout = 10_000, interval = 100 } = {}) {
  const deadline = Date.now() + timeout;
  let lastError = null;
  while (Date.now() < deadline) {
    try {
      const value = await check();
      if (value) return value;
    } catch (err) {
      lastError = err;
    }
    await sleep(interval);
  }
  throw new Error(`timed out waiting for condition${lastError ? `: ${lastError.message}` : ''}`);
}

async function api(ui, route, options = {}) {
  const res = await fetch(`${ui.url}${route}`, {
    ...options,
    headers: { 'x-bhejo-token': ui.token, ...(options.headers ?? {}) },
  });
  const text = await res.text();
  let json = null;
  try {
    json = text ? JSON.parse(text) : null;
  } catch {
    /* not JSON */
  }
  return { status: res.status, json, text };
}

/** Raw request so the Host header can be forged; fetch() refuses to set it. */
function rawRequest({ port, method, route, headers = {}, body }) {
  return new Promise((resolve, reject) => {
    const req = http.request(
      { host: '127.0.0.1', port, method, path: route, headers },
      (res) => {
        const chunks = [];
        res.on('data', (chunk) => chunks.push(chunk));
        res.on('end', () => resolve({ status: res.statusCode, body: Buffer.concat(chunks).toString('utf8') }));
      },
    );
    req.on('error', reject);
    if (body !== undefined) req.write(body);
    req.end();
  });
}

describe('browser UI', () => {
  before(async () => {
    const home = tmp('bhejo-ui-home-');
    state.dirs.push(home);
    process.env.BHEJO_HOME = path.join(home, 'state');

    const inboxA = tmp('bhejo-ui-inbox-a-');
    const inboxB = tmp('bhejo-ui-inbox-b-');
    state.dirs.push(inboxA, inboxB);

    state.udpPort = 55100 + Math.floor(Math.random() * 500);

    const alpha = new Receiver({
      identity: loadIdentity({ ephemeral: true, alias: 'Alpha-PC' }),
      dir: inboxA,
      port: 0,
    });
    const bravo = new Receiver({
      identity: loadIdentity({ ephemeral: true, alias: 'Bravo-PC' }),
      dir: inboxB,
      port: 0,
    });

    state.receivers.push(alpha, bravo);
    await alpha.start();
    await bravo.start();

    const mkDiscovery = (receiver) =>
      new Discovery({
        alias: receiver.identity.alias,
        deviceType: 'desktop',
        httpPort: receiver.port,
        fingerprint: receiver.identity.fingerprint,
        port: state.udpPort,
        announceIntervalMs: 350,
        peerTtlMs: 6000,
      });

    const discA = mkDiscovery(alpha);
    const discB = mkDiscovery(bravo);
    state.discoveries.push(discA, discB);
    await discA.start();
    await discB.start();

    const uiA = new UiServer({
      identity: alpha.identity,
      receiver: alpha,
      discovery: discA,
      trust: new TrustStore(path.join(home, 'trust-a')),
      port: 0,
    });
    const uiB = new UiServer({
      identity: bravo.identity,
      receiver: bravo,
      discovery: discB,
      trust: new TrustStore(path.join(home, 'trust-b')),
      port: 0,
    });
    state.uis.push(uiA, uiB);

    await uiA.start();
    await uiB.start();

    // Bravo asks its own UI before accepting, exactly like the CLI wires it up.
    bravo.onIncoming = (request) => uiB.decide(request);

    state.alpha = alpha;
    state.bravo = bravo;
    state.uiA = uiA;
    state.uiB = uiB;
    state.inboxA = inboxA;
    state.inboxB = inboxB;

    // Wait until each side actually sees the other over multicast.
    await waitFor(() => discA.peers().some((p) => p.alias === 'Bravo-PC'));
    await waitFor(() => discB.peers().some((p) => p.alias === 'Alpha-PC'));
  });

  after(async () => {
    for (const ui of state.uis) await ui.stop().catch(() => {});
    for (const discovery of state.discoveries) await discovery.stop().catch(() => {});
    for (const receiver of state.receivers) await receiver.stop().catch(() => {});
    for (const dir of state.dirs) await fs.promises.rm(dir, { recursive: true, force: true }).catch(() => {});
  });

  it('serves the page and the state document', async () => {
    const page = await fetch(state.uiA.url);
    assert.equal(page.status, 200);
    const html = await page.text();
    assert.match(html, /bhejo/i);
    assert.ok(html.includes(state.uiA.token), 'the page must carry the per-run token');

    const { status, json } = await api(state.uiA, '/api/state');
    assert.equal(status, 200);
    assert.equal(json.device.alias, 'Alpha-PC');
    assert.equal(json.device.port, state.alpha.port);
    assert.ok(json.peers.some((p) => p.alias === 'Bravo-PC'), 'peer list should include Bravo');
  });

  it('refuses API calls without the token', async () => {
    const res = await fetch(`${state.uiA.url}/api/state`);
    assert.equal(res.status, 403);

    const staged = await fetch(`${state.uiA.url}/api/stage?name=x.txt`, {
      method: 'POST',
      body: 'no token here',
    });
    assert.equal(staged.status, 403);

    // A rejected upload must still report its status. Answering before the body
    // was consumed used to reset the connection instead.
    const big = await fetch(`${state.uiA.url}/api/stage?name=big.bin`, {
      method: 'POST',
      body: Buffer.alloc(3 * 1024 * 1024, 1),
    });
    assert.equal(big.status, 403);
  });

  it('refuses cross-origin posts and forged Host headers', async () => {
    // A hostile page cannot read our token, but it *can* send a simple POST.
    // The Origin check is the second line of defence.
    const forged = await fetch(`${state.uiA.url}/api/send`, {
      method: 'POST',
      headers: {
        'content-type': 'text/plain',
        origin: 'https://evil.example',
        'x-bhejo-token': state.uiA.token,
      },
      body: JSON.stringify({ target: 'x' }),
    });
    assert.equal(forged.status, 403);

    // DNS rebinding: right address, wrong Host.
    const rebound = await rawRequest({
      port: state.uiA.port,
      method: 'GET',
      route: '/api/state',
      headers: { host: 'evil.example', 'x-bhejo-token': state.uiA.token },
    });
    assert.equal(rebound.status, 403);
  });

  it('sends a staged file to the peer after the other UI accepts', async () => {
    const payload = Buffer.from('bhejo browser test\n'.repeat(4000), 'utf8');

    const staged = await api(state.uiA, '/api/stage?name=folder%2Freport.txt', {
      method: 'POST',
      headers: { 'content-type': 'application/octet-stream' },
      body: payload,
    });
    assert.equal(staged.status, 200);
    assert.equal(staged.json.name, 'folder/report.txt');
    assert.equal(staged.json.size, payload.length);

    const bravo = state.discoveries[0].peers().find((p) => p.alias === 'Bravo-PC');

    const send = await api(state.uiA, '/api/send', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ target: bravo.fingerprint }),
    });
    assert.equal(send.status, 200);
    assert.ok(send.json.transferId);

    // Bravo's UI should now hold the request.
    const pending = await waitFor(async () => {
      const { json } = await api(state.uiB, '/api/state');
      return json.requests.length ? json.requests[0] : null;
    });
    assert.equal(pending.alias, 'Alpha-PC');
    assert.equal(pending.files[0].fileName, 'folder/report.txt');
    assert.equal(pending.isNew, true, 'a first-time sender should be flagged as new');

    const decision = await api(state.uiB, `/api/incoming/${pending.id}`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ action: 'accept' }),
    });
    assert.equal(decision.status, 200);
    assert.equal(decision.json.accepted, true);

    // Alpha's transfer should reach "done".
    const finished = await waitFor(async () => {
      const { json } = await api(state.uiA, '/api/state');
      const transfer = json.transfers.find((t) => t.id === send.json.transferId);
      return transfer && transfer.status !== 'sending' ? transfer : null;
    });
    assert.equal(finished.status, 'done', `transfer failed: ${finished.error ?? 'unknown'}`);
    assert.equal(finished.sentBytes, payload.length);

    // Bravo's inbox should hold the file, byte for byte, at the right depth.
    const saved = path.join(state.inboxB, 'folder', 'report.txt');
    await waitFor(() => fs.existsSync(saved));
    assert.deepEqual(fs.readFileSync(saved), payload);

    // And the sender's staged copy is cleaned up once delivered.
    const remaining = await api(state.uiA, '/api/state');
    assert.equal(remaining.json.staged.length, 0);
  });

  it('records the accepted device as trusted', async () => {
    const { json } = await api(state.uiB, '/api/state');
    assert.ok(json.transfers.some((t) => t.direction === 'in' && t.status === 'done'));
  });

  it('removes a staged file without sending it', async () => {
    const staged = await api(state.uiB, '/api/stage?name=scratch.bin', {
      method: 'POST',
      headers: { 'content-type': 'application/octet-stream' },
      body: Buffer.alloc(64, 7),
    });
    assert.equal(staged.status, 200);

    let list = await api(state.uiB, '/api/state');
    assert.equal(list.json.staged.length, 1);

    const removed = await api(state.uiB, `/api/stage/${staged.json.id}`, { method: 'DELETE' });
    assert.equal(removed.status, 200);

    list = await api(state.uiB, '/api/state');
    assert.equal(list.json.staged.length, 0);
  });
});
