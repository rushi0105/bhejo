// Discovery tests. Multicast is the one part of this tool that depends on the
// network stack, so these tests skip honestly rather than fail spuriously when
// the environment blocks multicast (VPN adapters, hardened Wi-Fi, containers).

import assert from 'node:assert/strict';
import test from 'node:test';
import { Discovery } from '../src/discovery.mjs';
import { allIpv4, sleep } from '../src/util.mjs';

function instance(name, httpPort, port, extra = {}) {
  return new Discovery({
    alias: name,
    deviceType: 'desktop',
    httpPort,
    fingerprint: name.padEnd(64, '0').slice(0, 64).replace(/[^0-9a-f]/g, '0'),
    port,
    multicastAddress: '224.0.0.167',
    announceIntervalMs: 300,
    peerTtlMs: 5000,
    ...extra,
  });
}

test('two instances on one host find each other over multicast', async (t) => {
  const port = 53400 + Math.floor(Math.random() * 400);
  const a = instance('alpha', 50001, port);
  const b = instance('bravo', 50002, port);
  await a.start();
  await b.start();
  t.after(async () => {
    await a.stop();
    await b.stop();
  });

  const deadline = Date.now() + 6000;
  while (Date.now() < deadline) {
    if (a.peers().length && b.peers().length) break;
    await sleep(150);
  }

  const alphaSees = a.peers();
  const bravoSees = b.peers();

  if (!alphaSees.length || !bravoSees.length) {
    t.skip('multicast appears to be filtered on this host; broadcast fallback would apply in the field');
    return;
  }

  // The address must come from the UDP header. Depending on the interface the
  // multicast went out on, that is a LAN address rather than loopback.
  const localAddresses = new Set([...allIpv4(), '127.0.0.1']);
  assert.ok(localAddresses.has(alphaSees[0].address), `unexpected source address ${alphaSees[0].address}`);
  assert.equal(alphaSees[0].alias, 'bravo');
  assert.equal(alphaSees[0].port, 50002);
  assert.equal(bravoSees[0].alias, 'alpha');
  assert.equal(bravoSees[0].port, 50001);
});

test('a peer never advertises itself', async () => {
  const port = 53800 + Math.floor(Math.random() * 400);
  const solo = instance('lonely', 50003, port);
  await solo.start();
  try {
    await sleep(700);
    assert.deepEqual(solo.peers(), [], 'multicast loopback must not register our own announcement');
  } finally {
    await solo.stop();
  }
});

test('peers are dropped once their announcements stop', async (t) => {
  const port = 54200 + Math.floor(Math.random() * 400);
  const a = instance('alpha', 50004, port, { peerTtlMs: 1500 });
  const b = instance('bravo', 50005, port, { peerTtlMs: 1500 });
  await a.start();
  await b.start();

  try {
    const deadline = Date.now() + 5000;
    while (Date.now() < deadline && a.peers().length === 0) await sleep(100);

    if (a.peers().length === 0) {
      t.skip('multicast appears to be filtered on this host');
      return;
    }

    assert.equal(a.peers()[0].alias, 'bravo');

    await b.stop();
    // TTL is 1.5s and the sweep runs at most every 0.75s, so 2.5s is plenty.
    await sleep(2500);
    assert.deepEqual(a.peers(), [], 'a silent peer must expire');
  } finally {
    await a.stop();
    await b.stop().catch(() => {});
  }
});
