// Verifies that the hand-rolled certificate is a real certificate, not just
// bytes that happen to parse. Node's own TLS stack is the judge.

import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import https from 'node:https';
import test from 'node:test';
import tls from 'node:tls';
import { buildSelfSignedCert, formatFingerprint, pemToDer } from '../src/cert.mjs';

test('certificate is accepted by the TLS stack', () => {
  const cert = buildSelfSignedCert({ commonName: 'Kitchen Laptop' });
  assert.doesNotThrow(() => tls.createSecureContext({ key: cert.keyPem, cert: cert.certPem }));
  assert.match(cert.certPem, /^-----BEGIN CERTIFICATE-----/);
  assert.equal(cert.fingerprint.length, 64);
});

test('certificate completes a real TLS handshake with the expected fingerprint', async () => {
  const cert = buildSelfSignedCert({
    commonName: 'Test Device',
    dnsNames: ['localhost', 'test.local'],
    ipAddresses: ['127.0.0.1'],
  });

  const server = https.createServer({ key: cert.keyPem, cert: cert.certPem }, (_req, res) => {
    res.end('pong');
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const port = server.address().port;

  try {
    const socket = await new Promise((resolve, reject) => {
      const s = tls.connect({ host: '127.0.0.1', port, rejectUnauthorized: false });
      s.once('secureConnect', () => resolve(s));
      s.once('error', reject);
    });

    const peer = socket.getPeerCertificate();
    const seenFingerprint = crypto.createHash('sha256').update(peer.raw).digest('hex');

    assert.equal(socket.getProtocol(), 'TLSv1.3');
    assert.equal(seenFingerprint, cert.fingerprint, 'fingerprint must survive the handshake');
    assert.equal(pemToDer(cert.certPem).toString('hex'), Buffer.from(peer.raw).toString('hex'));

    // Subject alternative names must actually be present: modern clients ignore CN.
    assert.equal(peer.subjectaltname, 'DNS:localhost, DNS:test.local, IP Address:127.0.0.1');
    assert.equal(peer.subject.CN, 'Test Device');
    assert.ok(Date.parse(peer.valid_to) > Date.now() + 365 * 24 * 3600 * 1000);

    socket.destroy();
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
});

test('fingerprints are stable per certificate and differ across certificates', () => {
  const a = buildSelfSignedCert({ commonName: 'A' });
  const b = buildSelfSignedCert({ commonName: 'B' });
  assert.notEqual(a.fingerprint, b.fingerprint);
  assert.equal(formatFingerprint(a.fingerprint).split(':').length, 32);
});
