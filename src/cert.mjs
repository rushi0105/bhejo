// Self-signed X.509 certificate generation with zero dependencies.
//
// Node's crypto module can generate keys and sign bytes, but has no API to
// assemble an X.509 certificate. Rather than pull in node-forge or shell out to
// openssl (which is absent on a stock Windows box), we encode the DER ourselves.
// The result is verified by Node's own TLS stack in test/cert.test.mjs, which is
// the only proof that matters: if tls.createSecureContext accepts it and a real
// handshake completes, the certificate is well formed.

import crypto from 'node:crypto';

// ---------------------------------------------------------------- DER basics

/** DER length prefix. Short form below 128, long form above. */
function derLen(n) {
  if (n < 0x80) return Buffer.from([n]);
  const bytes = [];
  let v = n;
  while (v > 0) {
    bytes.unshift(v & 0xff);
    v = Math.floor(v / 256);
  }
  return Buffer.from([0x80 | bytes.length, ...bytes]);
}

/** Tag-Length-Value. `tag` is a single tag byte. */
function tlv(tag, content) {
  return Buffer.concat([Buffer.from([tag]), derLen(content.length), content]);
}

const seq = (...items) => tlv(0x30, Buffer.concat(items));
const set = (...items) => tlv(0x31, Buffer.concat(items));

/** INTEGER from a big-endian buffer. DER wants minimal encoding, unsigned. */
function derInt(buf) {
  let b = buf;
  while (b.length > 1 && b[0] === 0 && (b[1] & 0x80) === 0) b = b.subarray(1);
  if (b.length === 0) b = Buffer.from([0]);
  if (b[0] & 0x80) b = Buffer.concat([Buffer.from([0]), b]);
  return tlv(0x02, b);
}

function derIntNum(n) {
  const bytes = [];
  let v = n;
  if (v === 0) return tlv(0x02, Buffer.from([0]));
  while (v > 0) {
    bytes.unshift(v & 0xff);
    v = Math.floor(v / 256);
  }
  return derInt(Buffer.from(bytes));
}

/** OBJECT IDENTIFIER from dotted-decimal form. */
function derOid(oid) {
  const parts = oid.split('.').map(Number);
  if (parts.length < 2) throw new Error(`bad OID: ${oid}`);
  const bytes = [parts[0] * 40 + parts[1]];
  for (const part of parts.slice(2)) {
    const chunk = [];
    let v = part;
    do {
      chunk.unshift(v & 0x7f);
      v = Math.floor(v / 128);
    } while (v > 0);
    for (let i = 0; i < chunk.length - 1; i++) chunk[i] |= 0x80;
    bytes.push(...chunk);
  }
  return tlv(0x06, Buffer.from(bytes));
}

const derUtf8 = (s) => tlv(0x0c, Buffer.from(s, 'utf8'));
const derNull = () => Buffer.from([0x05, 0x00]);
const derBool = (b) => tlv(0x01, Buffer.from([b ? 0xff : 0x00]));
const derOctet = (buf) => tlv(0x04, buf);
const derBitString = (buf, unused = 0) =>
  tlv(0x03, Buffer.concat([Buffer.from([unused]), buf]));

/** UTCTime, "YYMMDDHHMMSSZ". Used for dates before 2050. */
function derUtcTime(date) {
  const iso = date.toISOString(); // 2026-10-22T09:15:00.000Z
  const s =
    iso.slice(2, 4) + iso.slice(5, 7) + iso.slice(8, 10) +
    iso.slice(11, 13) + iso.slice(14, 16) + iso.slice(17, 19) + 'Z';
  return tlv(0x17, Buffer.from(s, 'ascii'));
}

// Relative distinguished name: SET { SEQUENCE { OID, UTF8String } }
const rdn = (oid, value) => set(seq(derOid(oid), derUtf8(value)));
const name = (...rdns) => seq(...rdns);

function extension(oid, value, critical = false) {
  const parts = [derOid(oid)];
  if (critical) parts.push(derBool(true));
  parts.push(derOctet(value));
  return seq(...parts);
}

// -------------------------------------------------------------------- OIDs

const OID = {
  sha256WithRsa: '1.2.840.113549.1.1.11',
  commonName: '2.5.4.3',
  organization: '2.5.4.10',
  basicConstraints: '2.5.29.19',
  keyUsage: '2.5.29.15',
  extKeyUsage: '2.5.29.37',
  subjectAltName: '2.5.29.17',
  serverAuth: '1.3.6.1.5.5.7.3.1',
};

// ------------------------------------------------------------- certificate

/**
 * Build a self-signed RSA-2048 certificate for local HTTPS.
 *
 * @param {object} opts
 * @param {string} opts.commonName  Device alias, embedded as the CN.
 * @param {string[]} [opts.dnsNames] Extra DNS subject alternative names.
 * @param {string[]} [opts.ipAddresses] IP subject alternative names.
 * @param {number} [opts.days] Validity window.
 * @returns {{keyPem: string, certPem: string, certDer: Buffer, fingerprint: string}}
 */
export function buildSelfSignedCert({
  commonName,
  dnsNames = ['localhost'],
  ipAddresses = ['127.0.0.1'],
  days = 1825,
} = {}) {
  if (!commonName) throw new Error('commonName is required');

  const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: { type: 'spki', format: 'der' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });

  const serial = crypto.randomBytes(16);
  serial[0] &= 0x7f; // keep it positive
  if (serial[0] === 0) serial[0] = 1;

  const now = Date.now();
  const notBefore = new Date(now - 24 * 60 * 60 * 1000); // 1 day of clock skew
  const notAfter = new Date(now + days * 24 * 60 * 60 * 1000);

  const sigAlg = seq(derOid(OID.sha256WithRsa), derNull());

  const subjectName = name(
    rdn(OID.organization, 'Bhejo'),
    rdn(OID.commonName, commonName),
  );

  // subjectAltName: browsers and modern TLS clients ignore CN.
  const generalNames = [
    ...dnsNames.map((d) => tlv(0x82, Buffer.from(d, 'ascii'))), // [2] dNSName
    ...ipAddresses.map((ip) => {
      const bytes = ip.split('.').map(Number);
      if (bytes.length !== 4 || bytes.some((b) => !Number.isInteger(b) || b < 0 || b > 255)) {
        throw new Error(`not an IPv4 address: ${ip}`);
      }
      return tlv(0x87, Buffer.from(bytes)); // [7] iPAddress
    }),
  ];

  const extensions = seq(
    // CA:TRUE so the cert can be pinned as a trust anchor by a user who wants
    // a browser to accept it without a warning.
    extension(OID.basicConstraints, seq(derBool(true)), true),
    // digitalSignature (bit 0) + keyEncipherment (bit 2) => 0b10100000, 5 unused
    extension(OID.keyUsage, derBitString(Buffer.from([0xa0]), 5), true),
    extension(OID.extKeyUsage, seq(derOid(OID.serverAuth))),
    extension(OID.subjectAltName, seq(...generalNames)),
  );

  const tbs = seq(
    tlv(0xa0, derIntNum(2)), // [0] EXPLICIT version = v3
    derInt(serial),
    sigAlg,
    subjectName, // issuer == subject for a self-signed cert
    seq(derUtcTime(notBefore), derUtcTime(notAfter)),
    subjectName,
    publicKey,
    tlv(0xa3, extensions), // [3] EXPLICIT extensions
  );

  const signature = crypto.sign('sha256', tbs, privateKey);
  const certDer = seq(tbs, sigAlg, derBitString(signature));

  const b64 = certDer.toString('base64').match(/.{1,64}/g).join('\n');
  const certPem = `-----BEGIN CERTIFICATE-----\n${b64}\n-----END CERTIFICATE-----\n`;

  return {
    keyPem: privateKey,
    certPem,
    certDer,
    fingerprint: fingerprintOf(certDer),
  };
}

/** SHA-256 fingerprint of a DER certificate, as lowercase hex. */
export function fingerprintOf(der) {
  return crypto.createHash('sha256').update(der).digest('hex');
}

/** SHA-256 fingerprint of a PEM certificate. */
export function fingerprintOfPem(pem) {
  return fingerprintOf(pemToDer(pem));
}

/** Strip PEM armour back to DER bytes. */
export function pemToDer(pem) {
  const body = String(pem)
    .replace(/-----BEGIN CERTIFICATE-----/, '')
    .replace(/-----END CERTIFICATE-----/, '')
    .replace(/\s+/g, '');
  if (!body) throw new Error('no certificate found in PEM input');
  return Buffer.from(body, 'base64');
}

/** Group a hex fingerprint into readable pairs: "ab:cd:ef:...". */
export function formatFingerprint(hex) {
  return (hex.match(/.{1,2}/g) ?? []).join(':');
}
