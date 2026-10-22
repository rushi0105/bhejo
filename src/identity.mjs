// Device identity: alias, persistent TLS keypair, and its fingerprint.
//
// The certificate is persisted rather than regenerated on every launch, unlike
// LocalSend. That is a deliberate trade: a stable fingerprint is what makes
// trust-on-first-use possible ("this is the fingerprint I accepted last week").
// A per-run certificate would make every connection unverifiable by definition.
// The private key is written with owner-only permissions, the same model SSH
// uses for host keys.

import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { buildSelfSignedCert } from './cert.mjs';
import { defaultAlias, deviceType, primaryIpv4, sanitizeSegment } from './util.mjs';

export function bhejoHome() {
  if (process.env.BHEJO_HOME) return path.resolve(process.env.BHEJO_HOME);
  return path.join(os.homedir(), '.bhejo');
}

/**
 * Load or create this device's identity.
 *
 * @param {object} [opts]
 * @param {string} [opts.alias] Override the display name for this run only.
 * @param {boolean} [opts.ephemeral] Generate a throwaway keypair in memory.
 * @param {string} [opts.home] Override the state directory.
 */
export function loadIdentity({ alias, ephemeral = false, home = bhejoHome() } = {}) {
  const deviceAlias = alias?.trim() || defaultAlias();

  if (ephemeral) {
    const cert = buildSelfSignedCert({
      commonName: deviceAlias,
      dnsNames: ['localhost', `${sanitizeSegment(deviceAlias).replace(/\s+/g, '-').toLowerCase()}.local`],
      ipAddresses: [...new Set(['127.0.0.1', primaryIpv4()])],
    });
    return {
      alias: deviceAlias,
      deviceType: deviceType(),
      fingerprint: cert.fingerprint,
      keyPem: cert.keyPem,
      certPem: cert.certPem,
      ephemeral: true,
      home,
    };
  }

  const file = path.join(home, 'identity.json');

  if (fs.existsSync(file)) {
    try {
      const saved = JSON.parse(fs.readFileSync(file, 'utf8'));
      if (saved.keyPem && saved.certPem && saved.fingerprint) {
        return {
          alias: deviceAlias,
          storedAlias: saved.alias ?? deviceAlias,
          deviceType: deviceType(),
          deviceId: saved.deviceId,
          fingerprint: saved.fingerprint,
          keyPem: saved.keyPem,
          certPem: saved.certPem,
          ephemeral: false,
          home,
        };
      }
    } catch {
      // Corrupt state file: fall through and regenerate.
    }
  }

  const cert = buildSelfSignedCert({
    commonName: deviceAlias,
    dnsNames: ['localhost', `${sanitizeSegment(deviceAlias).replace(/\s+/g, '-').toLowerCase()}.local`],
    ipAddresses: [...new Set(['127.0.0.1', primaryIpv4()])],
  });

  const record = {
    version: 1,
    alias: deviceAlias,
    deviceId: `dev_${cert.fingerprint.slice(0, 16)}`,
    createdAt: new Date().toISOString(),
    fingerprint: cert.fingerprint,
    keyPem: cert.keyPem,
    certPem: cert.certPem,
  };

  fs.mkdirSync(home, { recursive: true, mode: 0o700 });
  fs.writeFileSync(file, JSON.stringify(record, null, 2), { mode: 0o600 });

  return {
    alias: deviceAlias,
    storedAlias: deviceAlias,
    deviceType: deviceType(),
    deviceId: record.deviceId,
    fingerprint: cert.fingerprint,
    keyPem: cert.keyPem,
    certPem: cert.certPem,
    ephemeral: false,
    home,
  };
}
