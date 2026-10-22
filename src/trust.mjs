// Trust-on-first-use store for peer fingerprints.
//
// This is what makes pinning meaningful across sessions. Without it the
// fingerprint check only proves "the device I am talking to is the same device
// as the one I just talked to", which is worthless against an active attacker.
// With it, the second transfer to a device is genuinely verified.
//
// The store is a plain JSON file holding only public information: alias,
// fingerprint, addresses. No keys, no tokens.

import fs from 'node:fs';
import path from 'node:path';
import { bhejoHome } from './identity.mjs';

export class TrustStore {
  constructor(home = bhejoHome()) {
    this.home = home;
    this.file = path.join(home, 'known-peers.json');
    this.data = this.#load();
  }

  #load() {
    try {
      const parsed = JSON.parse(fs.readFileSync(this.file, 'utf8'));
      if (parsed && typeof parsed.peers === 'object' && parsed.peers) return parsed;
    } catch {
      /* missing or corrupt: start empty */
    }
    return { version: 1, peers: {} };
  }

  #save() {
    fs.mkdirSync(this.home, { recursive: true, mode: 0o700 });
    const temp = `${this.file}.${process.pid}.tmp`;
    fs.writeFileSync(temp, JSON.stringify(this.data, null, 2), { mode: 0o600 });
    fs.renameSync(temp, this.file);
  }

  get(fingerprint) {
    return this.data.peers[fingerprint] ?? null;
  }

  isKnown(fingerprint) {
    return Boolean(this.get(fingerprint));
  }

  remember(fingerprint, { alias, address } = {}) {
    if (!fingerprint) return;
    const now = new Date().toISOString();
    const existing = this.get(fingerprint) ?? {};
    this.data.peers[fingerprint] = {
      alias: alias ?? existing.alias ?? 'unknown',
      address: address ?? existing.address ?? null,
      firstSeen: existing.firstSeen ?? now,
      lastSeen: now,
    };
    this.#save();
  }

  touch(fingerprint, address) {
    const existing = this.get(fingerprint);
    if (!existing) return;
    existing.lastSeen = new Date().toISOString();
    if (address) existing.address = address;
    this.#save();
  }

  forget(fingerprint) {
    if (!this.data.peers[fingerprint]) return false;
    delete this.data.peers[fingerprint];
    this.#save();
    return true;
  }

  get size() {
    return Object.keys(this.data.peers).length;
  }

  list() {
    return Object.entries(this.data.peers).map(([fingerprint, info]) => ({ fingerprint, ...info }));
  }
}
