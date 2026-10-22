// Peer discovery: one UDP socket, one multicast group, one broadcast fallback.
//
// Deliberately simpler than LocalSend's scheme. We send a small JSON
// announcement to a multicast group every few seconds, and also to the
// limited broadcast address for networks where multicast is filtered. Every
// received announcement is answered with a unicast reply, so two devices that
// cannot both receive multicast can still meet.
//
// Trust boundary: the source address always comes from the UDP packet header,
// never from the JSON body. A peer cannot claim to live at a different address
// than the one it is actually sending from.

import dgram from 'node:dgram';
import { EventEmitter } from 'node:events';
import {
  APP_ID,
  DEFAULT_MULTICAST_ADDRESS,
  DEFAULT_PORT,
  PROTOCOL_VERSION,
} from './util.mjs';

const MAX_PACKET = 4096;

export class Discovery extends EventEmitter {
  constructor({
    alias,
    deviceType,
    httpPort,
    fingerprint,
    port = DEFAULT_PORT,
    multicastAddress = DEFAULT_MULTICAST_ADDRESS,
    announceIntervalMs = 4000,
    peerTtlMs = 15_000,
    broadcast = true,
    log = () => {},
  }) {
    super();
    this.alias = alias;
    this.deviceType = deviceType;
    this.httpPort = httpPort;
    this.fingerprint = fingerprint;
    this.port = port;
    this.multicastAddress = multicastAddress;
    this.announceIntervalMs = announceIntervalMs;
    this.peerTtlMs = peerTtlMs;
    this.broadcast = broadcast;
    this.log = log;

    /** @type {Map<string, object>} fingerprint -> peer */
    this.peerMap = new Map();
    this.socket = null;
    this.timers = [];
    this.started = false;
    this.joinedMulticast = false;
  }

  async start() {
    if (this.started) return;

    this.socket = dgram.createSocket({ type: 'udp4', reuseAddr: true });

    await new Promise((resolve, reject) => {
      const onError = (err) => {
        this.socket?.removeListener('error', onError);
        reject(err);
      };
      this.socket.once('error', onError);
      this.socket.bind(this.port, () => {
        this.socket.removeListener('error', onError);
        resolve();
      });
    });

    this.socket.on('error', (err) => this.emit('error', err));
    this.socket.on('message', (buf, rinfo) => this.#onPacket(buf, rinfo));

    try {
      this.socket.addMembership(this.multicastAddress);
      this.joinedMulticast = true;
      this.socket.setMulticastTTL(1); // never leave the local segment
      this.socket.setMulticastLoopback(true); // two instances on one host can meet
    } catch (err) {
      this.joinedMulticast = false;
      this.log(`multicast unavailable (${err.code ?? err.message}); using broadcast only`);
    }

    if (this.broadcast) {
      try {
        this.socket.setBroadcast(true);
      } catch {
        /* some interfaces refuse; announce() tolerates the failure */
      }
    }

    this.started = true;
    this.#announce();

    this.timers.push(setInterval(() => this.#announce(), this.announceIntervalMs));
    // Sweep often enough that a device which left disappears promptly, but
    // never more than once a second.
    const sweepMs = Math.max(500, Math.min(2000, Math.floor(this.peerTtlMs / 2)));
    this.timers.push(setInterval(() => this.#expirePeers(), sweepMs));
    for (const timer of this.timers) timer.unref?.();
  }

  async stop() {
    for (const timer of this.timers) clearInterval(timer);
    this.timers = [];
    this.started = false;
    if (!this.socket) return;
    const socket = this.socket;
    this.socket = null;
    await new Promise((resolve) => socket.close(resolve));
  }

  /** Current peers, freshest first, with self excluded. */
  peers() {
    return [...this.peerMap.values()]
      .filter((p) => p.fingerprint !== this.fingerprint)
      .sort((a, b) => a.alias.localeCompare(b.alias) || b.lastSeen - a.lastSeen);
  }

  findByAlias(alias) {
    const needle = String(alias).toLowerCase();
    return this.peers().filter(
      (p) => p.alias.toLowerCase() === needle || p.alias.toLowerCase().includes(needle),
    );
  }

  #payload() {
    return Buffer.from(
      JSON.stringify({
        app: APP_ID,
        proto: PROTOCOL_VERSION,
        alias: this.alias,
        deviceType: this.deviceType,
        port: this.httpPort,
        fingerprint: this.fingerprint,
        ts: Date.now(),
      }),
      'utf8',
    );
  }

  #announce() {
    if (!this.socket) return;
    const payload = this.#payload();

    const send = (address, port) => {
      this.socket.send(payload, port, address, (err) => {
        // Broadcast to 255.255.255.255 routinely fails on interfaces without
        // IPv4 broadcast (VPNs, some Wi-Fi drivers). That is not fatal.
        if (err && address !== '255.255.255.255') {
          this.log(`announce to ${address}:${port} failed: ${err.message}`);
        }
      });
    };

    if (this.joinedMulticast) send(this.multicastAddress, this.port);
    if (this.broadcast) send('255.255.255.255', this.port);
  }

  #onPacket(buf, rinfo) {
    if (buf.length > MAX_PACKET) return;

    let msg;
    try {
      msg = JSON.parse(buf.toString('utf8'));
    } catch {
      return; // not ours
    }

    if (!msg || msg.app !== APP_ID) return;
    if (msg.proto !== PROTOCOL_VERSION) return;
    if (msg.fingerprint === this.fingerprint) return; // ourselves (multicast loopback)
    if (typeof msg.fingerprint !== 'string' || msg.fingerprint.length !== 64) return;
    if (!Number.isInteger(msg.port) || msg.port < 1 || msg.port > 65535) return;
    if (typeof msg.alias !== 'string' || !msg.alias.trim()) return;

    const now = Date.now();
    const existing = this.peerMap.get(msg.fingerprint);
    const peer = {
      alias: msg.alias.slice(0, 64),
      deviceType: typeof msg.deviceType === 'string' ? msg.deviceType.slice(0, 16) : 'unknown',
      address: rinfo.address, // from the packet header, not the payload
      port: msg.port,
      fingerprint: msg.fingerprint,
      firstSeen: existing?.firstSeen ?? now,
      lastSeen: now,
    };
    this.peerMap.set(msg.fingerprint, peer);

    if (!existing) {
      this.emit('peer', peer);
      // Answer directly so the sender learns about us even if it cannot
      // receive multicast. Reply to the port the packet came *from* (the
      // sender's discovery socket), not to the HTTP port it advertised.
      // A device that is only sending does not listen at all, so skip it.
      if (!this.httpPort) return;
      setTimeout(() => {
        if (!this.socket) return;
        this.socket.send(this.#payload(), rinfo.port, rinfo.address, () => {});
      }, 20 + Math.floor(Math.random() * 130)).unref?.();
    } else {
      this.emit('update', peer);
    }
  }

  #expirePeers() {
    const cutoff = Date.now() - this.peerTtlMs;
    for (const [fingerprint, peer] of this.peerMap) {
      if (peer.lastSeen < cutoff) {
        this.peerMap.delete(fingerprint);
        this.emit('lost', peer);
      }
    }
  }
}

/**
 * Start discovery, wait `ms`, return whatever was found, then stop.
 * Used by `bhejo discover` and by `bhejo send --to <alias>`.
 */
export async function discoverFor({ identity, httpPort, ms = 4000, port, log }) {
  const discovery = new Discovery({
    alias: identity.alias,
    deviceType: identity.deviceType,
    httpPort,
    fingerprint: identity.fingerprint,
    port,
    log,
  });
  await discovery.start();
  await new Promise((resolve) => setTimeout(resolve, ms));
  const peers = discovery.peers();
  await discovery.stop();
  return peers;
}
