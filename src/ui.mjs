// Local browser UI.
//
// The receiver already runs a TLS server for peers, but a browser cannot use it:
// the certificate is self-signed, so the user would face a full-page warning on
// every visit. Instead this module runs a second, plain-HTTP server bound to
// 127.0.0.1 only, which serves one page and a small JSON API.
//
// Threat model for that server, because "localhost" is not automatically safe:
//   * Any web page you visit can `fetch("http://127.0.0.1:PORT/api/send")`.
//     A cross-origin POST with a text/plain body is a "simple request" and is
//     sent even though the response is unreadable. So every API call requires a
//     custom header (`x-bhejo-token`), which forces a CORS preflight that we
//     never answer. The token is generated per run and embedded in the page.
//   * DNS rebinding: an attacker-controlled hostname can resolve to 127.0.0.1
//     and then talk to this server same-origin. The Host header is checked
//     against the exact allowed values, which defeats it.
//   * Binding to 127.0.0.1 (not 0.0.0.0) keeps it off the LAN entirely.
//
// The UI never handles peer TLS itself: it uploads files to this server, and
// this server sends them with the same verified transport the CLI uses.

import { once } from 'node:events';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { sendFiles } from './sender.mjs';
import { DEFAULT_PORT, randomToken, safeEqual, sanitizeSegment } from './util.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const MAX_STAGE_BYTES = 16 * 1024 * 1024 * 1024; // 16 GB per file
const MAX_STAGED_FILES = 500;
const MAX_JSON_BODY = 64 * 1024;
const DECISION_TIMEOUT_MS = 120_000;
const KEEP_TRANSFERS = 20;
const DRAIN_LIMIT = 64 * 1024 * 1024;

class UiError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

function sendJson(res, status, body) {
  const payload = Buffer.from(JSON.stringify(body), 'utf8');
  res.writeHead(status, {
    'content-type': 'application/json; charset=utf-8',
    'content-length': payload.length,
    'cache-control': 'no-store',
    'x-content-type-options': 'nosniff',
    'referrer-policy': 'no-referrer',
  });
  res.end(payload);
}

/** Read a request body away so an early rejection still reaches the client. */
async function drain(req, limit) {
  let total = 0;
  for await (const chunk of req) {
    total += chunk.length;
    if (total > limit) return;
  }
}

async function readJson(req, limit = MAX_JSON_BODY) {  const chunks = [];
  let size = 0;
  for await (const chunk of req) {
    size += chunk.length;
    if (size > limit) throw new UiError(413, 'request body too large');
    chunks.push(chunk);
  }
  if (!chunks.length) return {};
  try {
    return JSON.parse(Buffer.concat(chunks).toString('utf8'));
  } catch {
    throw new UiError(400, 'malformed JSON');
  }
}

export class UiServer {  /**
   * @param {object} opts
   * @param {object} opts.identity   Loaded identity (alias, fingerprint, deviceType).
   * @param {object} opts.receiver   A started Receiver, used for state and events.
   * @param {object} [opts.discovery] Started Discovery, used for the peer list.
   * @param {object} [opts.trust]    TrustStore, used to mark new devices.
   * @param {number} [opts.port]     Preferred port; falls back to an ephemeral one.
   * @param {(msg: string) => void} [opts.log]
   */
  constructor({ identity, receiver, discovery = null, trust = null, port = DEFAULT_PORT + 1, log = () => {} }) {
    this.identity = identity;
    this.receiver = receiver;
    this.discovery = discovery;
    this.trust = trust;
    this.preferredPort = port;
    this.log = log;

    this.token = randomToken(16);
    this.server = null;
    this.port = null;
    this.url = null;
    this.spool = null;
    this.html = null;
    this.allowedHosts = new Set();

    /** decisionId -> pending entry */
    this.pending = new Map();
    /** transferId -> { direction, peerAlias, files, ... } */
    this.transfers = new Map();
    /** stageId -> { id, name, size, path } */
    this.staged = new Map();

    this.#watchReceiver();
  }

  // ------------------------------------------------------------------ setup

  async start() {
    this.spool = await fs.promises.mkdtemp(path.join(os.tmpdir(), 'bhejo-outbox-'));
    const template = await fs.promises.readFile(path.join(HERE, 'ui.html'), 'utf8');
    this.html = template.replace('%%BHEJO_TOKEN%%', this.token);

    this.server = http.createServer((req, res) => {
      this.#handle(req, res).catch(async (err) => {
        if (res.headersSent) {
          res.destroy();
          return;
        }
        // Answer only after the body is consumed. Replying while the browser is
        // still uploading makes it surface a network error instead of our
        // status, which hides the real reason from the page.
        await drain(req, DRAIN_LIMIT).catch(() => {});
        sendJson(res, err instanceof UiError ? err.status : 500, {
          error: err.message ?? 'internal error',
        });
      });
    });
    this.server.on('error', (err) => this.log(`ui: ${err.message}`));

    this.port = await this.#listen(this.preferredPort);
    this.allowedHosts = new Set([`127.0.0.1:${this.port}`, `localhost:${this.port}`]);
    this.url = `http://127.0.0.1:${this.port}`;

    if (this.port !== this.preferredPort) {
      this.log(`ui port ${this.preferredPort} was busy; serving on ${this.port}`);
    }
    return { url: this.url, port: this.port };
  }

  async #listen(port) {
    const attempt = (p) =>
      new Promise((resolve, reject) => {
        const onError = (err) => {
          this.server.removeListener('listening', onListening);
          reject(err);
        };
        const onListening = () => {
          this.server.removeListener('error', onError);
          resolve(this.server.address().port);
        };
        this.server.once('error', onError);
        this.server.once('listening', onListening);
        this.server.listen(p, '127.0.0.1');
      });

    try {
      return await attempt(port);
    } catch (err) {
      if (err.code === 'EADDRINUSE' && port !== 0) return attempt(0);
      throw err;
    }
  }

  async stop() {
    for (const entry of this.pending.values()) {
      entry.resolve({ accepted: false, reason: 'receiver shutting down' });
    }
    this.pending.clear();

    if (this.server) {
      const server = this.server;
      this.server = null;
      await new Promise((resolve) => {
        server.close(resolve);
        server.closeAllConnections?.();
      });
    }

    if (this.spool) {
      await fs.promises.rm(this.spool, { recursive: true, force: true }).catch(() => {});
      this.spool = null;
    }
  }

  // ------------------------------------------------------- incoming requests

  /**
   * Ask the browser whether to accept a transfer. Used as Receiver#onIncoming.
   * Resolves to a decline if nobody answers, so a stale tab cannot hang a sender.
   */
  decide(request) {
    const id = randomToken(8);
    return new Promise((resolve) => {
      const timer = setTimeout(() => {
        this.pending.delete(id);
        resolve({ accepted: false, reason: 'no answer from the receiving device' });
      }, DECISION_TIMEOUT_MS);
      timer.unref?.();

      this.pending.set(id, {
        id,
        request,
        peer: request.peer,
        createdAt: Date.now(),
        resolve: (decision) => {
          clearTimeout(timer);
          this.pending.delete(id);
          resolve(decision);
        },
      });
    });
  }

  // -------------------------------------------------------------- receiver io

  #watchReceiver() {
    const receiver = this.receiver;
    if (!receiver) return;

    receiver.on('accepted', ({ sessionId, peer, files }) => {
      const transfer = {
        id: sessionId,
        direction: 'in',
        peerAlias: peer.alias,
        files: files.map((f) => ({ name: f.fileName, size: f.size, sent: 0, done: false })),
        sentBytes: 0,
        totalBytes: files.reduce((n, f) => n + f.size, 0),
        status: 'receiving',
        error: null,
        startedAt: Date.now(),
      };
      this.#remember(transfer);
    });

    receiver.on('progress', ({ sessionId, fileName, bytes }) => {
      const transfer = this.transfers.get(sessionId);
      if (!transfer) return;
      const entry = transfer.files.find((f) => f.name === fileName);
      if (entry) entry.sent = bytes;
      transfer.sentBytes = transfer.files.reduce((n, f) => n + f.sent, 0);
    });

    receiver.on('received', ({ sessionId, fileName }) => {
      const transfer = this.transfers.get(sessionId);
      if (!transfer) return;
      const entry = transfer.files.find((f) => f.name === fileName);
      if (entry) {
        entry.done = true;
        entry.sent = entry.size;
      }
      transfer.sentBytes = transfer.files.reduce((n, f) => n + f.sent, 0);
      if (transfer.files.every((f) => f.done)) {
        transfer.status = 'done';
        transfer.sentBytes = transfer.totalBytes;
        transfer.finishedAt = Date.now();
      }
    });

    const fail = (label) => ({ sessionId, peer }) => {
      const transfer = this.transfers.get(sessionId);
      if (!transfer) return;
      transfer.status = 'failed';
      transfer.error = label;
      transfer.finishedAt = Date.now();
      if (peer?.alias) transfer.peerAlias = peer.alias;
    };
    receiver.on('cancelled', fail('cancelled by the sender'));
    receiver.on('expired', fail('session expired'));
    receiver.on('rejected', ({ alias, reason }) => {
      for (const transfer of this.transfers.values()) {
        if (transfer.direction === 'in' && transfer.status === 'receiving' && transfer.peerAlias === alias) {
          transfer.status = 'failed';
          transfer.error = reason;
        }
      }
    });
  }

  #remember(transfer) {
    this.transfers.set(transfer.id, transfer);
    while (this.transfers.size > KEEP_TRANSFERS) {
      const oldest = this.transfers.keys().next().value;
      this.transfers.delete(oldest);
    }
  }

  // ------------------------------------------------------------------ routing

  async #handle(req, res) {
    this.#guard(req);

    const url = new URL(req.url ?? '/', 'http://127.0.0.1');
    const segments = url.pathname.split('/').filter(Boolean);
    const method = req.method ?? 'GET';

    if (method === 'GET' && segments.length === 0) {
      const body = Buffer.from(this.html, 'utf8');
      res.writeHead(200, {
        'content-type': 'text/html; charset=utf-8',
        'content-length': body.length,
        'cache-control': 'no-store',
        'x-content-type-options': 'nosniff',
        'referrer-policy': 'no-referrer',
      });
      res.end(body);
      return;
    }

    if (method === 'GET' && segments.length === 2 && segments[1] === 'state') {
      return sendJson(res, 200, this.#state());
    }

    if (method === 'POST' && segments.length === 2 && segments[1] === 'stage') {
      return await this.#stage(req, res, url);
    }

    if (method === 'DELETE' && segments.length === 3 && segments[1] === 'stage') {
      const removed = await this.#dropStaged(segments[2]);
      if (!removed) throw new UiError(404, 'no such staged file');
      return sendJson(res, 200, { ok: true });
    }

    if (method === 'POST' && segments.length === 2 && segments[1] === 'send') {
      return await this.#send(req, res);
    }

    if (method === 'POST' && segments.length === 3 && segments[1] === 'incoming') {
      return await this.#decide(segments[2], req, res);
    }

    throw new UiError(404, 'no such route');
  }

  #guard(req) {
    const host = String(req.headers.host ?? '').toLowerCase();
    if (!this.allowedHosts.has(host)) throw new UiError(403, 'unexpected Host header');

    const origin = req.headers.origin;
    if (origin && !this.allowedHosts.has(origin.replace(/^http:\/\//, ''))) {
      throw new UiError(403, 'cross-origin request refused');
    }

    const url = req.url ?? '/';
    const isApi = url.startsWith('/api/');
    if (isApi && !safeEqual(req.headers['x-bhejo-token'], this.token)) {
      throw new UiError(403, 'missing or wrong token');
    }
  }

  #state() {
    return {
      device: {
        alias: this.identity.alias,
        fingerprint: this.identity.fingerprint,
        deviceType: this.identity.deviceType,
        dir: this.receiver?.dir ?? '',
        port: this.receiver?.port ?? null,
        pin: this.receiver?.pin ?? null,
      },
      peers: (this.discovery?.peers() ?? []).map((peer) => ({
        alias: peer.alias,
        address: peer.address,
        port: peer.port,
        fingerprint: peer.fingerprint,
        deviceType: peer.deviceType,
      })),
      staged: [...this.staged.values()].map((file) => ({
        id: file.id,
        name: file.name,
        size: file.size,
      })),
      requests: [...this.pending.values()].map((entry) => ({
        id: entry.id,
        alias: entry.peer.alias,
        address: entry.peer.address,
        fingerprint: entry.peer.fingerprint,
        files: entry.request.files,
        totalBytes: entry.request.totalBytes,
        isNew: this.trust ? !this.trust.isKnown(entry.peer.fingerprint) : false,
        createdAt: entry.createdAt,
      })),
      transfers: [...this.transfers.values()].map((transfer) => ({
        id: transfer.id,
        direction: transfer.direction,
        peerAlias: transfer.peerAlias,
        files: transfer.files.map((f) => ({ name: f.name, size: f.size, sent: f.sent, done: f.done })),
        sentBytes: transfer.sentBytes,
        totalBytes: transfer.totalBytes,
        status: transfer.status,
        error: transfer.error,
        startedAt: transfer.startedAt,
      })),
    };
  }

  // ------------------------------------------------------------------ staging

  async #stage(req, res, url) {
    if (this.staged.size >= MAX_STAGED_FILES) throw new UiError(413, 'too many staged files');

    const requested = url.searchParams.get('name') ?? 'file';
    const name =
      requested
        .split(/[\\/]+/)
        .filter((s) => s && s !== '.' && s !== '..')
        .map(sanitizeSegment)
        .join('/') || 'file';

    const id = randomToken(8);
    const spoolPath = path.join(this.spool, id);
    const out = fs.createWriteStream(spoolPath, { flags: 'wx', mode: 0o600 });
    let size = 0;

    try {
      for await (const chunk of req) {
        size += chunk.length;
        if (size > MAX_STAGE_BYTES) throw new UiError(413, 'file too large');
        if (!out.write(chunk)) await once(out, 'drain');
      }
      await new Promise((resolve, reject) => out.end((err) => (err ? reject(err) : resolve())));
    } catch (err) {
      out.destroy();
      await fs.promises.unlink(spoolPath).catch(() => {});
      throw err;
    }

    this.staged.set(id, { id, name, size, path: spoolPath });
    return sendJson(res, 200, { id, name, size });
  }

  async #dropStaged(id) {
    const entry = this.staged.get(id);
    if (!entry) return false;
    this.staged.delete(id);
    await fs.promises.unlink(entry.path).catch(() => {});
    return true;
  }

  // --------------------------------------------------------------------- send

  async #send(req, res) {
    const body = await readJson(req);
    const target = String(body.target ?? '');
    const pin = body.pin == null || body.pin === '' ? null : String(body.pin);

    const peer = (this.discovery?.peers() ?? []).find((p) => p.fingerprint === target);
    if (!peer) throw new UiError(409, 'that device is not visible right now');

    const files = [...this.staged.values()];
    if (!files.length) throw new UiError(400, 'nothing to send');

    const transfer = {
      id: randomToken(6),
      direction: 'out',
      peerAlias: peer.alias,
      files: files.map((f) => ({ name: f.name, size: f.size, sent: 0, done: false })),
      sentBytes: 0,
      totalBytes: files.reduce((n, f) => n + f.size, 0),
      status: 'sending',
      error: null,
      startedAt: Date.now(),
    };
    this.#remember(transfer);

    // Answer immediately; the transfer continues in the background and the page
    // picks up progress by polling /api/state.
    sendJson(res, 200, { transferId: transfer.id });

    this.#runSend({ transfer, peer, files, pin }).catch((err) => {
      transfer.status = 'failed';
      transfer.error = err.message;
      transfer.finishedAt = Date.now();
    });
  }

  async #runSend({ transfer, peer, files, pin }) {
    try {
      const result = await sendFiles({
        host: peer.address,
        port: peer.port,
        expectedFingerprint: peer.fingerprint,
        pin,
        files: files.map((f) => ({ absolutePath: f.path, fileName: f.name, size: f.size })),
        senderAlias: this.identity.alias,
        senderFingerprint: this.identity.fingerprint,
        onProgress: ({ fileName, sent }) => {
          const entry = transfer.files.find((f) => f.name === fileName);
          if (entry) entry.sent = sent;
          transfer.sentBytes = transfer.files.reduce((n, f) => n + f.sent, 0);
        },
      });

      for (const item of result.results) {
        if (!item.ok) continue;
        const staged = [...this.staged.values()].find((s) => s.name === item.file.fileName);
        if (staged) await this.#dropStaged(staged.id);
        const entry = transfer.files.find((f) => f.name === item.file.fileName);
        if (entry) {
          entry.done = true;
          entry.sent = entry.size;
        }
      }

      const failed = result.results.filter((item) => !item.ok);
      if (failed.length) {
        transfer.status = failed.length === result.results.length ? 'failed' : 'done';
        transfer.error = failed[0].error;
      } else {
        transfer.status = 'done';
      }
      transfer.sentBytes = transfer.files.reduce((n, f) => n + f.sent, 0);
    } catch (err) {
      transfer.status = 'failed';
      transfer.error = err.message;
    } finally {
      transfer.finishedAt = Date.now();
      this.trust?.touch(peer.fingerprint, peer.address);
    }
  }

  // ---------------------------------------------------------------- decisions

  async #decide(id, req, res) {
    const entry = this.pending.get(id);
    if (!entry) throw new UiError(404, 'that request is no longer pending');

    const body = await readJson(req);
    const accepted = body.action === 'accept';

    if (accepted && this.trust) {
      this.trust.remember(entry.peer.fingerprint, {
        alias: entry.peer.alias,
        address: entry.peer.address,
      });
    }

    entry.resolve(
      accepted
        ? { accepted: true }
        : { accepted: false, reason: 'declined in the browser' },
    );
    return sendJson(res, 200, { ok: true, accepted });
  }
}
