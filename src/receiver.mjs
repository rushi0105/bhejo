// Receiving side: a small HTTPS server that speaks the Bhejo transfer API.
//
// API (all JSON unless noted, all over TLS):
//   GET  /api/v1/info                      -> device identity + fingerprint
//   POST /api/v1/prepare-upload            -> { sessionId, files:[{id,token}] }
//   POST /api/v1/upload?sessionId&fileId&token  (body = raw file bytes)
//   POST /api/v1/cancel?sessionId          -> drop a session early
//
// Two-step design, same shape as LocalSend: metadata is negotiated and
// accepted *before* any bytes are written, so a rejected sender never gets to
// touch the disk.

import crypto from 'node:crypto';
import { EventEmitter } from 'node:events';
import fs from 'node:fs';
import https from 'node:https';
import path from 'node:path';
import { Transform } from 'node:stream';
import { pipeline } from 'node:stream/promises';
import {
  APP_ID,
  PROTOCOL_VERSION,
  SESSION_TTL_MS,
  humanBytes,
  randomToken,
  safeEqual,
  safeResolve,
  uniquePath,
} from './util.mjs';

const MAX_JSON_BODY = 1024 * 1024;
const MAX_CONCURRENT_UPLOADS = 4;
const MAX_FILES_PER_SESSION = 10_000;

class HttpError extends Error {
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
    connection: 'close',
  });
  res.end(payload);
}

async function readJson(req, limit) {
  const chunks = [];
  let size = 0;
  for await (const chunk of req) {
    size += chunk.length;
    if (size > limit) throw new HttpError(413, 'request body too large');
    chunks.push(chunk);
  }
  if (!chunks.length) return {};
  try {
    return JSON.parse(Buffer.concat(chunks).toString('utf8'));
  } catch {
    throw new HttpError(400, 'malformed JSON');
  }
}

export class Receiver extends EventEmitter {
  /**
   * @param {object} opts
   * @param {object} opts.identity     Result of loadIdentity().
   * @param {string} opts.dir          Destination directory.
   * @param {number} [opts.port]       Preferred port; falls back to an ephemeral one if taken.
   * @param {string|null} [opts.pin]   Required PIN, or null for none.
   * @param {boolean} [opts.autoAccept] Accept without asking.
   * @param {(req: object) => Promise<{accepted: boolean, reason?: string}>} [opts.onIncoming]
   * @param {(msg: string) => void} [opts.log]
   */
  constructor({
    identity,
    dir,
    port = 53317,
    pin = null,
    autoAccept = false,
    onIncoming,
    log = () => {},
  }) {
    super();
    this.identity = identity;
    this.dir = path.resolve(dir);
    this.preferredPort = port;
    this.pin = pin ? String(pin) : null;
    this.autoAccept = autoAccept;
    this.onIncoming = onIncoming;
    this.log = log;

    /** @type {Map<string, object>} sessionId -> session */
    this.sessions = new Map();
    this.activeUploads = 0;
    this.server = null;
    this.sweeper = null;
    this.port = null;
    this.sockets = new Set();
  }

  async start() {
    fs.mkdirSync(this.dir, { recursive: true });
    this.server = https.createServer(
      { key: this.identity.keyPem, cert: this.identity.certPem, minVersion: 'TLSv1.2' },
      (req, res) => this.#handle(req, res),
    );
    this.server.on('connection', (socket) => {
      this.sockets.add(socket);
      socket.on('close', () => this.sockets.delete(socket));
      socket.setTimeout(120_000, () => socket.destroy());
    });
    this.server.on('error', (err) => this.emit('error', err));

    this.port = await this.#listen(this.preferredPort);
    if (this.port !== this.preferredPort && this.preferredPort !== 0) {
      this.log(`port ${this.preferredPort} was busy; listening on ${this.port} instead`);
    }

    this.sweeper = setInterval(() => this.#sweep(), 30_000);
    this.sweeper.unref?.();

    return { port: this.port, fingerprint: this.identity.fingerprint, dir: this.dir };
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
        this.server.listen(p, '0.0.0.0');
      });

    try {
      return await attempt(port);
    } catch (err) {
      if (err.code === 'EADDRINUSE' && port !== 0) return attempt(0);
      throw err;
    }
  }

  async stop() {
    if (this.sweeper) clearInterval(this.sweeper);
    this.sweeper = null;
    for (const socket of this.sockets) socket.destroy();
    this.sockets.clear();
    if (!this.server) return;
    const server = this.server;
    this.server = null;
    await new Promise((resolve) => {
      server.close(resolve);
      server.closeAllConnections?.();
    });
  }

  async #handle(req, res) {
    const url = new URL(req.url ?? '/', 'https://placeholder');
    const route = `${req.method} ${url.pathname}`;

    try {
      switch (route) {
        case 'GET /api/v1/info':
          return sendJson(res, 200, {
            app: APP_ID,
            proto: PROTOCOL_VERSION,
            alias: this.identity.alias,
            deviceType: this.identity.deviceType,
            fingerprint: this.identity.fingerprint,
            requiresPin: Boolean(this.pin),
          });

        case 'POST /api/v1/prepare-upload':
          return await this.#prepareUpload(req, res, url);

        case 'POST /api/v1/upload':
          return await this.#upload(req, res, url);

        case 'POST /api/v1/cancel':
          return this.#cancel(req, res, url);

        case 'GET /':
          res.writeHead(200, { 'content-type': 'text/plain; charset=utf-8', connection: 'close' });
          return res.end(`${APP_ID} receiver is running. Use the app or CLI to send files.\n`);

        default:
          throw new HttpError(404, `no such route: ${route}`);
      }
    } catch (err) {
      const status = err instanceof HttpError ? err.status : 500;
      if (status >= 500) this.emit('error', err);
      if (!res.headersSent) {
        sendJson(res, status, { error: err.message ?? 'internal error' });
      } else {
        res.destroy();
      }
    }
  }

  async #prepareUpload(req, res, url) {
    const body = await readJson(req, MAX_JSON_BODY);
    const info = body.info && typeof body.info === 'object' ? body.info : {};
    const files = Array.isArray(body.files) ? body.files : [];

    if (files.length === 0) throw new HttpError(400, 'no files in request');
    if (files.length > MAX_FILES_PER_SESSION) throw new HttpError(413, 'too many files');

    // PIN is checked before the user is bothered with a prompt.
    if (this.pin) {
      const supplied = body.pin ?? url.searchParams.get('pin');
      if (!safeEqual(supplied, this.pin)) {
        this.emit('rejected', { alias: info.alias ?? 'unknown', reason: 'wrong PIN' });
        throw new HttpError(403, 'wrong or missing PIN');
      }
    }

    const peer = {
      alias: typeof info.alias === 'string' && info.alias.trim() ? info.alias.slice(0, 64) : 'unknown device',
      fingerprint: typeof info.fingerprint === 'string' ? info.fingerprint : '',
      address: req.socket.remoteAddress?.replace(/^::ffff:/, '') ?? 'unknown',
    };

    const declared = [];
    for (const raw of files) {
      if (!raw || typeof raw !== 'object') throw new HttpError(400, 'malformed file entry');
      const id = typeof raw.id === 'string' ? raw.id : null;
      const fileName = typeof raw.fileName === 'string' ? raw.fileName : null;
      const size = Number(raw.size);
      if (!id || !fileName) throw new HttpError(400, 'file entry needs id and fileName');
      if (!Number.isInteger(size) || size < 0) throw new HttpError(400, 'file entry needs a valid size');
      declared.push({ id, fileName, size });
    }

    this.emit('incoming', { peer, files: declared, totalBytes: declared.reduce((n, f) => n + f.size, 0) });

    const decision = await this.#decide({ peer, files: declared });

    if (!decision || !decision.accepted) {
      this.emit('rejected', { alias: peer.alias, reason: decision?.reason ?? 'declined' });
      throw new HttpError(403, decision?.reason ?? 'declined by receiver');
    }

    const sessionId = randomToken(12);
    const session = {
      id: sessionId,
      peer,
      createdAt: Date.now(),
      expiresAt: Date.now() + SESSION_TTL_MS,
      state: 'open',
      files: new Map(),
    };

    for (const file of declared) {
      session.files.set(file.id, {
        id: file.id,
        fileName: file.fileName,
        size: file.size,
        token: randomToken(16),
        state: 'pending',
      });
    }

    this.sessions.set(sessionId, session);
    this.emit('accepted', { sessionId, peer, files: declared });

    return sendJson(res, 200, {
      sessionId,
      files: [...session.files.values()].map((f) => ({ id: f.id, token: f.token })),
    });
  }

  async #decide(request) {
    if (this.onIncoming) {
      try {
        return await this.onIncoming(request);
      } catch (err) {
        this.log(`accept handler failed: ${err.message}`);
        return { accepted: false, reason: 'receiver error' };
      }
    }
    return this.autoAccept
      ? { accepted: true }
      : { accepted: false, reason: 'receiver is not accepting transfers' };
  }

  async #upload(req, res, url) {
    const sessionId = url.searchParams.get('sessionId');
    const fileId = url.searchParams.get('fileId');
    const token = url.searchParams.get('token');

    const session = this.sessions.get(sessionId);
    if (!session) throw new HttpError(404, 'unknown or expired session');
    if (session.expiresAt < Date.now()) {
      this.sessions.delete(sessionId);
      throw new HttpError(410, 'session expired');
    }

    const file = session.files.get(fileId);
    if (!file) throw new HttpError(404, 'file is not part of this session');
    if (!safeEqual(token, file.token)) throw new HttpError(403, 'bad file token');
    if (file.state !== 'pending') throw new HttpError(409, `file is already ${file.state}`);
    if (this.activeUploads >= MAX_CONCURRENT_UPLOADS) throw new HttpError(503, 'too many uploads in flight');

    const declaredLength = Number(req.headers['content-length']);
    if (Number.isFinite(declaredLength) && declaredLength !== file.size) {
      throw new HttpError(400, `content-length ${declaredLength} does not match declared size ${file.size}`);
    }

    const target = safeResolve(this.dir, file.fileName);
    fs.mkdirSync(path.dirname(target), { recursive: true });
    const finalPath = uniquePath(target);

    file.state = 'receiving';
    this.activeUploads++;

    const hash = crypto.createHash('sha256');
    let bytes = 0;
    const started = Date.now();

    try {
      // wx: fail rather than clobber if something appeared at this path since
      // uniquePath() checked. This is the TOCTOU guard.
      const out = fs.createWriteStream(finalPath, { flags: 'wx', mode: 0o644 });
      const meter = new Transform({
        transform: (chunk, _enc, cb) => {
          bytes += chunk.length;
          hash.update(chunk);
          this.emit('progress', {
            sessionId,
            fileId,
            fileName: file.fileName,
            bytes,
            total: file.size,
          });
          cb(null, chunk);
        },
      });

      await pipeline(req, meter, out);

      if (bytes !== file.size) {
        throw new HttpError(400, `received ${bytes} bytes, expected ${file.size}`);
      }

      file.state = 'done';
      file.savedAs = finalPath;
      file.bytes = bytes;
      file.sha256 = hash.digest('hex');
      file.elapsedMs = Date.now() - started;

      const relative = path.relative(this.dir, finalPath).split(path.sep).join('/');
      this.emit('received', { ...file, sessionId, relative, peer: session.peer });

      return sendJson(res, 200, {
        ok: true,
        savedAs: relative,
        bytes,
        sha256: file.sha256,
      });
    } catch (err) {
      file.state = 'failed';
      await fs.promises.unlink(finalPath).catch(() => {});
      if (err instanceof HttpError) throw err;
      if (err.code === 'EEXIST') throw new HttpError(409, 'destination file already exists');
      throw new HttpError(500, `write failed: ${err.message}`);
    } finally {
      this.activeUploads--;
    }
  }

  #cancel(req, res, url) {
    const sessionId = url.searchParams.get('sessionId');
    const session = this.sessions.get(sessionId);
    if (session) {
      session.state = 'cancelled';
      this.sessions.delete(sessionId);
      this.emit('cancelled', { sessionId, peer: session.peer });
    }
    return sendJson(res, 200, { ok: true });
  }

  #sweep() {
    const now = Date.now();
    for (const [id, session] of this.sessions) {
      if (session.expiresAt < now) {
        this.sessions.delete(id);
        this.emit('expired', { sessionId: id, peer: session.peer });
      }
    }
  }

  /** Human-readable summary, used by the CLI. */
  static describeIncoming({ peer, files, totalBytes }) {
    const lines = [
      `${peer.alias} (${peer.address}) wants to send ${files.length} file${files.length === 1 ? '' : 's'} (${humanBytes(totalBytes)})`,
    ];
    for (const file of files.slice(0, 12)) {
      lines.push(`   ${file.fileName}  ${humanBytes(file.size)}`);
    }
    if (files.length > 12) lines.push(`   ... and ${files.length - 12} more`);
    return lines.join('\n');
  }
}
