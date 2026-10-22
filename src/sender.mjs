// Sending side.
//
// Every request runs over a TLS connection that is verified *before* a single
// byte of the request is written. That ordering is the whole point: Node's
// `checkServerIdentity` is skipped when `rejectUnauthorized:false`, so relying
// on it to catch an impostor would silently fail open. Instead we complete the
// handshake ourselves, compare the peer certificate's SHA-256 against the
// fingerprint learned from discovery, and only then write to the socket.
//
// HTTP/1.1 is written by hand instead of going through https.request. Node's
// agent will not reuse an already-connected socket handed to it via
// `createConnection` when `agent:false` (it quietly dials the default port
// instead), and an upload that has already left the process cannot be recalled.
// Writing the request on the verified socket removes that failure mode
// entirely.

import crypto from 'node:crypto';
import fs from 'node:fs';
import { Transform } from 'node:stream';
import tls from 'node:tls';
import { sha256Hex } from './util.mjs';

const HANDSHAKE_TIMEOUT_MS = 10_000;
// Long enough for a human to walk over and press Accept. The prepare-upload
// step blocks on exactly that decision, so a short socket timeout here turns
// "nobody answered yet" into a confusing failure.
const IDLE_TIMEOUT_MS = 180_000;
const MAX_RESPONSE_BYTES = 1024 * 1024;
const MAX_HEADER_BYTES = 64 * 1024;

class FingerprintMismatchError extends Error {
  constructor(expected, actual) {
    super(
      `certificate fingerprint mismatch: expected ${expected.slice(0, 16)}..., got ${actual.slice(0, 16)}.... ` +
        'Someone may be impersonating that device, or it regenerated its identity.',
    );
    this.code = 'FINGERPRINT_MISMATCH';
    this.expected = expected;
    this.actual = actual;
  }
}

/**
 * Open a TLS connection and verify the peer's certificate fingerprint.
 * Nothing is written until this resolves successfully.
 */
export async function connectPinned({ host, port, expectedFingerprint, timeoutMs = HANDSHAKE_TIMEOUT_MS }) {
  const socket = await new Promise((resolve, reject) => {
    const s = tls.connect({
      host,
      port,
      rejectUnauthorized: false, // self-signed by design; the fingerprint is the trust anchor
      servername: undefined,
      minVersion: 'TLSv1.2',
    });
    const timer = setTimeout(() => {
      s.destroy();
      reject(new Error(`TLS handshake with ${host}:${port} timed out after ${timeoutMs}ms`));
    }, timeoutMs);

    s.once('secureConnect', () => {
      clearTimeout(timer);
      resolve(s);
    });
    s.once('error', (err) => {
      clearTimeout(timer);
      reject(err);
    });
  });

  const cert = socket.getPeerCertificate();
  if (!cert || !cert.raw) {
    socket.destroy();
    throw new Error(`${host}:${port} presented no certificate`);
  }

  const fingerprint = sha256Hex(cert.raw);
  if (expectedFingerprint && fingerprint !== expectedFingerprint) {
    socket.destroy();
    throw new FingerprintMismatchError(expectedFingerprint, fingerprint);
  }

  socket.setTimeout(IDLE_TIMEOUT_MS, () => {
    socket.destroy(
      new Error(
        `${host}:${port} stopped responding after ${Math.round(IDLE_TIMEOUT_MS / 1000)}s. ` +
          'If the transfer was waiting for someone to accept it, they did not answer in time.',
      ),
    );
  });
  return { socket, fingerprint };
}

function parseHead(head) {
  const lines = head.split('\r\n');
  const statusLine = lines.shift() ?? '';
  const match = /^HTTP\/1\.[01] (\d{3})/.exec(statusLine);
  if (!match) throw new Error(`malformed status line: ${statusLine.slice(0, 80)}`);

  const headers = Object.create(null);
  for (const line of lines) {
    if (!line) continue;
    const colon = line.indexOf(':');
    if (colon === -1) continue;
    headers[line.slice(0, colon).trim().toLowerCase()] = line.slice(colon + 1).trim();
  }
  return { status: Number(match[1]), headers };
}

/** Decode a complete-or-partial chunked body. */
function decodeChunked(buf) {
  const parts = [];
  let offset = 0;
  for (;;) {
    const lineEnd = buf.indexOf('\r\n', offset);
    if (lineEnd === -1) return { done: false };
    const size = parseInt(buf.subarray(offset, lineEnd).toString('latin1'), 16);
    if (!Number.isFinite(size) || size < 0) return { done: true, error: new Error('bad chunk size') };
    if (size === 0) return { done: true, body: Buffer.concat(parts) };
    const start = lineEnd + 2;
    if (buf.length < start + size) return { done: false };
    parts.push(buf.subarray(start, start + size));
    offset = start + size + 2;
  }
}

/**
 * Perform one HTTP/1.1 exchange on an established TLS socket.
 * Resolves with { status, headers, json, text }. The caller owns the socket.
 */
export function exchange(socket, { method, path, host, headers = {}, body }) {
  return new Promise((resolve, reject) => {
    let buffer = Buffer.alloc(0);
    let head = null;
    let settled = false;

    const finish = (err, value) => {
      if (settled) return;
      settled = true;
      socket.removeListener('data', onData);
      socket.removeListener('error', onError);
      socket.removeListener('close', onClose);
      if (err) reject(err);
      else resolve(value);
    };

    const onError = (err) => finish(err);
    const onClose = () => finish(new Error('connection closed before a complete response arrived'));

    function onData(chunk) {
      buffer = buffer.length ? Buffer.concat([buffer, chunk]) : chunk;

      if (!head) {
        const end = buffer.indexOf('\r\n\r\n');
        if (end === -1) {
          if (buffer.length > MAX_HEADER_BYTES) finish(new Error('response headers too large'));
          return;
        }
        try {
          head = parseHead(buffer.subarray(0, end).toString('latin1'));
        } catch (err) {
          return finish(err);
        }
        buffer = buffer.subarray(end + 4);
      }

      if (buffer.length > MAX_RESPONSE_BYTES) return finish(new Error('response too large'));

      let bodyBuf;
      if (head.headers['transfer-encoding']?.toLowerCase().includes('chunked')) {
        const decoded = decodeChunked(buffer);
        if (decoded.error) return finish(decoded.error);
        if (!decoded.done) return;
        bodyBuf = decoded.body;
      } else {
        const length = Number(head.headers['content-length'] ?? 0);
        if (!Number.isFinite(length)) return finish(new Error('invalid content-length'));
        if (buffer.length < length) return;
        bodyBuf = buffer.subarray(0, length);
      }

      const text = bodyBuf.toString('utf8');
      let json = null;
      try {
        json = JSON.parse(text);
      } catch {
        /* not JSON, leave as text */
      }
      return finish(null, { status: head.status, headers: head.headers, json, text });
    }

    socket.on('data', onData);
    socket.on('error', onError);
    socket.on('close', onClose);

    const lines = [`${method} ${path} HTTP/1.1`, `Host: ${host ?? 'bhejo'}`];
    const hasLength = Object.keys(headers).some((k) => k.toLowerCase() === 'content-length');
    if (body !== undefined && !hasLength && !Buffer.isBuffer(body) && typeof body !== 'string') {
      finish(new Error('streaming bodies need an explicit content-length'));
      return;
    }
    if (body !== undefined && !hasLength) {
      lines.push(`Content-Length: ${Buffer.byteLength(body)}`);
    }
    for (const [key, value] of Object.entries(headers)) lines.push(`${key}: ${value}`);
    lines.push('Connection: close', '', '');

    socket.write(lines.join('\r\n'));

    if (body === undefined) return;

    if (Buffer.isBuffer(body) || typeof body === 'string') {
      socket.write(body);
      return;
    }

    // Streaming upload: never call socket.end() before the response, some peers
    // close the connection on FIN and truncate the reply.
    body.on('error', (err) => {
      socket.destroy();
      finish(err);
    });
    body.pipe(socket, { end: false });
  });
}

/** GET /api/v1/info, returning both the body and the verified fingerprint. */
export async function probe({ host, port, expectedFingerprint, timeoutMs }) {
  const { socket, fingerprint } = await connectPinned({ host, port, expectedFingerprint, timeoutMs });

  try {
    const { status, json, text } = await exchange(socket, {
      method: 'GET',
      path: '/api/v1/info',
      host: `${host}:${port}`,
      headers: { accept: 'application/json' },
    });

    if (status !== 200 || !json) {
      throw new Error(
        `device at ${host}:${port} did not answer the info request (HTTP ${status}): ${text.slice(0, 120)}`,
      );
    }
    if (json.fingerprint !== fingerprint) {
      throw new Error(
        'device advertised a different fingerprint than its certificate carries - refusing to continue',
      );
    }
    return { ...json, fingerprint };
  } finally {
    socket.destroy();
  }
}

/**
 * Send a set of files to a peer.
 *
 * @param {object} opts
 * @param {string} opts.host
 * @param {number} opts.port
 * @param {string} [opts.expectedFingerprint] Pin to this fingerprint. Omit only after the user confirmed it.
 * @param {string|null} [opts.pin]
 * @param {Array<{absolutePath: string, fileName: string, size: number}>} opts.files
 * @param {string} [opts.senderAlias]
 * @param {string|null} [opts.senderFingerprint]
 * @param {(p: {fileName: string, sent: number, total: number, fileIndex: number, fileCount: number}) => void} [opts.onProgress]
 * @param {(msg: string) => void} [opts.onLog]
 * @param {boolean} [opts.verify] Compare the receiver's SHA-256 against the bytes sent.
 */
export async function sendFiles({
  host,
  port,
  expectedFingerprint,
  pin = null,
  files,
  senderAlias = 'bhejo-cli',
  senderFingerprint = null,
  onProgress = () => {},
  onLog = () => {},
  verify = true,
}) {
  if (!files?.length) throw new Error('nothing to send');

  const info = await probe({ host, port, expectedFingerprint });
  onLog(`connected to ${info.alias} at ${host}:${port}`);

  // ---- 1. negotiate -------------------------------------------------------
  const ids = files.map((_, index) => `f${index}`);
  const prepareBody = Buffer.from(
    JSON.stringify({
      info: { alias: senderAlias, fingerprint: senderFingerprint },
      pin: pin ?? undefined,
      files: files.map((file, index) => ({
        id: ids[index],
        fileName: file.fileName,
        size: file.size,
      })),
    }),
    'utf8',
  );

  const prep = await connectPinned({ host, port, expectedFingerprint: info.fingerprint });
  let prepareResult;
  try {
    prepareResult = await exchange(prep.socket, {
      method: 'POST',
      path: '/api/v1/prepare-upload',
      host: `${host}:${port}`,
      headers: { 'content-type': 'application/json', 'content-length': prepareBody.length },
      body: prepareBody,
    });
  } finally {
    prep.socket.destroy();
  }

  if (prepareResult.status !== 200 || !prepareResult.json?.sessionId) {
    const reason = prepareResult.json?.error ?? prepareResult.text.slice(0, 200);
    const hint = prepareResult.status === 403 ? ' (wrong PIN, or the other device declined)' : '';
    throw new Error(`receiver refused the transfer: ${reason}${hint}`);
  }

  const { sessionId, files: granted } = prepareResult.json;
  const tokenById = new Map(granted.map((entry) => [entry.id, entry.token]));

  // ---- 2. upload ----------------------------------------------------------
  const results = [];

  for (let index = 0; index < files.length; index++) {
    const file = files[index];
    const id = ids[index];
    const token = tokenById.get(id);

    if (!token) {
      results.push({ file, ok: false, error: 'receiver did not grant a token for this file' });
      continue;
    }

    const query = new URLSearchParams({ sessionId, fileId: id, token });
    const pinned = await connectPinned({ host, port, expectedFingerprint: info.fingerprint });
    const hash = crypto.createHash('sha256');
    let sent = 0;

    const source = fs.createReadStream(file.absolutePath);
    const meter = new Transform({
      transform: (chunk, _enc, cb) => {
        sent += chunk.length;
        hash.update(chunk);
        onProgress({
          fileName: file.fileName,
          sent,
          total: file.size,
          fileIndex: index,
          fileCount: files.length,
        });
        cb(null, chunk);
      },
    });

    try {
      const { status, json, text } = await exchange(pinned.socket, {
        method: 'POST',
        path: `/api/v1/upload?${query.toString()}`,
        host: `${host}:${port}`,
        headers: {
          'content-type': 'application/octet-stream',
          'content-length': file.size,
        },
        body: source.pipe(meter),
      });

      if (status !== 200 || !json?.ok) {
        const reason = json?.error ?? text.slice(0, 200);
        results.push({ file, ok: false, error: `HTTP ${status}: ${reason}` });
        continue;
      }

      const localHash = hash.digest('hex');
      if (verify && json.sha256 && json.sha256 !== localHash) {
        results.push({
          file,
          ok: false,
          error: `integrity check failed: sent ${localHash.slice(0, 12)}..., receiver stored ${String(json.sha256).slice(0, 12)}...`,
        });
        continue;
      }

      results.push({
        file,
        ok: true,
        bytes: json.bytes,
        sha256: localHash,
        savedAs: json.savedAs,
      });
    } catch (err) {
      results.push({ file, ok: false, error: err.message });
    } finally {
      source.destroy();
      pinned.socket.destroy();
    }
  }

  return { peer: info, sessionId, results };
}

export { FingerprintMismatchError };
