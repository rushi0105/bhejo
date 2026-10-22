import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

export const PROTOCOL_VERSION = 1;
export const APP_ID = 'bhejo';
export const DEFAULT_PORT = 53317;
export const DEFAULT_MULTICAST_ADDRESS = '224.0.0.167';
export const SESSION_TTL_MS = 10 * 60 * 1000;

export function sha256Hex(buf) {
  return crypto.createHash('sha256').update(buf).digest('hex');
}

export async function sha256File(filePath) {
  const hash = crypto.createHash('sha256');
  await new Promise((resolve, reject) => {
    fs.createReadStream(filePath)
      .on('data', (chunk) => hash.update(chunk))
      .on('error', reject)
      .on('end', resolve);
  });
  return hash.digest('hex');
}

export function randomToken(bytes = 16) {
  return crypto.randomBytes(bytes).toString('hex');
}

export function humanBytes(n) {
  if (!Number.isFinite(n)) return '?';
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  let value = n;
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit++;
  }
  return unit === 0 ? `${value} B` : `${value.toFixed(value < 10 ? 1 : 0)} ${units[unit]}`;
}

export function humanDuration(ms) {
  if (ms < 1000) return `${Math.round(ms)}ms`;
  if (ms < 60_000) return `${(ms / 1000).toFixed(1)}s`;
  return `${Math.floor(ms / 60_000)}m${Math.round((ms % 60_000) / 1000)}s`;
}

export const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

/** Constant-time string compare that tolerates unequal lengths. */
export function safeEqual(a, b) {
  const bufA = Buffer.from(String(a ?? ''), 'utf8');
  const bufB = Buffer.from(String(b ?? ''), 'utf8');
  if (bufA.length !== bufB.length) return false;
  return crypto.timingSafeEqual(bufA, bufB);
}

const WINDOWS_RESERVED = /^(con|prn|aux|nul|com[1-9]|lpt[1-9])(\.|$)/i;

/**
 * Reduce a single path segment to something safe to write on disk everywhere.
 * Rejects absolute paths, control characters, Windows-reserved names, and any
 * leading dots (which would let a peer drop hidden files or ".bashrc").
 */
export function sanitizeSegment(name) {
  let base = String(name ?? '')
    .replace(/[\\/]/g, ' ')                 // no separators inside a segment
    .replace(/[\u0000-\u001f\u007f]/g, '')  // no control characters
    .replace(/[<>:"|?*]/g, '_')             // illegal on Windows
    .replace(/\s+/g, ' ')
    .trim()
    .replace(/^\.+/, '');                   // no hidden / traversal names

  if (!base) base = 'file';
  if (WINDOWS_RESERVED.test(base)) base = `_${base}`;
  if (base.length > 160) {
    const ext = path.extname(base).slice(0, 16);
    base = base.slice(0, 160 - ext.length) + ext;
  }
  return base;
}

/**
 * Resolve an untrusted relative path inside `baseDir`.
 *
 * The peer controls the file name, so this is the security boundary: every
 * segment is sanitized, traversal segments are dropped, and the result is
 * re-checked to be inside baseDir before anything is opened.
 */
export function safeResolve(baseDir, relativeName) {
  const root = path.resolve(baseDir);
  const segments = String(relativeName ?? '')
    .split(/[\\/]+/)
    .filter((s) => s && s !== '.' && s !== '..')
    .map(sanitizeSegment);

  if (segments.length === 0) segments.push('file');

  const target = path.resolve(root, ...segments);
  if (target !== root && !target.startsWith(root + path.sep)) {
    throw new Error(`refusing to write outside of ${root}`);
  }
  return target;
}

/**
 * Find a non-existing path, appending " (1)", " (2)" … before the extension.
 * This only narrows the race; callers still open with O_EXCL.
 */
export function uniquePath(target) {
  if (!fs.existsSync(target)) return target;
  const dir = path.dirname(target);
  const ext = path.extname(target);
  const stem = path.basename(target, ext);
  for (let i = 1; i < 10_000; i++) {
    const candidate = path.join(dir, `${stem} (${i})${ext}`);
    if (!fs.existsSync(candidate)) return candidate;
  }
  throw new Error(`could not find a free filename near ${target}`);
}

/** Primary non-internal IPv4 address, for display and multicast membership. */
export function primaryIpv4() {
  const nets = os.networkInterfaces();
  for (const list of Object.values(nets)) {
    for (const net of list ?? []) {
      if (net.family === 'IPv4' && !net.internal) return net.address;
    }
  }
  return '127.0.0.1';
}

export function allIpv4() {
  const out = [];
  for (const list of Object.values(os.networkInterfaces())) {
    for (const net of list ?? []) {
      if (net.family === 'IPv4' && !net.internal) out.push(net.address);
    }
  }
  return out;
}

export function defaultAlias() {
  const host = os.hostname().replace(/\.local$/i, '');
  return host || 'Bhejo device';
}

export function deviceType() {
  switch (process.platform) {
    case 'win32': return 'desktop';
    case 'darwin': return 'desktop';
    case 'android': return 'mobile';
    case 'ios': return 'mobile';
    default: return 'desktop';
  }
}

/** Recursively expand user-supplied paths into a flat upload list. */
export function collectFiles(inputs) {
  const files = [];

  const walk = (absPath, relPrefix, depth) => {
    if (depth > 24) throw new Error(`directory nesting too deep: ${absPath}`);
    const stat = fs.statSync(absPath);
    if (stat.isDirectory()) {
      for (const entry of fs.readdirSync(absPath, { withFileTypes: true })) {
        if (entry.isSymbolicLink()) continue; // never follow links out of the tree
        walk(path.join(absPath, entry.name), path.join(relPrefix, entry.name), depth + 1);
      }
      return;
    }
    if (!stat.isFile()) return;
    files.push({
      absolutePath: absPath,
      // Always forward slashes on the wire; each side normalises its own way.
      fileName: relPrefix.split(path.sep).join('/'),
      size: stat.size,
    });
  };

  for (const input of inputs) {
    const abs = path.resolve(input);
    if (!fs.existsSync(abs)) throw new Error(`no such file or directory: ${input}`);
    const stat = fs.statSync(abs);
    walk(abs, stat.isDirectory() ? path.basename(abs) : path.basename(abs), 0);
  }

  return files;
}
