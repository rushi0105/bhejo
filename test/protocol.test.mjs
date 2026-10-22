// End-to-end protocol tests. A real HTTPS receiver, a real sender, real files
// on disk, and assertions on the bytes that land there.

import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { loadIdentity } from '../src/identity.mjs';
import { Receiver } from '../src/receiver.mjs';
import { connectPinned, exchange, sendFiles } from '../src/sender.mjs';
import { collectFiles, sha256File } from '../src/util.mjs';

async function scratch(prefix) {
  return fs.mkdtemp(path.join(os.tmpdir(), `bhejo-${prefix}-`));
}

/** Issue a request directly, bypassing the CLI's friendlier checks. */
async function rawRequest({ port, fingerprint, method, reqPath, body, headers = {} }) {
  const pinned = await connectPinned({ host: '127.0.0.1', port, expectedFingerprint: fingerprint });
  try {
    return await exchange(pinned.socket, {
      method,
      path: reqPath,
      host: `127.0.0.1:${port}`,
      headers,
      body,
    });
  } finally {
    pinned.socket.destroy();
  }
}

async function startReceiver(overrides = {}) {
  const dir = await scratch('dst');
  const receiver = new Receiver({
    identity: loadIdentity({ ephemeral: true }),
    dir,
    port: 0,
    autoAccept: true,
    ...overrides,
  });
  const started = await receiver.start();
  return { receiver, dir, ...started };
}

test('transfers a batch of files byte-for-byte over pinned TLS', async (t) => {
  const srcDir = await scratch('src');
  const { receiver, dir, port, fingerprint } = await startReceiver();
  t.after(async () => {
    await receiver.stop();
    await receiver.stop().catch(() => {});
  });

  try {
    const sizes = [0, 1, 1234, 3 * 1024 * 1024];
    const created = [];
    for (const size of sizes) {
      const file = path.join(srcDir, `payload-${size}.bin`);
      await fs.writeFile(file, crypto.randomBytes(size));
      created.push(file);
    }
    const textFile = path.join(srcDir, 'notes.txt');
    await fs.writeFile(textFile, 'hello from the LAN\n');
    created.push(textFile);

    const files = collectFiles(created);
    const result = await sendFiles({
      host: '127.0.0.1',
      port,
      expectedFingerprint: fingerprint,
      files,
      senderAlias: 'test-runner',
    });

    assert.equal(result.results.length, files.length);
    for (const entry of result.results) {
      assert.ok(entry.ok, `${entry.file.fileName} failed: ${entry.error}`);
    }

    for (const file of files) {
      const destination = path.join(dir, file.fileName);
      const stat = await fs.stat(destination);
      assert.equal(stat.size, file.size, `${file.fileName} size differs`);
      assert.equal(
        await sha256File(destination),
        await sha256File(file.absolutePath),
        `${file.fileName} content differs`,
      );
    }
  } finally {
    await receiver.stop();
  }
});

test('a hostile filename cannot escape the destination directory', async (t) => {
  const { receiver, dir, port, fingerprint } = await startReceiver();
  t.after(() => receiver.stop());

  try {
    const payload = Buffer.from('pwned');
    const prepared = await rawRequest({
      port,
      fingerprint,
      method: 'POST',
      reqPath: '/api/v1/prepare-upload',
      headers: { 'content-type': 'application/json' },
      body: Buffer.from(
        JSON.stringify({
          info: { alias: 'attacker', fingerprint: 'f'.repeat(64) },
          files: [
            { id: 'a', fileName: '../../../evil.txt', size: payload.length },
            { id: 'b', fileName: 'C:\\Windows\\System32\\evil.dll', size: payload.length },
            { id: 'c', fileName: '/etc/cron.d/evil', size: payload.length },
          ],
        }),
      ),
    });

    assert.equal(prepared.status, 200);
    for (const granted of prepared.json.files) {
      const query = new URLSearchParams({
        sessionId: prepared.json.sessionId,
        fileId: granted.id,
        token: granted.token,
      });
      const response = await rawRequest({
        port,
        fingerprint,
        method: 'POST',
        reqPath: `/api/v1/upload?${query.toString()}`,
        headers: { 'content-type': 'application/octet-stream', 'content-length': payload.length },
        body: payload,
      });
      assert.equal(response.status, 200, `upload rejected: ${response.text}`);
    }

    const written = await fs.readdir(dir, { recursive: true });
    const root = path.resolve(dir);
    for (const entry of written) {
      const absolute = path.resolve(dir, entry);
      assert.ok(
        absolute === root || absolute.startsWith(root + path.sep),
        `escaped the sandbox: ${absolute}`,
      );
    }
    // Traversal segments are dropped, not honoured.
    assert.ok(written.some((entry) => entry.endsWith('evil.txt')), 'the file should land inside the sandbox');
    await assert.rejects(fs.access(path.resolve(dir, '..', '..', '..', 'evil.txt')));
  } finally {
    await receiver.stop();
  }
});

test('a wrong PIN is refused before anything is written', async (t) => {
  const srcDir = await scratch('src');
  const source = path.join(srcDir, 'secret.txt');
  await fs.writeFile(source, 'sensitive');

  const { receiver, dir, port, fingerprint } = await startReceiver({ pin: '4242' });
  t.after(() => receiver.stop());

  try {
    await assert.rejects(
      sendFiles({
        host: '127.0.0.1',
        port,
        expectedFingerprint: fingerprint,
        pin: '0000',
        files: collectFiles([source]),
      }),
      /wrong or missing PIN/,
    );
    assert.deepEqual(await fs.readdir(dir), [], 'a refused transfer must not create files');

    const ok = await sendFiles({
      host: '127.0.0.1',
      port,
      expectedFingerprint: fingerprint,
      pin: '4242',
      files: collectFiles([source]),
    });
    assert.ok(ok.results[0].ok);
    assert.equal(await fs.readFile(path.join(dir, 'secret.txt'), 'utf8'), 'sensitive');
  } finally {
    await receiver.stop();
  }
});

test('a mismatched fingerprint aborts before the request is sent', async (t) => {
  const srcDir = await scratch('src');
  const source = path.join(srcDir, 'file.txt');
  await fs.writeFile(source, 'data');

  const { receiver, dir, port } = await startReceiver();
  t.after(() => receiver.stop());

  try {
    await assert.rejects(
      sendFiles({
        host: '127.0.0.1',
        port,
        expectedFingerprint: '0'.repeat(64),
        files: collectFiles([source]),
      }),
      (err) => err.code === 'FINGERPRINT_MISMATCH',
    );
    assert.deepEqual(await fs.readdir(dir), []);
  } finally {
    await receiver.stop();
  }
});

test('a declined transfer is reported, not silently dropped', async (t) => {
  const srcDir = await scratch('src');
  const source = path.join(srcDir, 'file.txt');
  await fs.writeFile(source, 'data');

  const { receiver, dir, port, fingerprint } = await startReceiver({
    autoAccept: false,
    onIncoming: async () => ({ accepted: false, reason: 'user pressed no' }),
  });
  t.after(() => receiver.stop());

  try {
    await assert.rejects(
      sendFiles({
        host: '127.0.0.1',
        port,
        expectedFingerprint: fingerprint,
        files: collectFiles([source]),
      }),
      /user pressed no/,
    );
    assert.deepEqual(await fs.readdir(dir), []);
  } finally {
    await receiver.stop();
  }
});

test('the info endpoint exposes identity but requires no authentication', async (t) => {
  const { receiver, port, fingerprint } = await startReceiver({
    identity: loadIdentity({ ephemeral: true, alias: 'Study Room PC' }),
  });
  t.after(() => receiver.stop());

  try {
    const response = await rawRequest({ port, fingerprint, method: 'GET', reqPath: '/api/v1/info' });
    assert.equal(response.status, 200);
    assert.equal(response.json.alias, 'Study Room PC');
    assert.equal(response.json.fingerprint, fingerprint);
    assert.equal(response.json.requiresPin, false);
  } finally {
    await receiver.stop();
  }
});

test('unknown routes return a JSON 404 rather than leaking a stack trace', async (t) => {
  const { receiver, port, fingerprint } = await startReceiver();
  t.after(() => receiver.stop());

  try {
    const response = await rawRequest({ port, fingerprint, method: 'GET', reqPath: '/admin' });
    assert.equal(response.status, 404);
    assert.match(response.json.error, /no such route/);
    assert.ok(!response.text.includes('at '));
  } finally {
    await receiver.stop();
  }
});
