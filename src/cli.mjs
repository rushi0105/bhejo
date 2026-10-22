// Command line interface.
//
// Four verbs, in order of how often you will use them: receive (also the
// default), send, discover, info.

import fs from 'node:fs';
import path from 'node:path';
import readline from 'node:readline';
import { createRequire } from 'node:module';
import { fingerprintOfPem, formatFingerprint } from './cert.mjs';
import { Discovery, discoverFor } from './discovery.mjs';
import { loadIdentity, bhejoHome } from './identity.mjs';
import { Receiver } from './receiver.mjs';
import { FingerprintMismatchError, probe, sendFiles } from './sender.mjs';
import { TrustStore } from './trust.mjs';
import { UiServer } from './ui.mjs';
import {
  DEFAULT_PORT,
  allIpv4,
  collectFiles,
  humanBytes,
  humanDuration,
  primaryIpv4,
} from './util.mjs';

const require = createRequire(import.meta.url);
const pkg = require('../package.json');

// ------------------------------------------------------------------ output

const useColor = Boolean(process.stdout.isTTY) && !process.env.NO_COLOR;
const ansi = (code) => (s) => (useColor ? `\x1b[${code}m${s}\x1b[0m` : String(s));
const bold = ansi('1');
const dim = ansi('2');
const red = ansi('31');
const green = ansi('32');
const yellow = ansi('33');
const cyan = ansi('36');

const say = (msg = '') => process.stdout.write(`${msg}\n`);
const warn = (msg) => process.stderr.write(`${yellow('!')} ${msg}\n`);

// Windows consoles are often on a legacy code page (CP437 here) that cannot
// represent U+2713 or U+2014. Node writes UTF-8 regardless, so those glyphs
// arrive as mojibake. Detect the common case and fall back to ASCII.
function detectUnicode() {
  if (process.env.BHEJO_ASCII) return false;
  if (process.env.BHEJO_UNICODE) return true;
  if (process.platform !== 'win32') return true;
  return Boolean(process.env.WT_SESSION || process.env.TERM_PROGRAM || process.env.ConEmuANSI);
}

const G = detectUnicode()
  ? { ok: '✓', bad: '✗', dash: '—', dots: '…' }
  : { ok: '[ok]', bad: '[fail]', dash: '-', dots: '...' };

export class CliError extends Error {
  constructor(message, exitCode = 1) {
    super(message);
    this.name = 'CliError';
    this.exitCode = exitCode;
  }
}

// ----------------------------------------------------------------- prompts

let rl = null;
let promptChain = Promise.resolve();

function rawAsk(question) {
  if (!process.stdin.isTTY) return Promise.resolve('');
  rl ??= readline.createInterface({ input: process.stdin, output: process.stdout });
  return new Promise((resolve) => rl.question(question, (answer) => resolve(answer.trim())));
}

/** Serialise prompts so two simultaneous transfers cannot interleave. */
function ask(question) {
  const next = promptChain.then(() => rawAsk(question));
  promptChain = next.then(
    () => {},
    () => {},
  );
  return next;
}

function closePrompts() {
  rl?.close();
  rl = null;
}

// -------------------------------------------------------------- arguments

const BOOLEAN_FLAGS = new Set([
  'autoAccept',
  'ephemeral',
  'help',
  'json',
  'noDiscovery',
  'noPin',
  'noUi',
  'noVerify',
  'self',
  'trust',
  'verbose',
  'version',
  'yes',
]);

const COMMANDS = new Set(['receive', 'send', 'discover', 'info', 'cert', 'help']);

export function parseArgs(argv) {
  const out = { _: [] };

  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];

    if (arg === '--') {
      out._.push(...argv.slice(i + 1));
      break;
    }
    if (arg === '-h') {
      out.help = true;
      continue;
    }
    if (arg === '-v') {
      out.version = true;
      continue;
    }
    if (!arg.startsWith('-')) {
      out._.push(arg);
      continue;
    }

    const body = arg.slice(2);
    const eq = body.indexOf('=');
    const rawKey = eq === -1 ? body : body.slice(0, eq);
    const key = rawKey.replace(/-([a-z])/g, (_, c) => c.toUpperCase());

    if (eq !== -1) {
      out[key] = body.slice(eq + 1);
      continue;
    }
    if (BOOLEAN_FLAGS.has(key)) {
      out[key] = true;
      continue;
    }
    const next = argv[i + 1];
    if (next !== undefined && !next.startsWith('-')) {
      out[key] = next;
      i++;
    } else {
      out[key] = true;
    }
  }

  return out;
}

// ------------------------------------------------------------------- main

export async function main(argv) {
  const [first, ...rest] = argv;
  const command = COMMANDS.has(first) ? first : 'receive';
  const opts = parseArgs(COMMANDS.has(first) ? rest : argv);

  if (opts.version) {
    say(pkg.version);
    return 0;
  }
  if (opts.help || command === 'help') {
    printHelp(command === 'help' ? opts._[0] : command);
    return 0;
  }

  if (!COMMANDS.has(first) && first && !first.startsWith('-') && command === 'receive' && opts._.length === 1) {
    // `bhejo some-file.txt` — almost certainly meant send.
    if (fs.existsSync(path.resolve(first))) {
      throw new CliError(
        `"${first}" looks like a path. To send it, run: bhejo send "${first}"\n` +
          'To start the receiver, run: bhejo receive',
      );
    }
  }

  switch (command) {
    case 'receive':
      return cmdReceive(opts);
    case 'send':
      return cmdSend(opts);
    case 'discover':
      return cmdDiscover(opts);
    case 'info':
      return cmdInfo(opts);
    case 'cert':
      return cmdCert(opts);
    default:
      printHelp();
      return 0;
  }
}

// --------------------------------------------------------------- receive

async function cmdReceive(opts) {
  const identity = loadIdentity({ alias: opts.alias, ephemeral: Boolean(opts.ephemeral) });
  const dir = path.resolve(opts.dir ?? process.cwd());
  const preferredPort = Number(opts.port ?? DEFAULT_PORT);
  const discoveryPort = Number(opts.discoveryPort ?? DEFAULT_PORT);

  let pin = opts.pin === undefined ? null : String(opts.pin);
  if (pin === 'true') pin = null;
  if (pin === null && opts.autoAccept && !opts.noPin) {
    pin = String(Math.floor(1000 + Math.random() * 9000));
  }

  const trust = new TrustStore(identity.home);

  /** Terminal fallback when the browser UI is off or unavailable. */
  const promptForTransfer = async (request) => {
    const known = trust.get(request.peer.fingerprint);
    say('');
    say(bold(Receiver.describeIncoming(request)));
    say(
      known
        ? `   ${dim(`known device (first seen ${known.firstSeen.slice(0, 10)})`)}`
        : `   ${yellow('new device')} ${dim(`fingerprint ${formatFingerprint(request.peer.fingerprint).slice(0, 23)}${G.dots}`)}`,
    );

    const answer = (await ask(`   Accept? [y/N] `)).toLowerCase();
    if (answer.startsWith('y')) {
      if (!known) trust.remember(request.peer.fingerprint, { alias: request.peer.alias, address: request.peer.address });
      return { accepted: true };
    }
    return { accepted: false, reason: 'declined on the receiving device' };
  };

  const receiver = new Receiver({
    identity,
    dir,
    port: preferredPort,
    pin,
    autoAccept: Boolean(opts.autoAccept),
    // When auto-accepting, leave this undefined so Receiver's own flag applies.
    onIncoming: opts.autoAccept ? undefined : promptForTransfer,
  });

  receiver.on('received', (file) => {
    const elapsed = file.elapsedMs ? humanDuration(file.elapsedMs) : '';
    say(
      `  ${green(G.ok)} ${file.relative}  ${dim(`${humanBytes(file.bytes)} ${elapsed}`.trim())}  ${dim(`sha256 ${file.sha256.slice(0, 12)}${G.dots}`)}`,
    );
  });
  receiver.on('rejected', ({ alias, reason }) => say(`  ${red(G.bad)} declined ${alias}: ${reason}`));
  receiver.on('cancelled', ({ peer }) => say(`  ${dim(`transfer from ${peer.alias} cancelled`)}`));
  receiver.on('error', (err) => warn(`transfer error: ${err.message}`));

  const started = await receiver.start();

  say('');
  say(`${bold(`Bhejo ${pkg.version}`)} ${dim(`${G.dash} receiving`)}`);
  say(`  name         ${identity.alias}${identity.ephemeral ? dim(' (ephemeral identity)') : ''}`);
  say(`  address      ${primaryIpv4()}:${started.port}`);
  say(`  fingerprint  ${formatFingerprint(identity.fingerprint)}`);
  say(`  saving to    ${started.dir}`);
  if (pin) say(`  PIN          ${bold(pin)} ${dim('(senders must enter this)')}`);
  if (opts.autoAccept) say(`  ${yellow('auto-accept is on')}${pin ? '' : ` ${red('and no PIN is set')}`}`);
  say('');

  let discovery = null;
  if (!opts.noDiscovery) {
    discovery = new Discovery({
      alias: identity.alias,
      deviceType: identity.deviceType,
      httpPort: started.port,
      fingerprint: identity.fingerprint,
      port: discoveryPort,
      log: (msg) => warn(msg),
    });
    discovery.on('peer', (peer) =>
      say(`  ${green('+')} ${peer.alias} ${dim(`at ${peer.address}:${peer.port}`)}`),
    );
    discovery.on('lost', (peer) => say(`  ${dim(`- ${peer.alias} left`)}`));
    discovery.on('error', (err) => warn(`discovery: ${err.message}`));

    try {
      await discovery.start();
      say(dim(`  listening for devices on UDP ${discoveryPort}${G.dots}`));
    } catch (err) {
      warn(`discovery unavailable (${err.message}); senders can still use --to <ip>`);
      discovery = null;
    }
    say('');
  }

  let ui = null;
  if (!opts.noUi) {
    ui = new UiServer({
      identity,
      receiver,
      discovery,
      trust,
      port: Number(opts.uiPort ?? DEFAULT_PORT + 1),
      log: (msg) => warn(msg),
    });

    try {
      const startedUi = await ui.start();
      say(`  browser UI   ${bold(startedUi.url)}`);

      if (!opts.autoAccept) {
        receiver.onIncoming = (request) => {
          say('');
          say(bold(Receiver.describeIncoming(request)));
          say(dim(`   decide in the browser: ${startedUi.url}`));
          return ui.decide(request);
        };
      }
      say('');
    } catch (err) {
      warn(`browser UI unavailable (${err.message}); using terminal prompts`);
      ui = null;
    }
  }

  say(dim('  waiting. press Ctrl+C to stop.'));

  await new Promise((resolve) => {
    const stop = async () => {
      say('');
      say(dim(`stopping${G.dots}`));
      process.removeListener('SIGINT', stop);
      process.removeListener('SIGTERM', stop);
      await discovery?.stop().catch(() => {});
      await ui?.stop().catch(() => {});
      await receiver.stop().catch(() => {});
      closePrompts();
      resolve();
    };
    process.once('SIGINT', stop);
    process.once('SIGTERM', stop);
    if (!process.stdin.isTTY) {
      // Launched from a script or service: keep running until killed.
      process.stdin.resume();
    }
  });

  return 0;
}

// ------------------------------------------------------------------ send

async function cmdSend(opts) {
  const inputs = opts._;
  if (inputs.length === 0) throw new CliError('nothing to send. Usage: bhejo send <file-or-folder>... --to <device>');

  const files = collectFiles(inputs);
  if (files.length === 0) throw new CliError('nothing to send: the given paths contain no files');

  const identity = loadIdentity({ alias: opts.alias });
  const trust = new TrustStore(identity.home);

  const target = await resolveTarget(opts, identity, trust);
  const totalBytes = files.reduce((n, f) => n + f.size, 0);

  say('');
  say(
    `Sending ${bold(String(files.length))} file${files.length === 1 ? '' : 's'} ${dim(`(${humanBytes(totalBytes)})`)} to ${bold(target.alias)} ${dim(`${target.host}:${target.port}`)}`,
  );

  const progress = makeProgress();
  const startedAt = Date.now();

  // The receiver asks its user before any bytes move, so the first exchange can
  // legitimately sit still for a while. Say so instead of looking hung.
  let notice = setTimeout(() => {
    say(dim(`  waiting for ${target.alias} to accept${G.dots}`));
  }, 1200);
  notice.unref?.();
  const clearNotice = () => {
    if (notice) {
      clearTimeout(notice);
      notice = null;
    }
  };

  let result;
  try {
    result = await sendFiles({
      host: target.host,
      port: target.port,
      expectedFingerprint: target.fingerprint,
      pin: opts.pin && opts.pin !== true ? String(opts.pin) : null,
      files,
      senderAlias: identity.alias,
      senderFingerprint: identity.fingerprint,
      onProgress: (event) => {
        clearNotice();
        progress.onProgress(event);
      },
      verify: !opts.noVerify,
    });
    clearNotice();
  } catch (err) {
    clearNotice();
    progress.clear();
    if (err instanceof FingerprintMismatchError) {
      throw new CliError(
        `${err.message}\nIf the device legitimately changed, forget it first: bhejo forget ${err.actual.slice(0, 16)}`,
      );
    }
    throw err;
  }

  progress.clear();
  say('');

  let failed = 0;
  for (const entry of result.results) {
    if (entry.ok) {
      say(
        `  ${green(G.ok)} ${entry.file.fileName}  ${dim(`${humanBytes(entry.bytes)}  sha256 ${entry.sha256.slice(0, 12)}${G.dots} verified`)}`,
      );
    } else {
      failed++;
      say(`  ${red(G.bad)} ${entry.file.fileName}  ${red(entry.error)}`);
    }
  }

  const elapsed = Date.now() - startedAt;
  const sentBytes = result.results.filter((r) => r.ok).reduce((n, r) => n + (r.bytes ?? 0), 0);
  say('');
  say(
    failed === 0
      ? green(`sent ${result.results.length} file${result.results.length === 1 ? '' : 's'} (${humanBytes(sentBytes)}) in ${humanDuration(elapsed)}`)
      : red(`${failed} of ${result.results.length} files failed`),
  );

  return failed === 0 ? 0 : 1;
}

/**
 * Work out where to send: an alias resolved through discovery, or an address
 * given directly. Returns { host, port, fingerprint, alias }.
 */
async function resolveTarget(opts, identity, trust) {
  const to = typeof opts.to === 'string' ? opts.to : null;

  if (!to) {
    const peers = await discoverFor({ identity, httpPort: 0, ms: Number(opts.wait ?? 4000) });
    if (peers.length === 0) {
      throw new CliError(
        'no devices found. Check that both devices are on the same Wi-Fi, or send directly: bhejo send <file> --to 192.168.1.20',
      );
    }
    if (peers.length > 1) {
      const list = peers.map((p) => `   ${p.alias}  ${dim(`${p.address}:${p.port}`)}`).join('\n');
      throw new CliError(`several devices found, choose one with --to:\n${list}`);
    }
    const [peer] = peers;
    return settleTrust({
      host: peer.address,
      port: peer.port,
      fingerprint: peer.fingerprint,
      alias: peer.alias,
      opts,
      trust,
    });
  }

  const direct = parseAddress(to);
  if (!direct) {
    // An alias: ask discovery who that is.
    const peers = await discoverFor({ identity, httpPort: 0, ms: Number(opts.wait ?? 6000) });
    const needle = to.toLowerCase();
    const matches = peers.filter((p) => p.alias.toLowerCase() === needle);
    const fuzzy = matches.length ? matches : peers.filter((p) => p.alias.toLowerCase().includes(needle));

    if (fuzzy.length === 0) {
      throw new CliError(
        `no nearby device named "${to}". Found: ${peers.map((p) => p.alias).join(', ') || 'nothing'}`,
      );
    }
    if (fuzzy.length > 1) {
      const list = fuzzy.map((p) => `   ${p.alias}  ${dim(`${p.address}:${p.port}`)}`).join('\n');
      throw new CliError(`"${to}" matches several devices:\n${list}`);
    }
    const [peer] = fuzzy;
    return settleTrust({
      host: peer.address,
      port: peer.port,
      fingerprint: peer.fingerprint,
      alias: peer.alias,
      opts,
      trust,
    });
  }

  const port = direct.port ?? Number(opts.port ?? DEFAULT_PORT);
  const expected = typeof opts.fingerprint === 'string' ? opts.fingerprint.replace(/:/g, '').toLowerCase() : null;

  let info;
  try {
    info = await probe({ host: direct.host, port, expectedFingerprint: expected });
  } catch (err) {
    if (err instanceof FingerprintMismatchError) throw err;
    throw new CliError(`cannot reach ${direct.host}:${port} - ${err.message}`);
  }

  return settleTrust({
    host: direct.host,
    port,
    fingerprint: info.fingerprint,
    alias: info.alias,
    opts,
    trust,
  });
}

/**
 * Decide whether this fingerprint may receive our files.
 *
 * Applied to discovery-resolved targets too, not just raw addresses: an
 * announcement carries a self-signed fingerprint, so anyone on the LAN can
 * claim an alias. The prompt is what turns that into a decision the user made.
 */
async function settleTrust({ host, port, fingerprint, alias, opts, trust }) {
  const known = trust.get(fingerprint);

  if (known) {
    if (known.alias !== alias) {
      warn(`device at ${host} was known as "${known.alias}" and now calls itself "${alias}"`);
    }
    trust.touch(fingerprint, host);
    return { host, port, fingerprint, alias };
  }

  // A different device already holds this alias: that is exactly the case a
  // user needs to see.
  const shadowed = trust.list().filter((peer) => peer.alias === alias);
  if (!opts.trust && !opts.yes && !opts.fingerprint) {
    say('');
    say(bold(`First contact with "${alias}" at ${host}:${port}`));
    say(`  certificate fingerprint  ${formatFingerprint(fingerprint)}`);
    if (shadowed.length) {
      say(yellow(`  note: "${alias}" was previously a different device`));
      for (const peer of shadowed) {
        say(dim(`        ${formatFingerprint(peer.fingerprint)}  last seen ${peer.lastSeen.slice(0, 10)}`));
      }
    }
    say(dim('  Compare this with the fingerprint shown on the other device.'));
    const answer = (await ask('  Trust this device? [y/N] ')).toLowerCase();
    if (!answer.startsWith('y')) {
      closePrompts();
      throw new CliError('aborted: device not trusted');
    }
  }

  trust.remember(fingerprint, { alias, address: host });
  return { host, port, fingerprint, alias };
}

/** "192.168.1.20", "192.168.1.20:53317", or "host.local" -> {host, port}. */
function parseAddress(value) {
  const match = /^([A-Za-z0-9._-]+)(?::(\d{1,5}))?$/.exec(value);
  if (!match) return null;
  const host = match[1];
  const port = match[2] ? Number(match[2]) : null;
  const looksLikeHost =
    port !== null ||
    /^\d{1,3}(\.\d{1,3}){3}$/.test(host) ||
    host.endsWith('.local') ||
    host === 'localhost';
  if (!looksLikeHost) return null;
  if (port !== null && (port < 1 || port > 65535)) return null;
  return { host, port };
}

function makeProgress() {
  const tty = Boolean(process.stdout.isTTY);
  let lastDraw = 0;
  let fileStartedAt = Date.now();
  let current = '';

  return {
    onProgress({ fileName, sent, total, fileIndex, fileCount }) {
      if (!tty) return;
      if (fileName !== current) {
        current = fileName;
        fileStartedAt = Date.now();
        process.stdout.write('\r\x1b[2K');
      }
      const now = Date.now();
      if (now - lastDraw < 90 && sent < total) return;
      lastDraw = now;

      const pct = total === 0 ? 100 : Math.floor((sent / total) * 100);
      const rate = sent / Math.max(0.05, (now - fileStartedAt) / 1000);
      const line =
        `  ${dim(`[${fileIndex + 1}/${fileCount}]`)} ${truncate(fileName, 34)} ` +
        `${String(pct).padStart(3)}% ${dim(`${humanBytes(rate)}/s`)}`;
      process.stdout.write(`\r\x1b[2K${line}`);

      if (sent >= total) process.stdout.write('\r\x1b[2K');
    },
    clear() {
      if (tty) process.stdout.write('\r\x1b[2K');
    },
  };
}

function truncate(text, max) {
  if (text.length <= max) return text.padEnd(max);
  return `${text.slice(0, max - 1)}${G.dots}`;
}

// -------------------------------------------------------------- discover

async function cmdDiscover(opts) {
  const identity = loadIdentity({ alias: opts.alias });
  const ms = Number(opts.wait ?? 5000);
  const port = Number(opts.discoveryPort ?? DEFAULT_PORT);

  const discovery = new Discovery({
    alias: identity.alias,
    deviceType: identity.deviceType,
    httpPort: 0, // a pure listener: do not advertise a server that is not running
    fingerprint: identity.fingerprint,
    port,
    log: (msg) => warn(msg),
  });

  if (!opts.json) say(dim(`Searching for ${humanDuration(ms)} on UDP ${port}${G.dots}`));

  const live = new Map();
  discovery.on('peer', (peer) => {
    live.set(peer.fingerprint, peer);
    if (!opts.json) say(`  ${green('+')} ${peer.alias}  ${dim(`${peer.address}:${peer.port}`)}`);
  });
  discovery.on('lost', (peer) => {
    live.delete(peer.fingerprint);
    if (!opts.json) say(`  ${dim(`- ${peer.alias}`)}`);
  });

  await discovery.start();
  await new Promise((resolve) => setTimeout(resolve, ms));
  const peers = discovery.peers();
  await discovery.stop();

  if (opts.json) {
    say(JSON.stringify(peers, null, 2));
    return 0;
  }

  say('');
  if (peers.length === 0) {
    say('No devices found.');
    say(dim('  Tips: same Wi-Fi network? multicast allowed by the router? try --to <ip> instead.'));
    return 0;
  }

  say(`${bold(String(peers.length))} device${peers.length === 1 ? '' : 's'} found`);
  for (const peer of peers) {
    say(`  ${peer.alias}`);
    say(`    ${dim(`${peer.address}:${peer.port}  ${peer.deviceType}`)}`);
  }
  return 0;
}

// ------------------------------------------------------------------ info

async function cmdInfo(opts) {
  const identity = loadIdentity({ alias: opts.alias });
  const trust = new TrustStore(identity.home);

  if (opts.json) {
    say(
      JSON.stringify(
        {
          alias: identity.alias,
          platform: process.platform,
          deviceType: identity.deviceType,
          fingerprint: identity.fingerprint,
          stateDir: bhejoHome(),
          addresses: allIpv4(),
          knownPeers: trust.list(),
        },
        null,
        2,
      ),
    );
    return 0;
  }

  say('');
  say(`  name         ${identity.alias}`);
  say(`  platform     ${process.platform} (${identity.deviceType})`);
  say(`  fingerprint  ${formatFingerprint(identity.fingerprint)}`);
  say(`  addresses    ${allIpv4().join(', ') || 'none'}`);
  say(`  state dir    ${bhejoHome()}`);
  say(`  known peers  ${trust.size}`);
  for (const peer of trust.list()) {
    say(`    ${peer.alias} ${dim(`${formatFingerprint(peer.fingerprint).slice(0, 23)}${G.dots}  ${peer.address ?? ''}`)}`);
  }
  say('');
  return 0;
}

// ------------------------------------------------------------------ cert

async function cmdCert(opts) {
  if (opts.self || opts._.length === 0) {
    const identity = loadIdentity({ alias: opts.alias });
    say(formatFingerprint(identity.fingerprint));
    return 0;
  }

  const file = opts._[0];
  if (!fs.existsSync(file)) throw new CliError(`no such file: ${file}`);
  try {
    say(formatFingerprint(fingerprintOfPem(fs.readFileSync(file, 'utf8'))));
  } catch (err) {
    throw new CliError(`could not read a certificate from ${file}: ${err.message}`);
  }
  return 0;
}

// ------------------------------------------------------------------ help

function printHelp(command) {
  const version = `Bhejo ${pkg.version} ${G.dash} peer-to-peer file sharing on your local network.`;

  if (command === 'send') {
    say(`${version}

Usage:
  bhejo send <file-or-folder>... [--to <device>] [options]

Options:
  --to <alias|ip>      Target device name (from discovery) or address, e.g. 192.168.1.20
  --port <n>           Port when sending to a raw address (default ${DEFAULT_PORT})
  --pin <1234>         PIN shown on the receiving device
  --wait <ms>          How long to wait for discovery (default 4000)
  --fingerprint <hex>  Pin the target certificate, skipping the trust prompt
  --trust              Send without the first-contact prompt
  --no-verify          Skip the SHA-256 comparison after upload
`);
    return;
  }

  if (command === 'receive') {
    say(`${version}

Usage:
  bhejo receive [--dir <path>] [--pin <1234>] [--auto-accept]

Options:
  --dir <path>         Where to save incoming files (default: current directory)
  --pin <1234>         Require senders to know this PIN
  --auto-accept        Accept every transfer without asking (implies a PIN unless --no-pin)
  --no-pin             Do not require a PIN even with --auto-accept
  --no-discovery       Do not listen for announcements
  --no-ui              Do not start the browser UI; use terminal prompts
  --ui-port <n>        Port for the browser UI (default 53318, localhost only)
  --port <n>           Preferred HTTPS port (default ${DEFAULT_PORT}, falls back if busy)
  --alias <name>       Device name shown to others
  --ephemeral          Use a throwaway identity and fingerprint
`);
    return;
  }

  say(`${version}

Usage:
  bhejo                       Receive files (same as: bhejo receive)
  bhejo send <paths...>       Send files or folders
  bhejo discover              List devices on this network
  bhejo info                  Show this device's identity and known peers
  bhejo cert [file]           Print a certificate fingerprint

Common options:
  --alias <name>       Device name shown to other devices
  --json               Machine-readable output (discover, info)
  --help, -h           This help
  --version, -v        Version

Examples:
  bhejo                                    # receive into the current folder
  bhejo receive --dir ~/Downloads          # receive into Downloads
  bhejo send ./report.pdf --to Kitchen-PC
  bhejo send ./photos --to 192.168.1.20 --pin 4821
  bhejo discover --wait 8000
`);
}
