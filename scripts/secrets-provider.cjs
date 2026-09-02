#!/usr/bin/env node
/**
 * secrets-provider.cjs — Cross-platform secret provider for OpenClaw
 * ==================================================================
 * Version 1.0.1 · MIT License · zero npm dependencies
 *
 * Stores your OpenClaw API keys in the operating system's built-in
 * encrypted credential store instead of plaintext config files:
 *
 *   macOS   → Keychain                  (/usr/bin/security, built in)
 *   Linux   → Secret Service / keyring  (secret-tool from libsecret)
 *   Windows → Credential Vault          (PowerShell PasswordVault, built in)
 *
 * NEW TO THIS? Run the guided setup:   node secrets-provider.cjs setup
 *
 * COMMANDS
 *   setup            Guided, interactive setup (recommended for everyone).
 *                    Checks your machine, stores your keys with hidden
 *                    input, and prints the exact openclaw.json config.
 *   doctor           Check this machine can store/read/delete secrets.
 *   store <name>     Save a secret. Value is read from stdin, e.g.:
 *                      printf '%s' 'sk-xxxx' | node secrets-provider.cjs store my-key
 *   get <name>       Print a secret (for testing).
 *   delete <name>    Remove a secret.
 *   help             Show this list.
 *
 * HOW OPENCLAW USES IT (exec provider protocol v1)
 *   With no command, the script reads one JSON request from stdin:
 *     {"protocolVersion":1,"provider":"key-vault","ids":["anthropic-api-key"]}
 *   and answers on stdout:
 *     {"protocolVersion":1,"values":{"anthropic-api-key":"sk-ant-..."}}
 *   Failures exit non-zero with a plain-language message on stderr.
 *
 * SECURITY DESIGN (for reviewers — see also the README)
 *   1. Secret NAMES and the NAMESPACE are allowlisted to
 *      [A-Za-z0-9._-]{1,128}. They are the only externally influenced
 *      strings that reach an OS command, and the allowlist makes shell,
 *      argument, and PowerShell injection impossible by construction.
 *   2. Secret VALUES never appear on a command line on Linux or Windows:
 *      they travel via stdin/stdout of the credential tool only.
 *      On macOS, `security add-generic-password` requires the value as
 *      an argument. macOS only lets a process read the argv of processes
 *      with the SAME uid (or root) — and any same-uid process could ask
 *      Keychain for the entry anyway once access is granted — so this
 *      adds no practical exposure on a single-user agent machine. It is
 *      still the one platform-imposed compromise in this script, and we
 *      would rather document it than hide it.
 *   3. All macOS/Linux invocations use execFile with argument arrays —
 *      no shell is ever involved. On Windows, PowerShell is invoked with
 *      -NoProfile -NonInteractive and only allowlisted identifiers are
 *      interpolated into the command text.
 *   4. No dependencies means no supply chain to compromise and nothing
 *      to keep patched. Node's standard library plus the OS tool, only.
 *   5. Keep this file chmod 700 (macOS/Linux), owned by the user OpenClaw
 *      runs as. OpenClaw refuses provider scripts with loose permissions;
 *      that check protects you.
 *
 * WHAT THIS DOES AND DOESN'T PROTECT
 *   Protects keys at rest: file theft, plaintext backups, dotfile repos,
 *   an agent tricked into printing its config. Does NOT protect against
 *   malware already running as your user, or bugs in OpenClaw itself —
 *   for those, use dedicated spend-capped keys per service and rotate.
 */

'use strict';

const { execFile } = require('node:child_process');
const { promisify } = require('node:util');
const path = require('node:path');
const run = promisify(execFile);

const VERSION = '1.0.1';

/* Groups all entries this script owns inside the credential store.
 * Override with KEY_VAULT_NAMESPACE to run several isolated agents on
 * one machine (e.g. 'openclaw-prod', 'openclaw-test'). */
const NAMESPACE = process.env.KEY_VAULT_NAMESPACE || 'openclaw';

/* One allowlist governs every identifier that can reach an OS command. */
const NAME_RE = /^[A-Za-z0-9._-]{1,128}$/;
const MAX_VALUE_BYTES = 64 * 1024; // sanity cap; API keys are tiny

const PLATFORM = process.platform; // 'darwin' | 'linux' | 'win32'

function fail(msg, code = 1) {
  process.stderr.write(`secrets-provider: ${msg}\n`);
  process.exit(code);
}

/* The namespace is user-controlled via an environment variable, so it
 * gets the same validation as names — otherwise a hostile environment
 * could inject into the Windows PowerShell command text. */
if (!NAME_RE.test(NAMESPACE)) {
  fail(`invalid KEY_VAULT_NAMESPACE "${NAMESPACE}". ` +
       `Use only letters, digits, dot, dash, underscore (max 128 chars).`);
}

function assertValidName(name) {
  if (!NAME_RE.test(name || '')) {
    fail(`invalid secret name "${name ?? ''}". Use only letters, digits, ` +
         `dot, dash, underscore (max 128 chars), e.g. "anthropic-api-key".`);
  }
}

/* Read all of stdin (protocol mode and piped `store`). */
async function readStdin() {
  let data = '';
  process.stdin.setEncoding('utf8');
  for await (const chunk of process.stdin) data += chunk;
  return data;
}

/* ────────────────────────────────────────────────────────────────────
 * PLATFORM BACKENDS — each implements get(name), set(name, value),
 * del(name). get() throws on a missing entry; callers convert that
 * into an error message that names the secret and shows the fix.
 * ──────────────────────────────────────────────────────────────────── */

const macos = {
  tool: '/usr/bin/security',
  label: 'macOS Keychain',
  async get(name) {
    const { stdout } = await run(this.tool,
      ['find-generic-password', '-a', NAMESPACE, '-s', name, '-w']);
    return stdout.replace(/\n$/, '');
  },
  async set(name, value) {
    /* -U = upsert. See SECURITY DESIGN §2 for why the value is an
     * argument here and why that's acceptable on macOS specifically. */
    await run(this.tool,
      ['add-generic-password', '-U', '-a', NAMESPACE, '-s', name, '-w', value]);
  },
  async del(name) {
    await run(this.tool,
      ['delete-generic-password', '-a', NAMESPACE, '-s', name]);
  },
  doctorHint:
    'Keychain ships with macOS — nothing to install.\n' +
    'The first real read pops a permission dialog: choose "Always Allow"\n' +
    'on a dedicated agent machine so restarts are unattended.',
};

/* Resolve secret-tool to a known absolute path. Refusing bare-name
 * PATH lookup means a planted fake binary earlier in PATH can never
 * intercept secret values (defense in depth — see README attack notes). */
function findSecretTool() {
  const fs = require('node:fs');
  for (const p of ['/usr/bin/secret-tool', '/bin/secret-tool', '/usr/local/bin/secret-tool']) {
    try { fs.accessSync(p, fs.constants.X_OK); return p; } catch { /* next */ }
  }
  return null; // reported by doctor / first use with an install hint
}

const linux = {
  tool: findSecretTool() || '/usr/bin/secret-tool', // absolute path only, never PATH
  label: 'Linux Secret Service (GNOME Keyring / KWallet)',
  async get(name) {
    const { stdout } = await run(this.tool,
      ['lookup', 'service', name, 'account', NAMESPACE]);
    return stdout.replace(/\n$/, '');
  },
  async set(name, value) {
    /* secret-tool reads the value from stdin — never a command line. */
    await new Promise((resolve, reject) => {
      const child = execFile(this.tool,
        ['store', `--label=${NAMESPACE} ${name}`,
         'service', name, 'account', NAMESPACE],
        (err) => (err ? reject(err) : resolve()));
      child.stdin.end(value);
    });
  },
  async del(name) {
    await run(this.tool, ['clear', 'service', name, 'account', NAMESPACE]);
  },
  doctorHint:
    'Needs secret-tool:  sudo apt install libsecret-tools   (Debian/Ubuntu)\n' +
    '                    sudo dnf install libsecret          (Fedora)\n' +
    'and an UNLOCKED keyring — automatic on desktop Linux after login.\n' +
    'Headless server/VPS? Read the "Headless Linux" section of the setup\n' +
    'guide before relying on this; keyrings need extra care there.',
};

const windows = {
  /* Absolute path — never resolved via PATH or the current directory,
   * so a planted powershell.exe can't intercept vault traffic. */
  tool: (process.env.SystemRoot || 'C:\\Windows') +
        '\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
  label: 'Windows Credential Vault',
  /* Uses the PasswordVault WinRT API — built into Windows 10/11, no
   * modules to install. Entries are encrypted per-user and visible in
   * Control Panel → Credential Manager → Web Credentials.
   * Only NAMESPACE and validated names are interpolated into the
   * PowerShell text (see SECURITY DESIGN §1/§3); secret values travel
   * exclusively via the child process's stdin/stdout. */
  ps(command) {
    return run(this.tool,
      ['-NoProfile', '-NonInteractive', '-Command', command]);
  },
  prelude:
    '[void][Windows.Security.Credentials.PasswordVault,' +
    'Windows.Security.Credentials,ContentType=WindowsRuntime];' +
    '$v=New-Object Windows.Security.Credentials.PasswordVault;',
  async get(name) {
    const { stdout } = await this.ps(
      this.prelude +
      `$c=$v.Retrieve('${NAMESPACE}','${name}');` +
      `$c.RetrievePassword();[Console]::Out.Write($c.Password)`);
    return stdout; // Console.Out.Write adds no newline
  },
  async set(name, value) {
    /* Value is read inside PowerShell from stdin; remove-then-add makes
     * store behave as an upsert, matching the other platforms. */
    await new Promise((resolve, reject) => {
      const child = execFile(this.tool,
        ['-NoProfile', '-NonInteractive', '-Command',
          this.prelude +
          `$val=[Console]::In.ReadToEnd();` +
          `try{$old=$v.Retrieve('${NAMESPACE}','${name}');$v.Remove($old)}catch{};` +
          `$v.Add((New-Object Windows.Security.Credentials.PasswordCredential(` +
          `'${NAMESPACE}','${name}',$val)))`],
        (err) => (err ? reject(err) : resolve()));
      child.stdin.end(value);
    });
  },
  async del(name) {
    await this.ps(this.prelude +
      `$c=$v.Retrieve('${NAMESPACE}','${name}');$v.Remove($c)`);
  },
  doctorHint:
    'Credential Vault ships with Windows 10/11 — nothing to install.\n' +
    'Running OpenClaw inside WSL? Then you are on LINUX as far as this\n' +
    'script is concerned: follow the Linux instructions inside WSL.\n' +
    'Note: keys are ASCII-safe by nature; avoid non-ASCII secret values\n' +
    'on Windows, where console encoding can vary.',
};

const BACKENDS = { darwin: macos, linux, win32: windows };
const backend = BACKENDS[PLATFORM];
if (!backend) fail(`unsupported platform "${PLATFORM}"`);

function scriptPath() { return path.resolve(process.argv[1] || 'secrets-provider.cjs'); }
function scriptName() { return path.basename(scriptPath()); }

async function getSecret(name) {
  assertValidName(name);
  try {
    const value = await backend.get(name);
    if (!value) throw new Error('entry exists but is empty');
    return value;
  } catch (err) {
    const detail = (err.stderr || err.message || '').toString().trim();
    throw new Error(
      `could not read secret "${name}" (namespace "${NAMESPACE}"): ${detail}\n` +
      `  Store it with:  printf '%s' '<value>' | node ${scriptName()} store ${name}\n` +
      `  Or run the guided setup:  node ${scriptName()} setup`);
  }
}

function checkValue(value) {
  if (!value) fail('refusing to store an empty value.');
  if (Buffer.byteLength(value) > MAX_VALUE_BYTES) {
    fail(`value exceeds ${MAX_VALUE_BYTES} bytes — that is not an API key.`);
  }
  /* Catch the classic novice mistake of storing the placeholder text. */
  const suspicious = /^<.*>$|your[-_ ]?(api[-_ ]?)?key|xxxx|paste/i;
  if (suspicious.test(value)) {
    process.stderr.write(
      `WARNING: the value you stored looks like placeholder text ` +
      `("${value.slice(0, 24)}..."). If that was a mistake, run store again ` +
      `with your real key — store overwrites.\n`);
  }
}

/* ── Hidden interactive input (for `setup`) ──────────────────────────
 * Raw-mode reader: echoes nothing while a key is typed/pasted. Uses
 * only public Node APIs (no readline internals). Handles Enter,
 * Backspace, Ctrl+C, and multi-character paste events. */
function promptHidden(question) {
  return new Promise((resolve, reject) => {
    process.stdout.write(question);
    const stdin = process.stdin;
    stdin.setRawMode(true);
    stdin.resume();
    stdin.setEncoding('utf8');
    let buf = '';
    const onData = (chunk) => {
      for (const ch of chunk) {
        if (ch === '\u0003') {                 // Ctrl+C
          cleanup(); process.stdout.write('\n'); process.exit(130);
        } else if (ch === '\r' || ch === '\n') { // Enter
          cleanup(); process.stdout.write('\n'); resolve(buf); return;
        } else if (ch === '\u007f' || ch === '\b') { // Backspace
          buf = buf.slice(0, -1);
        } else if (ch >= ' ') {                // printable chars only
          buf += ch;
        }
      }
    };
    const cleanup = () => {
      stdin.setRawMode(false);
      stdin.pause();
      stdin.removeListener('data', onData);
    };
    stdin.on('data', onData);
    stdin.on('error', (e) => { cleanup(); reject(e); });
  });
}

/* Visible-input prompt for non-secret answers (names, yes/no). */
function promptVisible(question) {
  return new Promise((resolve) => {
    const rl = require('node:readline')
      .createInterface({ input: process.stdin, output: process.stdout });
    rl.question(question, (ans) => { rl.close(); resolve(ans.trim()); });
  });
}

/* ── doctor: environment self-check ─────────────────────────────────── */
async function doctor({ quiet = false } = {}) {
  if (!quiet) {
    process.stdout.write(
      `secrets-provider ${VERSION}\n` +
      `platform : ${PLATFORM} (${backend.label})\n` +
      `namespace: ${NAMESPACE}\n\n${backend.doctorHint}\n\n`);
  }
  const probe = `__doctor_probe_${Date.now()}`;
  let ok = false;
  try {
    await backend.set(probe, 'ok');
    ok = (await backend.get(probe)) === 'ok';
  } catch (err) {
    process.stdout.write(
      `RESULT: FAIL — ${((err.stderr || err.message) + '').trim()}\n` +
      `See the hint above and the setup guide for fixes.\n`);
    return false;
  } finally {
    /* Never leave the probe entry behind, even on a failed read. */
    try { await backend.del(probe); } catch { /* best effort */ }
  }
  process.stdout.write(ok
    ? 'RESULT: PASS — stored, read back, and deleted a test secret.\n'
    : 'RESULT: FAIL — read back a different value than stored.\n');
  return ok;
}

/* ── setup: guided wizard for non-developers ────────────────────────── */
async function setup() {
  if (!process.stdin.isTTY) {
    fail('setup is interactive — run it directly in a terminal.\n' +
         'For scripted use, pipe values into the "store" command instead.');
  }
  process.stdout.write(
    `\n` + BANNER +
    `\n guided setup\n` +
    ` ────────────
` +
    `This stores your API keys in your computer's encrypted credential\n` +
    `store (${backend.label}) so they never sit in a plaintext file.\n\n` +
    `Step 1/3 — checking this machine...\n\n`);

  if (!(await doctor({ quiet: false }))) {
    process.stdout.write('\nFix the issue above, then run setup again.\n');
    process.exit(1);
  }

  process.stdout.write(
    `\nStep 2/3 — store your keys.\n` +
    `Name each key in lowercase-with-dashes (e.g. anthropic-api-key,\n` +
    `apify-token, dataforseo-login). Your typing/paste will be INVISIBLE\n` +
    `when entering the key value — that's intentional. Press Enter on an\n` +
    `empty name when you're done.\n\n`);

  const stored = [];
  for (;;) {
    const name = await promptVisible('Secret name (empty to finish): ');
    if (!name) break;
    if (!NAME_RE.test(name)) {
      process.stdout.write('  Only letters, digits, dot, dash, underscore. Try again.\n');
      continue;
    }
    const value = (await promptHidden(`Value for "${name}" (hidden): `))
      .replace(/\r?\n$/, '');
    if (!value) { process.stdout.write('  Empty value — skipped.\n'); continue; }
    checkValue(value);
    await backend.set(name, value);
    const back = await backend.get(name);
    process.stdout.write(back === value
      ? `  ✓ stored and verified "${name}" (${value.length} chars)\n`
      : `  ✗ verification failed for "${name}" — try again.\n`);
    if (back === value) stored.push(name);
  }

  process.stdout.write(
    `\nStep 3/3 — connect OpenClaw.\n` +
    `Add this to your openclaw.json (inside the top-level { }):\n\n` +
    `  "secrets": {\n` +
    `    "providers": {\n` +
    `      "key-vault": {\n` +
    `        "source": "exec",\n` +
    `        "command": ${JSON.stringify(scriptPath())},\n` +
    `        "timeoutMs": 5000\n` +
    `      }\n` +
    `    }\n` +
    `  }\n\n` +
    (stored.length
      ? `Then reference your secrets by name where keys used to be:\n` +
        stored.map((n) => `  - ${n}`).join('\n') + '\n\n'
      : '') +
    `Restart OpenClaw, confirm everything works, and ONLY THEN delete\n` +
    `the old plaintext keys from your config. Done.\n`);
}

/* ── banner ─────────────────────────────────────────────────────────── */
// Printed only by `help` and `setup`. Never on `get` or the provider
// protocol path — those write to stdout and must stay machine-readable.
const BANNER =
  ' \u2588\u2588\u2588\u2588\u2588\u2588\u2588 \u2588\u2588\u2588\u2588\u2588\u2588\u2588 \u2588\u2588\u2588\u2588\u2588\u2588\u2588 \u2588\u2588   \u2588\u2588 \u2588\u2588\u2588\u2588\u2588\u2588\u2588 \u2588\u2588      \u2588\u2588\u2588\u2588\u2588\u2588\u2588 \u2588\u2588   \u2588\u2588\n' +
  ' \u2588\u2588   \u2588\u2588 \u2588\u2588   \u2588\u2588 \u2588\u2588      \u2588\u2588\u2588  \u2588\u2588 \u2588\u2588      \u2588\u2588      \u2588\u2588   \u2588\u2588 \u2588\u2588   \u2588\u2588\n' +
  ' \u2588\u2588   \u2588\u2588 \u2588\u2588\u2588\u2588\u2588\u2588\u2588 \u2588\u2588\u2588\u2588\u2588   \u2588\u2588 \u2588 \u2588\u2588 \u2588\u2588      \u2588\u2588      \u2588\u2588\u2588\u2588\u2588\u2588\u2588 \u2588\u2588 \u2588 \u2588\u2588\n' +
  ' \u2588\u2588   \u2588\u2588 \u2588\u2588      \u2588\u2588      \u2588\u2588  \u2588\u2588\u2588 \u2588\u2588      \u2588\u2588      \u2588\u2588   \u2588\u2588 \u2588\u2588\u2588\u2588\u2588\u2588\u2588\n' +
  ' \u2588\u2588\u2588\u2588\u2588\u2588\u2588 \u2588\u2588      \u2588\u2588\u2588\u2588\u2588\u2588\u2588 \u2588\u2588   \u2588\u2588 \u2588\u2588\u2588\u2588\u2588\u2588\u2588 \u2588\u2588\u2588\u2588\u2588\u2588\u2588 \u2588\u2588   \u2588\u2588 \u2588\u2588   \u2588\u2588\n' +
  '\n' +
  ' \u2588\u2588   \u2588\u2588 \u2588\u2588\u2588\u2588\u2588\u2588\u2588 \u2588\u2588   \u2588\u2588     \u2588\u2588   \u2588\u2588 \u2588\u2588\u2588\u2588\u2588\u2588\u2588 \u2588\u2588   \u2588\u2588 \u2588\u2588      \u2588\u2588\u2588\u2588\u2588\u2588\u2588\n' +
  ' \u2588\u2588  \u2588\u2588  \u2588\u2588       \u2588\u2588 \u2588\u2588      \u2588\u2588   \u2588\u2588 \u2588\u2588   \u2588\u2588 \u2588\u2588   \u2588\u2588 \u2588\u2588         \u2588\u2588\n' +
  ' \u2588\u2588\u2588\u2588\u2588   \u2588\u2588\u2588\u2588\u2588     \u2588\u2588\u2588       \u2588\u2588   \u2588\u2588 \u2588\u2588\u2588\u2588\u2588\u2588\u2588 \u2588\u2588   \u2588\u2588 \u2588\u2588         \u2588\u2588\n' +
  ' \u2588\u2588  \u2588\u2588  \u2588\u2588         \u2588\u2588        \u2588\u2588 \u2588\u2588  \u2588\u2588   \u2588\u2588 \u2588\u2588   \u2588\u2588 \u2588\u2588         \u2588\u2588\n' +
  ' \u2588\u2588   \u2588\u2588 \u2588\u2588\u2588\u2588\u2588\u2588\u2588    \u2588\u2588         \u2588\u2588\u2588   \u2588\u2588   \u2588\u2588 \u2588\u2588\u2588\u2588\u2588\u2588\u2588 \u2588\u2588\u2588\u2588\u2588\u2588\u2588    \u2588\u2588\n';

/* ── entry point ────────────────────────────────────────────────────── */
const HELP =
  `\n` + BANNER +
  `\n secrets-provider ${VERSION} — encrypted key storage for OpenClaw\n\n` +
  `  node ${scriptName()} setup            guided setup (start here)\n` +
  `  node ${scriptName()} doctor           check this machine works\n` +
  `  node ${scriptName()} store <name>     save a secret (value via stdin)\n` +
  `  node ${scriptName()} get <name>       print a secret (testing)\n` +
  `  node ${scriptName()} delete <name>    remove a secret\n\n` +
  `With no command, speaks the OpenClaw exec-provider protocol on stdin.\n` +
  `Docs: see README.md and references/setup-guide.md\n`;

async function main() {
  const [, , cmd, name] = process.argv;

  if (cmd === 'help' || cmd === '--help' || cmd === '-h') {
    process.stdout.write(HELP); return;
  }
  if (cmd === '--version' || cmd === '-v') {
    process.stdout.write(VERSION + '\n'); return;
  }
  if (cmd === 'setup') return setup();
  if (cmd === 'doctor') { if (!(await doctor())) process.exit(1); return; }

  if (cmd === 'get') {
    process.stdout.write(await getSecret(name));
    return;
  }
  if (cmd === 'store') {
    assertValidName(name);
    if (process.stdin.isTTY) {
      fail(`store reads the value from stdin so it stays out of shell\n` +
           `history. Either pipe it:\n` +
           `  printf '%s' '<value>' | node ${scriptName()} store ${name}\n` +
           `or use the friendlier guided mode:  node ${scriptName()} setup`);
    }
    const value = (await readStdin()).replace(/\r?\n$/, '');
    checkValue(value);
    await backend.set(name, value);
    process.stderr.write(`stored "${name}" in ${backend.label}.\n`);
    return;
  }
  if (cmd === 'delete') {
    assertValidName(name);
    await backend.del(name);
    process.stderr.write(`deleted "${name}".\n`);
    return;
  }
  if (cmd) fail(`unknown command "${cmd}".\n\n` + HELP);

  /* Protocol mode — OpenClaw is the caller. */
  const input = await readStdin();
  if (!input.trim()) fail('no stdin received.\n\n' + HELP);
  let req;
  try { req = JSON.parse(input); }
  catch { fail('stdin was not valid JSON (expected an OpenClaw provider request).'); }
  if (!Array.isArray(req.ids)) fail('request has no "ids" array.');

  const values = {};
  for (const id of req.ids) values[id] = await getSecret(id);
  process.stdout.write(JSON.stringify({ protocolVersion: 1, values }));
}

main().catch((err) => fail(err.message));
