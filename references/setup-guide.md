# OpenClaw Key Vault — Setup Guide

Store your OpenClaw API keys in your operating system's encrypted credential
store instead of plaintext config files. One script, three platforms, zero
dependencies beyond Node (which OpenClaw already requires).

**Why bother?** By default your keys sit in `~/.openclaw/openclaw.json` in
plain text. Anything that can read files as your user — including the agent
itself, if misconfigured or prompt-injected — can read every key you own.
Moving keys into the OS credential store means they're encrypted at rest,
excluded from backups-in-plaintext, and absent from any file the agent can
be tricked into printing.

---

## Step 1 — Put the script in place

Copy `scripts/secrets-provider.cjs` somewhere permanent, e.g.:

- macOS/Linux: `~/secrets-provider.cjs`, then `chmod 700 ~/secrets-provider.cjs`
- Windows: `C:\Users\<you>\secrets-provider.cjs`

The permissions step matters: OpenClaw refuses to run provider scripts that
other users could tamper with. That check protects you.

## Fastest path: the guided setup

```
node secrets-provider.cjs setup
```

It checks your machine, stores your keys with hidden input, verifies each
one, and prints your exact openclaw.json block. If you use it, you can skip
Straight to "Point OpenClaw at the script" below. The manual steps follow
for people who prefer them.

## Step 2 — Verify your machine is ready

```
node secrets-provider.cjs doctor
```

This stores, reads back, and deletes a throwaway test secret. If it prints
`RESULT: PASS`, skip to Step 3. If it fails, see your platform's section
below.

### macOS
Nothing to install — Keychain and `/usr/bin/security` ship with macOS.
The first real read will pop a permission dialog: choose **Always Allow**
on a dedicated agent machine (no prompt on every restart) or **Allow** if
you want to approve each session.

### Linux (desktop)
Install the CLI: `sudo apt install libsecret-tools` (Debian/Ubuntu) or
`sudo dnf install libsecret` (Fedora). Your desktop's keyring (GNOME
Keyring or KWallet) unlocks when you log in, and the script uses it.

### Linux (headless server / VPS) — read this honestly
Headless boxes usually have **no keyring daemon running**, and starting one
means unlocking it with a password at boot — which has to come from
somewhere, weakening the whole scheme. Your realistic options, best first:

1. **Enable keyring unlock via PAM at SSH login** (`libpam-gnome-keyring`):
   the keyring unlocks with your login password each time you sign in.
   Good when a human starts/restarts the agent.
2. **Point the script at a cloud secrets manager instead** — if you're on a
   VPS you likely have one nearby (AWS/GCP/Azure secret managers, Vault,
   Doppler). This script's structure makes that swap a ~20-line backend.
3. **Accept an env file with `chmod 600` + full-disk encryption** and be
   honest with yourself that you've traded encrypted-at-rest for
   convenience. If you do this, the key-policy rules in the SKILL (caps,
   dedicated keys, rotation) are doing all your protecting.

### Windows
Nothing to install — the script uses the Credential Vault built into
Windows 10/11 via PowerShell. **If you run OpenClaw inside WSL**, you're on
Linux as far as this script is concerned: follow the Linux instructions
inside your WSL environment.

## Step 3 — Store your keys

The value is read from stdin so it never lands in shell history:

```
printf '%s' 'sk-ant-your-key' | node secrets-provider.cjs store anthropic-api-key
printf '%s' 'your-apify-token' | node secrets-provider.cjs store apify-token
```

Windows PowerShell equivalent:

```
'sk-ant-your-key' | node secrets-provider.cjs store anthropic-api-key
```

Services that need **two credentials** (e.g. DataForSEO uses login +
password): store two entries — `dataforseo-login` and `dataforseo-password`.
One entry per value, clearly named, always.

Check a key stored correctly — **without printing it**:

```
node secrets-provider.cjs fingerprint anthropic-api-key
  anthropic-api-key  sha256:9f2c4a1b8e05d773  (108 chars)

node secrets-provider.cjs check anthropic-api-key   # exit 0 stored, 1 not
```

The fingerprint is a truncated hash — enough to confirm you stored the right
key (compare it against the same key fingerprinted elsewhere, or just check
the length matches your provider dashboard), never enough to recover it.

There is also `get`, which prints the raw secret. It requires an explicit
`--print-secret` flag, because if an agent or a CI job runs it, that key ends
up in a transcript or log and rotating becomes the only fix. To use a key in a
command **without** it entering an agent's context, let the shell resolve it:

```
TOKEN=$(node secrets-provider.cjs get apify-token --print-secret)
curl -H "Authorization: Bearer $TOKEN" https://api.apify.com/v2/...
```

Only the literal `$(...)` text is ever logged. See
[THREAT-MODEL.md](../THREAT-MODEL.md) for why this matters more for tool keys
(Apify, Maps, Instantly) than for LLM provider keys.

## Step 4 — Point OpenClaw at the script

In `openclaw.json`:

```json
"secrets": {
  "providers": {
    "key-vault": {
      "source": "exec",
      "command": "/absolute/path/to/secrets-provider.cjs",
      "timeoutMs": 5000
    }
  }
}
```

Then replace each plaintext key in the config with a reference to its secret
id, restart OpenClaw, confirm everything works — and only then delete the
plaintext keys from the config.

---

## Troubleshooting

- **"could not read secret X"** — you haven't stored it (the error message
  shows the exact store command), or on Linux the keyring is locked, or the
  namespace differs (did you set `KEY_VAULT_NAMESPACE` when storing but not
  when running?).
- **macOS prompts every restart** — you clicked Allow instead of Always
  Allow. Re-trigger the prompt and choose Always Allow, or manage it in
  Keychain Access → the entry → Access Control.
- **Linux: "Object does not exist at path .../collection/login"** — the
  keyring collection is locked or absent. On a desktop, log out and back in.
  On a server, see the headless section above.
- **OpenClaw refuses the provider script** — fix ownership/permissions:
  `chmod 700` and make sure the file is owned by the user OpenClaw runs as.
- **"get prints the raw secret to stdout"** — `get` now needs an explicit
  `--print-secret`. If you were only checking a key exists, use `check` or
  `fingerprint` instead; they never emit the value.
- **Windows: "Retrieve" errors** — the entry doesn't exist under resource
  `openclaw`. Check Credential Manager → Web Credentials, or just re-run
  the store command.

## Uninstall / rotate

Rotate: store the new value with the same name (store is an upsert), restart
OpenClaw. Confirm the rotation landed with
`node secrets-provider.cjs fingerprint <name>` — the hash changes when the
value does, so you can verify without printing either key.
Remove: `node secrets-provider.cjs delete <name>`.

---

MIT licensed. No warranty — read the script before you run it; it's short
and heavily commented on purpose.
