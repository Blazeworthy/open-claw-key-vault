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

### Naming them

One entry per **value**, named in lowercase-with-dashes. The name is the id
OpenClaw will use to reference it, so pick it once and keep it:

| Service | Store as | Notes |
|---|---|---|
| Anthropic | `anthropic-api-key` | |
| OpenAI | `openai-api-key` | |
| Apify | `apify-token` | |
| Google Maps | `google-maps-api-key` | Restrict the key by IP + API at Google |
| Instantly | `instantly-api-key` | Reputation-damage key — see THREAT-MODEL |
| DataForSEO | `dataforseo-login` **and** `dataforseo-password` | Two values, two entries |
| Anything with user + secret | `<service>-login`, `<service>-password` | Never combine into one entry |

Names must match `[A-Za-z0-9._-]`, max 128 characters. Slashes are **not**
allowed, so `providers/openai/apiKey` won't work here — use
`openai-api-key` instead.

### Storing them

The value is read from stdin so it never lands in your shell history:

```bash
printf '%s' 'sk-ant-your-real-key' | node secrets-provider.cjs store anthropic-api-key
printf '%s' 'apify_api_your-real-token' | node secrets-provider.cjs store apify-token
```

Windows PowerShell:

```powershell
'sk-ant-your-real-key' | node secrets-provider.cjs store anthropic-api-key
```

Prefer not to have the key in your terminal at all? `node secrets-provider.cjs
setup` prompts for each value with the input hidden.

A trailing newline is stripped automatically. A line break *inside* the value
is rejected — API keys are single-line, and this keeps the value off the
command line on every platform. For a multi-line credential (a PEM key, a
Google service-account JSON), store the **file path** here and keep the file
itself `chmod 600`.

### Confirming it worked — without printing the key

```bash
node secrets-provider.cjs fingerprint anthropic-api-key
  anthropic-api-key  sha256:9f2c4a1b8e05d773  (108 chars)

node secrets-provider.cjs check anthropic-api-key   # exit 0 stored, 1 not
```

The fingerprint is a truncated hash: enough to tell two keys apart or confirm
a rotation landed, never enough to recover the value. The character count is
usually the quickest sanity check against your provider's dashboard.

There is also `get`, which prints the raw secret and therefore requires an
explicit `--print-secret`. To *use* a key without it entering an agent's
context, let the shell resolve it:

```bash
TOKEN=$(node secrets-provider.cjs get apify-token --print-secret)
curl -H "Authorization: Bearer $TOKEN" https://api.apify.com/v2/...
```

Only the literal `$(...)` text is ever logged. See
[THREAT-MODEL.md](../THREAT-MODEL.md) for why this matters far more for tool
keys (Apify, Maps, Instantly) than for LLM provider keys.

## Step 4 — Point OpenClaw at the script

Two pieces: **declare the provider once**, then **reference each secret** where
a plaintext key used to be.

### 4a. Declare the provider

In `openclaw.json`:

```json
{
  "secrets": {
    "providers": {
      "key-vault": {
        "source": "exec",
        "command": "/absolute/path/to/secrets-provider.cjs",
        "timeoutMs": 5000
      }
    }
  }
}
```

`key-vault` is a name you choose — it's what you'll put in `provider` below.

OpenClaw validates the script before running it. `command` **must not be a
symlink**, must **not be group- or world-writable**, and on macOS/Linux must
be **owned by the user running OpenClaw**. That's why Step 1 says `chmod 700`.
On Windows, resolution fails if the ACL can't be verified — keep the script in
your user profile, not a shared directory.

Options you can add, with their defaults:

| Option | Default | Use it when |
|---|---|---|
| `timeoutMs` | `5000` | A slow keyring unlock needs longer |
| `noOutputTimeoutMs` | `5000` | Same, for the first byte of output |
| `maxOutputBytes` | 1 MiB | Rarely — responses here are tiny |
| `args` | — | Extra CLI args for the script |
| `env` | — | Set a variable for the script, e.g. the namespace |
| `passEnv` | — | Allowlist which of *your* env vars reach the script |
| `jsonOnly` | `true` | Leave it alone; this script always speaks JSON |
| `trustedDirs` | — | Restrict which directories `command` may live in |

Running more than one agent on a machine? Give each its own namespace so the
entries stay separate — set it in `env`, and use the same value when storing:

```json
"key-vault": {
  "source": "exec",
  "command": "/absolute/path/to/secrets-provider.cjs",
  "env": { "KEY_VAULT_NAMESPACE": "openclaw-prod" }
}
```

```bash
KEY_VAULT_NAMESPACE=openclaw-prod printf '%s' 'sk-...' \
  | node secrets-provider.cjs store anthropic-api-key
```

### 4b. Reference the secrets — what actually goes in the field

This is the part people get stuck on. Wherever the config used to hold a
plaintext string, put a **SecretRef object** instead:

```json
{ "source": "exec", "provider": "key-vault", "id": "anthropic-api-key" }
```

- `source` — always `"exec"` for this script
- `provider` — the name you gave it in 4a (`key-vault`)
- `id` — the name you stored the key under in Step 3

**Before** — a model provider key in plaintext:

```json
{
  "models": {
    "providers": {
      "anthropic": {
        "apiKey": "sk-ant-abc123..."
      }
    }
  }
}
```

**After:**

```json
{
  "models": {
    "providers": {
      "anthropic": {
        "apiKey": {
          "source": "exec",
          "provider": "key-vault",
          "id": "anthropic-api-key"
        }
      }
    }
  }
}
```

The same object works anywhere a secret is accepted — including environment
variables handed to an MCP server:

```json
{
  "mcpServers": {
    "apify": {
      "env": {
        "APIFY_TOKEN": {
          "source": "exec",
          "provider": "key-vault",
          "id": "apify-token"
        }
      }
    }
  }
}
```

Two-value services get two refs, pointing at the two entries you stored:

```json
"username": { "source": "exec", "provider": "key-vault", "id": "dataforseo-login" },
"password": { "source": "exec", "provider": "key-vault", "id": "dataforseo-password" }
```

## Step 5 — Verify, then delete the plaintext

**Order matters. Do not delete the plaintext keys first.**

1. Load the new config:

   ```bash
   openclaw secrets reload
   ```

   Secrets resolve into an in-memory snapshot at startup and on reload, so a
   full restart works too — `reload` just avoids one.

2. Confirm every reference resolves and nothing plaintext is left:

   ```bash
   openclaw secrets audit --allow-exec
   openclaw secrets audit --check --allow-exec   # exits 1 if it finds anything
   ```

   `--allow-exec` lets the audit actually run exec providers. The `--check`
   form is what you'd put in a pre-commit hook or CI.

3. Exercise the agent on something that uses each key.

4. **Only now** remove the plaintext values from `openclaw.json`, then reload
   and audit once more.

If a reference fails to resolve, OpenClaw reports the id it couldn't get.
Check the name matches exactly (`node secrets-provider.cjs check <id>`) and
that the namespace matches if you set one.

## Managing your keys afterwards

### Rotate or change a key

`store` is an upsert — storing the same name again replaces the value:

```bash
printf '%s' 'sk-ant-THE-NEW-KEY' | node secrets-provider.cjs store anthropic-api-key
node secrets-provider.cjs fingerprint anthropic-api-key   # hash changes = it took
openclaw secrets reload
```

Nothing in `openclaw.json` changes — the reference points at the name, not the
value. Revoke the old key at the provider once the new one is working.

### Rename a key

There's no rename. Store under the new name, update the `id` in
`openclaw.json`, reload, then delete the old entry:

```bash
printf '%s' "$(node secrets-provider.cjs get old-name --print-secret)" \
  | node secrets-provider.cjs store new-name
# ...update openclaw.json, reload, confirm...
node secrets-provider.cjs delete old-name
```

### Remove a key

```bash
node secrets-provider.cjs delete apify-token
node secrets-provider.cjs check apify-token    # exit 1 = gone
```

Remove its SecretRef from `openclaw.json` too, or resolution will fail on the
next reload. **Deleting the entry does not revoke the key** — revoke it at the
provider as well, or it still works for whoever has a copy.

## Where your keys actually live

This script stores nothing of its own. Everything is in your OS credential
store, and you can inspect or delete entries there without this script.

| | macOS | Linux | Windows |
|---|---|---|---|
| Store | Keychain | Secret Service (GNOME Keyring / KWallet) | Credential Vault |
| GUI | **Keychain Access** → *login* | **Passwords and Keys** (`seahorse`) | **Credential Manager** → *Web Credentials* |
| Your secret name is the… | *Service* (`-s`) | `service` attribute | *User name* |
| The namespace is the… | *Account* (`-a`) | `account` attribute | *Resource* / internet address |

Default namespace is `openclaw`.

### Doing it by hand — macOS

```bash
security find-generic-password -a openclaw -s apify-token          # show metadata
security find-generic-password -a openclaw -s apify-token -w       # print value
security add-generic-password -U -a openclaw -s apify-token -w     # prompts, no argv
security delete-generic-password -a openclaw -s apify-token
```

Giving `-w` with no value **as the final option** makes `security` prompt
instead of taking the secret on the command line. This script does the same.

In Keychain Access, search the secret name, double-click, tick *Show
password*. The **Access Control** tab is where "Always Allow" lives if you
want to change what you chose at the first prompt.

### Doing it by hand — Linux

```bash
secret-tool lookup service apify-token account openclaw
secret-tool store --label="openclaw apify-token" service apify-token account openclaw
secret-tool clear service apify-token account openclaw
```

`store` reads the value from stdin and prompts if it's a terminal. In the
`seahorse` GUI the entries appear under your *Login* keyring with the label
`openclaw <name>`.

### Doing it by hand — Windows

These entries are **Web Credentials**, so `cmdkey` won't list them — use the
Credential Manager UI, or PowerShell:

```powershell
[void][Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials,ContentType=WindowsRuntime]
$v = New-Object Windows.Security.Credentials.PasswordVault

# list everything this script owns
$v.RetrieveByResource('openclaw') | Select-Object UserName

# read one value
$c = $v.Retrieve('openclaw','apify-token'); $c.RetrievePassword(); $c.Password

# remove one
$v.Remove($v.Retrieve('openclaw','apify-token'))
```

In the GUI: **Control Panel → Credential Manager → Web Credentials**, look for
`openclaw`.

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
- **"refusing to store a value containing a line break"** — you pasted a
  multi-line block (a PEM key or service-account JSON). Store the file path
  instead and keep the file `chmod 600`. A *trailing* newline is fine; it's
  stripped for you.
- **A SecretRef won't resolve** — run `node secrets-provider.cjs check <id>`.
  If that exits 0 the key is stored, so the mismatch is in `openclaw.json`:
  check `provider` matches the name you declared, `id` matches the stored
  name exactly, and that `KEY_VAULT_NAMESPACE` is set in the provider's `env`
  if you used one when storing.
- **`openclaw secrets audit` reports nothing but keys still fail** — add
  `--allow-exec`; without it the audit won't run exec providers.
- **Windows: "Retrieve" errors** — the entry doesn't exist under resource
  `openclaw`. Check Credential Manager → Web Credentials, or just re-run
  the store command.

## Uninstalling completely

1. Delete each entry: `node secrets-provider.cjs delete <name>` for every key
   you stored (or remove them in your OS's credential GUI — see the table
   above).
2. Remove the `secrets.providers` block and every SecretRef from
   `openclaw.json`, restoring plaintext values only if you intend to go back.
3. Delete the script file.

Rotation and removal of individual keys are covered in
[Managing your keys afterwards](#managing-your-keys-afterwards) above.

---

MIT licensed. No warranty — read the script before you run it; it's short
and heavily commented on purpose.
