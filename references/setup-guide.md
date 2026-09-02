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

One entry per **value**. Use lowercase-with-dashes. The name is the id
OpenClaw will reference, so choose it once and keep it:

| Pattern | Use for |
|---|---|
| `<service>-api-key` | A single key or token |
| `<service>-login` **and** `<service>-password` | Anything needing two values — never combine them into one entry |
| `<service>-<purpose>-key` | A second key for the same service (staging vs production) |

**Name rules.** A name must start with a letter or digit, then may contain
letters, digits and any of `.` `_` `-` `:` `/` `#`, up to 256 characters.

This is deliberately *identical* to OpenClaw's exec SecretRef `id` contract
(`^[A-Za-z0-9][A-Za-z0-9._:/#-]{0,255}$`), so anything this script accepts is
valid as an `id` in `openclaw.json` — no storing a name that OpenClaw later
refuses. Path-style names like `providers/openai/apiKey` work if you prefer
OpenClaw's own idiom. A **leading** dot, dash or underscore is rejected,
because OpenClaw rejects it too.

Throughout the rest of this guide:

- `<put name here>` — the name you chose above, e.g. what you'll type as the id
- `<put api key here>` — the actual secret value from your provider

### Adding a key — macOS

**Option A — hidden prompt (recommended).** Nothing is typed as a command
argument, so nothing lands in your shell history:

1. Open **Terminal**.
2. Change to wherever you put the script:
   ```bash
   cd ~
   ```
3. Run:
   ```bash
   node secrets-provider.cjs store <put name here> --prompt
   ```
4. At `Value for "<put name here>" (hidden, paste then Enter):` paste the key
   and press **Enter**. **Nothing appears on screen while you paste — that is
   intentional**, not a frozen terminal.
5. You'll see `stored "<put name here>" in macOS Keychain.`
6. The first time something *reads* a key, macOS shows a Keychain permission
   dialog. Choose **Always Allow** on a dedicated agent machine so restarts
   are unattended.

**Option B — piped (for scripts).** The value is in the command, so it will be
in your shell history unless you prefix the line with a space:

```bash
 printf '%s' '<put api key here>' | node secrets-provider.cjs store <put name here>
```

Wrap the value in **single quotes** so `$`, `!` and backslashes are taken
literally. If the key itself contains a single quote, use Option A instead.

**Option C — several keys at once:** `node secrets-provider.cjs setup` walks
through them with hidden input and prints your config block at the end.

### Adding a key — Linux

First-time only, install the credential tool and confirm the keyring is
unlocked:

```bash
sudo apt install libsecret-tools     # Debian/Ubuntu
sudo dnf install libsecret           # Fedora
node secrets-provider.cjs doctor     # expect RESULT: PASS
```

Then exactly as macOS:

1. Open your terminal and `cd` to the script's directory.
2. Hidden prompt (recommended):
   ```bash
   node secrets-provider.cjs store <put name here> --prompt
   ```
   Paste at the hidden prompt, press **Enter**. You'll see
   `stored "<put name here>" in Linux Secret Service (GNOME Keyring / KWallet).`
3. Or piped, for scripts (leading space keeps it out of history):
   ```bash
    printf '%s' '<put api key here>' | node secrets-provider.cjs store <put name here>
   ```

On a desktop the keyring unlocks when you log in. On a **headless server**
read [the headless section](#linux-headless-server--vps--read-this-honestly)
first — the guarantees are weaker there.

### Adding a key — Windows

Use **PowerShell**, not Command Prompt. `cmd.exe` mangles quoting and has no
reliable way to pipe a value without leaving it in the command.

1. Press **Win**, type `PowerShell`, open it.
2. `cd` to the script's folder:
   ```powershell
   cd $HOME
   ```
3. Hidden prompt (recommended):
   ```powershell
   node secrets-provider.cjs store <put name here> --prompt
   ```
   Paste at the hidden prompt, press **Enter**. You'll see
   `stored "<put name here>" in Windows Credential Vault.`
4. Or piped, for scripts:
   ```powershell
   '<put api key here>' | node secrets-provider.cjs store <put name here>
   ```
   Use **single quotes** in PowerShell — double quotes would expand `$`.

**Running OpenClaw inside WSL?** Then you are on Linux as far as this script
is concerned. Install `libsecret-tools` inside WSL and follow the Linux steps
there; keys stored in Windows are not visible to WSL, and vice versa.

### If you set a namespace

Running more than one agent on the machine? Whatever `KEY_VAULT_NAMESPACE` you
put in the provider's `env` block (Step 4a) must also be set when you store,
or the agent won't find the key:

```bash
KEY_VAULT_NAMESPACE=<put namespace here> node secrets-provider.cjs store <put name here> --prompt
```

```powershell
$env:KEY_VAULT_NAMESPACE='<put namespace here>'
node secrets-provider.cjs store <put name here> --prompt
```

### What the script refuses, and why

- **Typing the value as a command argument without `--prompt`** — that puts
  your key in shell history. The error message lists the three ways in.
- **A value containing a line break** — API keys are single-line. For a
  multi-line credential (PEM key, service-account JSON), store the **file
  path** here and keep the file itself `chmod 600`.
- **An empty value**, or a name with characters outside `A-Z a-z 0-9 . _ -`.

A *trailing* newline is stripped for you, so `echo` works as well as `printf`.

### Confirming it worked — without printing the key

```bash
node secrets-provider.cjs fingerprint <put name here>
  <put name here>  sha256:9f2c4a1b8e05d773  (108 chars)

node secrets-provider.cjs check <put name here>   # 0 stored, 1 absent, 2 store unreachable
```

The fingerprint is a truncated hash: enough to tell two keys apart or confirm
a rotation landed, never enough to recover the value. The character count is
usually the quickest sanity check against your provider's dashboard.

There is also `get`, which prints the raw secret and therefore requires an
explicit `--print-secret`. To *use* a key without it entering an agent's
context, let the shell resolve it:

```bash
TOKEN=$(node secrets-provider.cjs get <put name here> --print-secret)
curl -H "Authorization: Bearer $TOKEN" https://api.example.com/v1/...
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
Provider names must match `^[a-z][a-z0-9_-]{0,63}$`.

**On Windows, that config will not work — use `node.exe` plus `args`.**
OpenClaw runs `command` as a binary directly, with no shell, and Windows has
no shebang support, so a `.cjs` file cannot be executed on its own. Point
`command` at Node and pass the script as an argument:

```json
{
  "secrets": {
    "providers": {
      "key-vault": {
        "source": "exec",
        "command": "C:\\Program Files\\nodejs\\node.exe",
        "args": ["C:\\Users\\<you>\\secrets-provider.cjs"],
        "timeoutMs": 5000
      }
    }
  }
}
```

Find your Node path with `where.exe node`. On macOS and Linux the direct form
above works because the script carries a `#!/usr/bin/env node` shebang and
Step 1 made it executable — but if you prefer, the `command` + `args` form
works there too. One caveat if you use it: `command` must not be a symlink,
and Node installed via Homebrew, nvm or a package manager usually *is* one.
Resolve the real path first:

```bash
realpath "$(command -v node)"
```

OpenClaw validates the script before running it. `command` **must not be a
symlink**, must **not be group- or world-writable**, and on macOS/Linux must
be **owned by the user running OpenClaw**. That's why Step 1 says `chmod 700`.
On Windows, resolution fails if the ACL can't be verified — keep the script in
your user profile, not a shared directory.

Options you can add, with their defaults:

| Option | Default | Use it when |
|---|---|---|
| `timeoutMs` | `5000` | A slow keyring unlock needs longer |
| `noOutputTimeoutMs` | same as `timeoutMs` | Same, for the first byte of output |
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
  | node secrets-provider.cjs store <put name here>
```

### 4b. Reference the secrets — what actually goes in the field

This is the part people get stuck on. Wherever the config used to hold a
plaintext string, put a **SecretRef object** instead:

```json
{ "source": "exec", "provider": "key-vault", "id": "<put name here>" }
```

- `source` — always `"exec"` for this script
- `provider` — the name you gave it in 4a (`key-vault`)
- `id` — the name you stored the key under in Step 3

**Before** — a model provider key in plaintext:

```json
{
  "models": {
    "providers": {
      "<provider name>": {
        "apiKey": "<put api key here>"
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
      "<provider name>": {
        "apiKey": {
          "source": "exec",
          "provider": "key-vault",
          "id": "<put name here>"
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
  "plugins": {
    "entries": {
      "acpx": {
        "enabled": true,
        "config": {
          "mcpServers": {
            "<server name>": {
              "command": "npx",
              "args": ["-y", "<the mcp server package>"],
              "env": {
                "<ENV_VAR_NAME>": {
                  "source": "exec",
                  "provider": "key-vault",
                  "id": "<put name here>"
                }
              }
            }
          }
        }
      }
    }
  }
}
```

Note the nesting: MCP server env vars live under
`plugins.entries.acpx.config.mcpServers`, not at the top level.

Two-value services get two refs, pointing at the two entries you stored:

```json
"username": { "source": "exec", "provider": "key-vault", "id": "<service>-login" },
"password": { "source": "exec", "provider": "key-vault", "id": "<service>-password" }
```

## Step 5 — Verify, then delete the plaintext

**Order matters. Do not delete the plaintext keys first.**

1. Check the provider path is trusted, without running anything:

   ```bash
   openclaw config validate
   ```

   This verifies every exec `command` path (not a symlink, correct ownership
   and permissions) without executing providers. It is a path-trust check,
   not proof the provider returns a secret — but it catches the most common
   Step 4 mistake before anything else runs.

2. Load the new config:

   ```bash
   openclaw secrets reload
   ```

   Secrets resolve into an in-memory snapshot at startup and on reload, so a
   full restart works too — `reload` just avoids one.

3. Confirm every reference resolves and nothing plaintext is left:

   ```bash
   openclaw secrets audit --allow-exec
   openclaw secrets audit --check --allow-exec   # exits 1 if it finds anything
   ```

   `--allow-exec` lets the audit actually run exec providers. The `--check`
   form is what you'd put in a pre-commit hook or CI.

4. Exercise the agent on something that uses each key.

5. **Only now** remove the plaintext values from `openclaw.json`, then reload
   and audit once more.

   Plaintext keeps working in OpenClaw — SecretRefs are opt-in per credential
   — so nothing forces this step. `secrets audit --check` reporting clean is
   how you know you actually finished.

If a reference fails to resolve, OpenClaw reports the id it couldn't get.
Check the name matches exactly and that the namespace matches if you set one:

```bash
node secrets-provider.cjs check <put name here>
#   exit 0 = stored      exit 1 = not stored
#   exit 2 = the credential store itself could not be reached
```

Exit 2 matters: a locked keyring or a missing `secret-tool` is a different
problem from a missing key, and this tells them apart instead of reporting
both as absent.

## Managing your keys afterwards

### Rotate or change a key

`store` is an upsert — storing the same name again replaces the value:

```bash
node secrets-provider.cjs store <put name here> --prompt   # paste the NEW key
node secrets-provider.cjs fingerprint <put name here>      # hash changes = it took
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
node secrets-provider.cjs delete <put name here>
node secrets-provider.cjs check <put name here>    # exit 1 = gone
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
security find-generic-password -a openclaw -s <put name here>        # show metadata
security find-generic-password -a openclaw -s <put name here> -w     # print value
security add-generic-password -U -a openclaw -s <put name here> -w   # prompts you
security delete-generic-password -a openclaw -s <put name here>
```

Giving `-w` with no value **as the final option** makes `security` prompt you
to type the value, which is the safest way to add one **by hand**. It only
works interactively: that prompt reads your terminal, not stdin, so it cannot
be scripted — which is why the provider script passes the value as an argument
on macOS instead (see the README's security notes).

In Keychain Access, search the secret name, double-click, tick *Show
password*. The **Access Control** tab is where "Always Allow" lives if you
want to change what you chose at the first prompt.

### Doing it by hand — Linux

```bash
secret-tool lookup service <put name here> account openclaw
secret-tool store --label="openclaw <put name here>" service <put name here> account openclaw
secret-tool clear service <put name here> account openclaw
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
$c = $v.Retrieve('openclaw','<put name here>'); $c.RetrievePassword(); $c.Password

# remove one
$v.Remove($v.Retrieve('openclaw','<put name here>'))
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
