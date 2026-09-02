```
 ███████ ███████ ███████ ██   ██ ███████ ██      ███████ ██   ██
 ██   ██ ██   ██ ██      ███  ██ ██      ██      ██   ██ ██   ██
 ██   ██ ███████ █████   ██ █ ██ ██      ██      ███████ ██ █ ██
 ██   ██ ██      ██      ██  ███ ██      ██      ██   ██ ███████
 ███████ ██      ███████ ██   ██ ███████ ███████ ██   ██ ██   ██

 ██   ██ ███████ ██   ██     ██   ██ ███████ ██   ██ ██      ███████
 ██  ██  ██       ██ ██      ██   ██ ██   ██ ██   ██ ██         ██
 █████   █████     ███       ██   ██ ███████ ██   ██ ██         ██
 ██  ██  ██         ██        ██ ██  ██   ██ ██   ██ ██         ██
 ██   ██ ███████    ██         ███   ██   ██ ███████ ███████    ██

 ─────────────────────────────────────────────────────────────────
  your keys, encrypted by your OS · zero dependencies · MIT
```

# OpenClaw Key Vault

Stop keeping your OpenClaw API keys in a plaintext config file. This is a
single, dependency-free script that makes OpenClaw fetch its keys from your
operating system's built-in encrypted credential store:

| OS      | Store it uses                              | Install needed?              |
|---------|--------------------------------------------|------------------------------|
| macOS   | Keychain                                   | No — ships with macOS        |
| Windows | Credential Vault (Credential Manager)      | No — ships with Windows 10/11|
| Linux   | Secret Service (GNOME Keyring / KWallet)   | `sudo apt install libsecret-tools` |

No npm packages. No accounts. No cloud. One file, about a third of it
comments explaining *why* — short enough to read end to end before you trust
it. For a tool that handles your keys, you should.

⭐ **Star this repo** if it's useful — it's how other OpenClaw users find it,
and starred projects are the ones that get security review.

## Quick start (5 minutes, no dev experience needed)

```bash
node secrets-provider.cjs setup
```

That's it. The guided setup checks your machine works, asks for your keys
one at a time (your paste is invisible on screen — that's intentional),
verifies each one stored correctly, and prints the exact block to add to
your `openclaw.json`. Restart OpenClaw, confirm it works, then delete the
old plaintext keys from the config.

Prefer commands? `node secrets-provider.cjs help` lists them
(`doctor`, `store`, `fingerprint`, `check`, `get`, `delete`). To add one key
later: `node secrets-provider.cjs store <name> --prompt` prompts with hidden
input so nothing lands in your shell history. Full walkthrough with per-OS notes
and troubleshooting: [references/setup-guide.md](references/setup-guide.md).

## What this protects against — and what it doesn't

**Protects (keys at rest):**
- Your keys appearing in config files, dotfile repos, screenshots, backups
- File-reading malware or a stolen/imaged disk (combined with disk encryption)
- Your agent being prompt-injected into printing its own config — there's
  nothing in the file to print

**Does not protect (keys in use):**
- Malware already running *as your user* — it can ask the credential store
  too. Keep the agent machine clean and don't install unvetted plugins.
- Bugs in OpenClaw itself leaking keys from memory or model context

**The exposure most guides skip:** your LLM provider key is injected by
OpenClaw into an HTTP header and never reaches the model — but *tool* keys
(Apify, Google Maps, Instantly) are different, because the agent builds those
requests itself. A key pasted into a command lands in the model's context and
is resent every turn. **[THREAT-MODEL.md](THREAT-MODEL.md)** covers that in
full, including the calling convention that avoids it:

```bash
TOKEN=$(node secrets-provider.cjs get apify-token --print-secret)
curl -H "Authorization: Bearer $TOKEN" https://api.apify.com/v2/...
```

Only the literal `$(...)` text enters the transcript. To check a stored key
without revealing it, use `fingerprint` (sha256 prefix + length) or `check`
(exit 0/1) — which is why `get` now refuses to run without `--print-secret`.

That second list is why storage is only half the practice. The other half:
**one dedicated key per service, hard spend caps at every provider, and
rotation** — so a leak is a capped bill and a five-minute fix, not an
incident. For keys that can *act* (send email, post, touch client systems),
don't give the agent raw capability at all: gate those behind approval
middleware or a proxy that whitelists operations.

## Known attack surface — read this if you're security-minded

We attacked this design ourselves before publishing. The honest results:

- **An agent with unrestricted shell/exec access defeats ANY same-user
  secret store — including this one.** It can invoke this script, or the
  OS credential tool directly, because it runs as you. On macOS, "Always
  Allow" attaches to the `security` binary, so any same-user process then
  reads silently; Windows PasswordVault never prompts same-user access at
  all. If your agent is wired to public channels, removing/sandboxing exec
  access IS the security boundary — this script protects keys at rest, and
  spend caps limit the damage when that boundary fails.
- **PATH hijacking is closed by construction**: every OS tool is invoked
  by absolute path (`/usr/bin/security`, probed absolute locations for
  `secret-tool`, `System32` PowerShell). A fake binary earlier in PATH
  never sees your values.
- **Protect the pointers, not just the secrets**: the script file AND your
  `openclaw.json` must be writable only by you (`chmod 700` the script;
  keep both out of /tmp and cloud-synced folders; on Windows keep them in
  your user profile). An attacker who can edit the config just points
  OpenClaw at their own "provider."
- **Only trust this from the canonical repo.** Verify the SHA-256 checksum
  published on each GitHub release. A reposted copy with three added lines
  can exfiltrate every key you store.

## Security design notes (for reviewers)

We assume you'll read the code — please do. The decisions you'll find:

1. **Injection is prevented by construction, not by escaping.** Secret
   names and the namespace are allowlisted to `[A-Za-z0-9._-]{1,128}`
   before touching any OS command. They are the only externally
   influenced strings that ever reach one. This includes the
   `KEY_VAULT_NAMESPACE` environment variable.
2. **No shell, anywhere.** macOS/Linux tools are invoked via `execFile`
   with argument arrays. Windows PowerShell runs `-NoProfile
   -NonInteractive` with only allowlisted identifiers in the command text.
3. **Secret values stay off command lines** on Linux and Windows (stdin of
   the credential tool only). On macOS, `security add-generic-password` takes
   the value as an argument. Its documented `-w`-as-last-option prompt reads
   the *controlling terminal*, not stdin, so it cannot be driven
   non-interactively — 1.2.0 shipped that as a "fix" and it broke storing in
   any real terminal; 1.2.1 reverted it. macOS permits reading argv only from
   same-uid processes (or root), which could query Keychain regardless, so
   this adds no practical exposure on a single-user agent machine. It is the
   one platform-imposed compromise, documented rather than hidden.
   Values containing a line break are refused rather than silently mangled —
   `find-generic-password -w` hex-encodes those, so they never round-tripped
   correctly anyway.
4. **Zero dependencies** — nothing to typosquat, nothing to patch, no
   postinstall scripts. Node stdlib + the OS tool.
5. **`store` refuses TTY input** and takes values via stdin/hidden prompt
   so keys stay out of shell history and `ps` output.
6. **`doctor` cleans up after itself** (probe entry removed in a `finally`)
   and the setup wizard verifies every stored key by reading it back.

Found something anyway? Please open an issue — that's what public source
is for.

## Honest platform status

- **Linux**: tested end-to-end (store, read, delete, OpenClaw protocol,
  failure paths) against GNOME Keyring.
- **macOS**: same code structure as the widely used `security` CLI pattern;
  tested in production by the author.
- **Windows**: written against Microsoft's documented PasswordVault API;
  the least road-tested path. Run `doctor` and report issues.
- **Headless Linux servers**: keyrings need care there — read the
  [Headless Linux section](references/setup-guide.md#linux-headless-server--vps--read-this-honestly) before trusting it
  on a VPS. We'd rather tell you this than have you find out.

## FAQ

**Is this official OpenClaw software?** No — it's a community exec
provider implementing OpenClaw's documented provider protocol
(`protocolVersion: 1`).

**Where do my keys actually live?** In your OS's credential store,
encrypted, unlocked by your login: Keychain Access on macOS, Credential
Manager → Web Credentials on Windows, your login keyring on Linux. You can
see and delete them there yourself — this script has no storage of its own.

**How do I rotate a key?** Store the new value under the same name
(store overwrites), restart OpenClaw.

**Multiple agents on one machine?** Set `KEY_VAULT_NAMESPACE=openclaw-test`
(etc.) when storing and in the provider's `env` config to keep entries
separate.

**A service needs a username AND a key (e.g. DataForSEO)?** Two entries:
`dataforseo-login` and `dataforseo-password`. One entry per value, always.

## Updating

Your keys live in the OS credential store, not in this script — so an
update is just replacing the script file. Nothing migrates, no keys move,
and rolling back means putting the old file back.

1. Get notified: on GitHub, **Watch → Custom → Releases** on this repo.
2. Download the new release, verify its SHA-256 checksum against the one
   in the release notes.
3. Replace your `secrets-provider.cjs` with the new one (same path, same
   permissions: `chmod 700`).
4. Run `node secrets-provider.cjs doctor`. Done.

Versioning promises: **secret names and the namespace never change meaning
across versions** — no update will ever require re-storing your keys.
Patch/minor releases are always safe to apply or skip; a major version
means OpenClaw changed its provider protocol or a security fix needs
action, and the release notes will say exactly what to do. This script
will never check for updates or make any network call itself — that
property is the point.

## Using this as an agent skill

This repo doubles as a **skill** for agent tools that read `SKILL.md`
(Claude Code, Cowork, and similar). Point your agent tooling at this
repository — or drop it into whatever directory your tool loads skills from —
and the agent gains the key-handling policy in
**[SKILL.md](SKILL.md)** alongside the script itself.

What the agent picks up:

- How to walk someone through setup, including the per-OS gotchas (macOS
  Keychain prompt, `libsecret-tools` on Linux, WSL being Linux not Windows)
- The rule that matters most: **never generate a command containing a literal
  key value** — use `$(...)` substitution, and `fingerprint`/`check` instead of
  `get`, so keys don't land in model context
- Classifying every key as money-damage or reputation-damage, and refusing to
  hand an agent raw send capability for the second kind

You do not need the skill to use the script — it works fine on its own. The
skill just means an agent gives consistent advice about keys instead of
improvising.

## Getting help, and telling us what broke

| What you've got | Where it goes |
|---|---|
| **A security vulnerability** | **[Private advisory](https://github.com/Blazeworthy/open-claw-key-vault/security/advisories/new)** or **security@blazeworthy.com** — never a public issue. See [SECURITY.md](SECURITY.md). |
| A bug — command fails, key won't store | [Bug report](https://github.com/Blazeworthy/open-claw-key-vault/issues/new?template=bug_report.yml) (include `doctor` output, never a real key) |
| "It worked / didn't work on my OS" | [Platform report](https://github.com/Blazeworthy/open-claw-key-vault/issues/new?template=platform_report.yml) — the most useful thing you can send us |
| A question about keys leaking into model context | Read [THREAT-MODEL.md](THREAT-MODEL.md) first — it probably covers it |
| A question, or you're stuck in setup | [Discussions](https://github.com/Blazeworthy/open-claw-key-vault/discussions) |
| An idea | [Idea](https://github.com/Blazeworthy/open-claw-key-vault/issues/new?template=idea.yml) — read the two hard constraints first |

**Platform reports are genuinely the thing we want most.** The README above
tells you Windows is our least road-tested path and headless Linux needs care.
That stays honest only if people tell us how it actually went — and a "worked
fine on Windows 11" is as valuable as a failure, because it's how a path earns
a status upgrade.

Want to change something? [CONTRIBUTING.md](CONTRIBUTING.md) lists the hard
constraints (zero dependencies, no network calls, no shell) before you spend
time on a PR.

## About Blazeworthy

Built and maintained by **[Blazeworthy](https://blazeworthy.com)** — an online
marketing and development agency. We build with AI agents in client work every
day, and this came out of not wanting anyone's API keys sitting in a plaintext
file.

If this tool saved you a rotation scramble, the best thanks is a
⭐ **[star on GitHub](https://github.com/Blazeworthy/open-claw-key-vault)** or
an issue telling us what broke on your platform. Both help more than you'd
think — this is maintained in the open, for free.

More from us at **[blazeworthy.com](https://blazeworthy.com)**.

## Disclaimer

This is a free, open-source community tool provided **as is, without
warranty of any kind** (see LICENSE). It is not affiliated with or endorsed
by the OpenClaw project, Anthropic, OpenAI, or any service whose keys you
store with it.

**You remain fully responsible for your API keys and your agent's
behavior.** This tool protects keys at rest on your machine; it cannot
prevent misuse by an agent with shell access, malware running as your user,
mistakes in your OpenClaw configuration, or charges incurred on your
accounts. Set spend caps on every key. Test on a non-critical key first.
By using this software you accept that the authors and Blazeworthy LLC are
not liable for lost keys, unauthorized usage, service charges, or any other
damages arising from its use.

## License

MIT. You are responsible for your keys — the spend caps are not optional
advice.
