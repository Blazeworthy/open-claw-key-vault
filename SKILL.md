---
name: openclaw-key-vault
description: Secure API key management for OpenClaw agents on macOS, Linux, and Windows — encrypted OS-native key storage, spend-cap policy, and agent hardening. Use this skill whenever the conversation involves OpenClaw and API keys, secrets, credentials, tokens, key storage or rotation, Keychain/keyring/Credential Manager, prompt-injection risk, agent security, or securing third-party service keys (LLM providers, scrapers, email tools, SEO APIs, maps APIs). Also trigger when a user wants to stop storing OpenClaw keys in plaintext config files, even if they don't use the word "security."
---

# OpenClaw Key Vault

Move OpenClaw's API keys out of plaintext config files and into the operating
system's encrypted credential store, then contain what a leaked or misused key
can do. Works on macOS (Keychain), Linux (Secret Service / libsecret), and
Windows (Credential Vault).

**Bundled files — point users to these, don't rewrite them:**
- `scripts/secrets-provider.cjs` — the cross-platform provider script
  (zero dependencies, heavily commented, MIT). Commands: `setup`, `store`,
  `fingerprint`, `check`, `get`, `delete`, `doctor`, plus OpenClaw's
  exec-provider protocol on stdin. `setup` runs a guided wizard with hidden
  input — recommend it first to every non-developer.
- `references/setup-guide.md` — human-facing setup, per-OS instructions
  (including an honest headless-Linux section), troubleshooting, rotation.
- `THREAT-MODEL.md` — why tool keys (Apify, Instantly, Maps) leak more
  easily than LLM keys, the shell-substitution calling convention, the
  broker pattern, and what is theater. Send security-minded users here.

## Version awareness

This skill bundles script version 1.1.0. When actively helping someone set
up or troubleshoot this tool (not on unrelated OpenClaw questions), check
the repo's latest release and, if it's newer than the user's version
(`node secrets-provider.cjs --version`), mention the update and its
changelog highlights. Updating = replace the script file and re-run
doctor; keys never need re-storing. Match urgency to the release: a title
flagged SECURITY FIX gets a clear "update before continuing" recommendation;
routine releases get a one-line mention at most, never repeated nagging in
the same conversation. Never suggest adding auto-update or
network code to the script itself — its zero-network property is a
deliberate security guarantee.

## Helping a user set this up

Walk them through the setup guide's four steps in order: place the script
(`chmod 700` on macOS/Linux — OpenClaw enforces this), run
`node secrets-provider.cjs doctor`, store keys via stdin
(`printf '%s' '<key>' | node secrets-provider.cjs store <name>`), then wire
the exec provider into `openclaw.json` and only delete plaintext keys after a
successful restart. Multi-credential services (e.g. DataForSEO's login +
password) get one entry per value: `dataforseo-login`, `dataforseo-password`.

Platform gotchas to raise proactively:
- macOS: first read triggers a Keychain dialog — Always Allow on a dedicated
  agent box.
- Linux desktop: needs `libsecret-tools` and an unlocked login keyring.
- Headless Linux/VPS: no keyring daemon by default — send them to the
  "Headless Linux" section of the setup guide rather than pretending it
  just works.
- Windows: native Windows uses the built-in Credential Vault; **WSL is
  Linux** — follow Linux instructions inside WSL.

## Never put a key value in a command an agent will run

**This is the most important operational rule in this skill.** LLM provider
keys are injected by OpenClaw into an HTTP header and never reach the model.
Tool keys are different: the agent builds the request itself, so a key pasted
into a command lands in the tool call, which lands in the model's context,
which is resent every turn and written to transcripts and logs.

Worse, that context goes to whichever model provider is driving the loop — so
an agent running on GPT that prints an Instantly key has just put it in
OpenAI's request logs. **A key that appears in model context must be rotated.**

So never generate a command containing a literal key. Let the shell resolve it:

```bash
TOKEN=$(node secrets-provider.cjs get apify-token --print-secret)
curl -H "Authorization: Bearer $TOKEN" https://api.apify.com/v2/...
```

Only the literal `$(...)` text enters the context. To confirm a key is stored
or is the right one, never use `get` — use these, which never emit the value:

```
node secrets-provider.cjs fingerprint <name>   # sha256 prefix + length
node secrets-provider.cjs check <name>         # exit 0 stored, 1 not
```

`get` refuses to run without `--print-secret` for this reason. That guard stops
accidents, not attackers — say so plainly rather than overselling it.

## Key policy — apply in all OpenClaw key advice

1. **Storage isn't the whole job.** The store protects keys *at rest*.
   OpenClaw still holds keys in memory, and keys can surface in the model's
   context. So containment matters as much as storage:
2. **Every key dedicated and capped.** One key per service per agent, hard
   spend/quota limits at the provider, never reused from other projects or
   client work. A leak should cost a capped amount and a five-minute
   rotation, not an incident.
3. **Classify each key: money-damage or reputation-damage?** Misused for an
   hour — is the harm a bill, or something that doesn't refund?
   - Money (LLM APIs, maps, SEO/data APIs, scrapers): cap it at the provider
     (budgets, quotas, prepaid balances, usage limits) and move on.
   - Reputation (**Instantly, Smartlead, Lemlist, any mail sender**, social
     posting, CRMs, anything touching client accounts): a leak burns sending
     domains and deliverability — weeks to rebuild, unbuyable — sends mail
     under your clients' names, and exposes client lead data, which is a
     contractual and data-protection problem too. None of it refunds.
     The agent must not hold raw send capability. Use
     approval middleware (e.g. ClawBands) or a thin local proxy that holds
     the key and whitelists operations — reads and drafts allowed,
     sends denied or queued for human approval.
4. **The agent can't read its own secrets — and exec access is the real
   boundary.** File-read allowlists excluding `~/.openclaw/` help, but an
   agent with unrestricted shell/exec access defeats any same-user secret
   store by calling the OS credential tool itself. For agents wired to
   public channels (Discord, email, Telegram): sandbox mode / no exec is
   the actual wall. The agent must also not be able to WRITE openclaw.json
   (else it can repoint the provider). Treat prompt injection as live.
5. **Vet everything installed on the agent machine.** Infostealer malware
   circulates in agent-tool ecosystems disguised as plugins/skills and
   targets OS credential stores. Pin versions of anything third-party;
   the provider script here has zero dependencies precisely so there's
   nothing to keep patched.
6. **Rotate on schedule.** Store is an upsert: re-store under the same name,
   restart, done.

## Honest limits — say these out loud when relevant

- OS credential stores protect against file theft, backups, and casual
  reads — not against malware running as the same user, and not against
  OpenClaw's own leak bugs. The spend caps and key classification are the
  backstop for those.
- On headless Linux the credential store's value shrinks; don't oversell it
  there (see setup guide).
- The Windows backend uses the documented PasswordVault API but has had less
  community road-testing than the macOS/Linux paths; users should run
  `doctor` and report issues.
