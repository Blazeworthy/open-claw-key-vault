# Security Policy

This tool handles API keys. We take reports seriously and we'd rather hear
about a problem than have you sit on it.

## Reporting a vulnerability

**Do not open a public issue for a security vulnerability.** A public report
tells every reader how to attack people who are still running the vulnerable
version, before a fix exists.

Use GitHub's private vulnerability reporting instead:

**[→ Open a private security advisory](https://github.com/Blazeworthy/open-claw-key-vault/security/advisories/new)**

Only maintainers can see it. You'll be credited in the fix release unless you
ask not to be.

Prefer email, or don't have a GitHub account? **security@blazeworthy.com**.
Same expectations either way.

Useful things to include: the platform, the version (`node secrets-provider.cjs
--version`), what an attacker gains, and the smallest reproduction you have.
Never include a real API key.

## What to expect

This is a free tool maintained in the open, not a funded product with an
on-call rotation. Honestly:

- We aim to acknowledge a report within a few days.
- A confirmed vulnerability that exposes stored keys gets a patch release as
  fast as we can turn one around, with `SECURITY FIX` in the release title so
  the skill's version check flags it as urgent.
- If we disagree that something is a vulnerability, we'll tell you why rather
  than letting it go quiet.

## Already known — documented, not vulnerabilities

These are properties of the design, covered in the README's "Known attack
surface" section and in **[THREAT-MODEL.md](THREAT-MODEL.md)** — which also
explains why tool keys (Apify, Google Maps, Instantly) leak into model context
more easily than LLM provider keys, and what actually prevents it. Reports of
the following are welcome as discussion, but aren't treated as new findings:

- **An agent with unrestricted shell/exec access can read the keys.** It runs
  as your user, so it can invoke this script or the OS credential tool
  directly. No same-user secret store defeats this. Removing or sandboxing
  exec access is the actual boundary.
- **Malware running as your user can read the keys**, for the same reason.
- **Reading a key out of the store as the user who owns it.** That is the
  store working as designed; see the exec-access item above.
- **Anyone who can write your `openclaw.json` or the script file can repoint
  the provider.** Keep both writable only by you.
- **`get --print-secret` prints a key, and an agent can run it.** The flag is
  an anti-footgun that makes the action deliberate, not a security boundary —
  anything that can run this script can call the OS credential tool directly.
  Documented as such in THREAT-MODEL.md.

## Verifying what you downloaded

Every release publishes a SHA-256 checksum for `secrets-provider.cjs`. Check it
before you run it:

```
shasum -a 256 secrets-provider.cjs                     # macOS / Linux
Get-FileHash secrets-provider.cjs -Algorithm SHA256    # Windows PowerShell
```

Only trust copies from this repository. A reposted copy with three added lines
can exfiltrate every key you store.

## Supported versions

The latest release is the supported version. Because your keys live in the OS
credential store and never in this script, updating is just replacing the file
— no migration, no re-storing keys, and rolling back means putting the old file
back.
