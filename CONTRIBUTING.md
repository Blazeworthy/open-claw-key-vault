# Contributing

The most valuable contribution to this project isn't code — it's a platform
report. We publish honest per-platform status in the README, and Windows and
headless Linux are the paths that need real-world confirmation most.

## Ways to help, roughly by usefulness

1. **Tell us it worked (or didn't) on your OS.** Use the
   [platform report template](../../issues/new?template=platform_report.yml).
   Successes matter as much as failures — they're how a path graduates from
   "written against the documentation" to "road-tested."
2. **Report a bug** with the
   [bug template](../../issues/new?template=bug_report.yml). Include `doctor`
   output. Never include a real API key.
3. **Report a vulnerability privately** — see [SECURITY.md](SECURITY.md).
   Not in a public issue.
4. **Improve the docs.** If the setup guide lost you somewhere, that's a
   defect. Say where.
5. **Code.** See the constraints below first.

## Hard constraints on code changes

These aren't stylistic preferences. They're the security properties people
audit this tool against, and a PR that breaks one won't be merged:

- **Zero npm dependencies.** Node stdlib and the OS credential tool, nothing
  else. Nothing to typosquat, nothing to patch, no postinstall scripts.
- **No network calls, ever.** Including update checks. The script never
  phoning home is the whole point.
- **No shell.** OS tools are invoked via `execFile` with argument arrays.
  Windows PowerShell runs `-NoProfile -NonInteractive` with only allowlisted
  identifiers in the command text.
- **Absolute paths for every OS binary.** This is what closes PATH hijacking.
- **Allowlist externally influenced strings by construction**, not by
  escaping. Secret names and the namespace are `[A-Za-z0-9._-]{1,128}`.
- **Keep secret values off command lines** wherever the platform allows it.
- **Keep it readable.** People are told to read this script before trusting
  it. A clever line that saves four lines but costs a reader two minutes is a
  bad trade here.

## Before you open a PR

- Run `node secrets-provider.cjs doctor` on every platform you can reach, and
  say in the PR which ones you actually tested.
- Test the failure paths too, not just the happy one: missing credential tool,
  locked keyring, absent secret, bad secret name.
- If you changed anything security-relevant, say plainly what an attacker
  could do before and after.

## What this project won't become

A key manager for everything, a cloud sync service, a daemon, or a package
with a dependency tree. It's one readable file that moves OpenClaw keys into
the OS credential store. Scope creep is how tools like this stop being
auditable in an afternoon.
