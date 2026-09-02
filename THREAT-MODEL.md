# Threat model — and the part most guides skip

Moving keys into the OS credential store solves keys **at rest**. This
document is about the other exposure, the one that actually bites agent
operators: a key ending up inside the model's context.

It's written around the keys people really run through agents — Apify,
Google Maps, Instantly, Smartlead, DataForSEO, scrapers, CRMs — not just
LLM provider keys. Those tool keys are the more exposed class, for a
structural reason.

## Two different problems

| | |
|---|---|
| **Accidental leakage** | The agent runs a command that prints a key while doing something reasonable. The value lands in the transcript. Fixable with friction. |
| **Adversarial leakage** | A prompt-injected agent deliberately reads a credential. **Not fixable by this script**, or any same-user secret store. |

Everything below says which of the two it addresses. Anything that claims
to fix the second one from inside the agent's own reach is theater.

## Why tool keys leak more easily than model keys

Your LLM provider key is injected by OpenClaw itself, into an HTTP
`Authorization` header. The model never sees it — it isn't in the prompt,
the tool definitions, or anything the model reads as text.

Tool keys are different. The agent *calls* Apify or Instantly, so unless
there's a first-class integration injecting the credential, the agent has
to build the request itself:

```
curl "https://api.apify.com/v2/acts/.../runs?token=apify_api_xxxxx"
```

The key is now in the tool call. The tool call is in the context. The
context is **resent to the model provider on every subsequent turn**, and
written to your transcript and any logging you have. No attacker required
— that's the normal path working exactly as designed.

### The cross-provider consequence

Because context goes to whichever model is driving the loop, a leaked key
is transmitted to a provider that may have nothing to do with it. If your
agent runs on GPT and prints an Instantly key, that credential is now in
OpenAI's request logs. If it runs on Claude and prints a Google key, it's
in Anthropic's.

Nobody acted in bad faith and nothing was hacked. But the value is now in
a third party's retention window, outside your control, and deleting your
transcript doesn't reach it.

**Treat any key that appears in model context as compromised, and rotate
it.** Not "probably fine."

## The calling convention: let the shell resolve it

*(Fixes accidental leakage.)*

Never let the value materialise in the command text. Use substitution:

```bash
TOKEN=$(node secrets-provider.cjs get apify-token --print-secret)
curl -H "Authorization: Bearer $TOKEN" https://api.apify.com/v2/...
```

What enters the context is the literal string
`$(node secrets-provider.cjs get apify-token --print-secret)`. The shell
resolves it, the key transits the process, and only curl's **output**
comes back to the model. The secret is never in the transcript.

Two honest caveats:

- It does nothing against an agent that has been injected into printing
  the value on purpose. It is an anti-footgun, not a boundary.
- The token appears briefly in `ps` argv — not from this script, which
  never puts a value on a command line, but from `curl` itself. Visible to
  same-uid processes only, which could read the store directly anyway. Use
  `curl --config` with a header file if even that matters to you.

To make the footgun harder to trip, `get` refuses to run without an
explicit `--print-secret`, and points you at the two commands that answer
the same questions safely:

```
node secrets-provider.cjs fingerprint <name>   # sha256 prefix + length, never the value
node secrets-provider.cjs check <name>         # exit 0 if stored, 1 if not
```

Most reasons to look at a stored secret are really *"is it there?"* and
*"is it the right one?"* Neither needs the value. `fingerprint` lets you
compare a stored key against a provider dashboard without revealing it.

## Classify every key before you store it

Ask one question: **misused for an hour, is the damage a bill, or
something that doesn't refund?**

### Money damage — cap it and move on

Apify, Google Maps, DataForSEO, scrapers, LLM APIs. A stolen key burns
credit. That is an argument with a vendor, not an incident.

- **Google Maps** is the one to fix at the provider today. Maps keys travel
  in URL query strings and are the most-leaked class of key on the
  internet — so use Google's key restrictions: lock the key to your agent
  box's **IP address** and to **specific APIs** (Geocoding only, say). A
  restricted Maps key that leaks won't authenticate from anyone else's IP.
  Add a budget cap and this stops being a real problem.
- **Apify and similar**: dedicated token for the agent, account-level
  usage and spend limits, scoped tokens if your plan offers them.

### Reputation damage — the agent must not hold it

Instantly, Smartlead, anything that sends email, posts publicly, or
touches client accounts.

An Instantly key can send mail from your sending domains **and** read your
client lead lists. Consider what a leak actually costs:

- Burned sending domains and wrecked deliverability — weeks to rebuild,
  and you cannot buy it back
- Mail going out under your clients' names
- Exposure of client contact data, which is a contractual and
  data-protection problem, not merely a security one

None of that refunds. **Do not give the agent raw send capability.** Reads
and drafts are fine; sends go through approval middleware or a proxy that
whitelists operations.

## Real boundaries, strongest first

*(These are the ones that survive an adversary.)*

**1. Run the agent as a different OS user.** Credential stores are
per-user. "Same-user malware defeats it" is only true while the agent *is*
the same user. Run OpenClaw in a container or under a service account,
keep the vault under yours, and the agent's shell access stops being a
master key. This is the only item here that is a boundary rather than a
mitigation.

**2. Give the agent a capability, not a credential — the broker pattern.**
Run a small local proxy that holds the keys and listens on loopback. The
agent calls `http://127.0.0.1:8081/enrich_lead` with no credential at all;
the proxy attaches the real key on the way out and exposes only the verbs
you chose. It simply has no endpoint for the destructive ones.

The agent can still *use* Apify or Instantly — it can never *hold* a
credential that works from anywhere in the world. A stolen capability dies
when you kill the proxy; a stolen key works until you rotate it. This also
gives you per-client key separation, so a leak is scoped to one client
rather than your whole book.

**3. Credentials that expire.** Where the provider supports it. Most SaaS
keys are long-lived, which is the root problem. Routing LLM traffic
through Bedrock or Vertex gets you STS/ADC tokens that expire in about an
hour; a leaked hour-old token is a non-event.

**4. Egress control.** A key in model context still has to get out.
Restricting the agent's outbound network to the endpoints it actually
needs closes the obvious exfiltration paths.

**5. Caps and rotation.** The backstop for when the above fails. Dedicated
key per service per agent, hard spend cap, scheduled rotation. Store is an
upsert — re-store under the same name and restart.

## What does not work

Named explicitly so nobody mistakes these for protection:

- **Removing `get` from this script.** An agent can call the OS tool
  directly: `security find-generic-password`, `secret-tool lookup`. The
  guard on `get` is anti-footgun only, and says so.
- **Refusing to run without a TTY.** An agent can allocate a PTY.
- **Telling the model "never print secrets" in a system prompt.** Prompt
  injection exists to overwrite exactly that.
- **This script, against an agent with unrestricted exec.** It runs as
  you, so it can do anything you can. Removing or sandboxing exec access
  *is* the boundary; this script protects keys at rest and spend caps
  limit the damage when that boundary fails.

Found a hole we haven't listed? See [SECURITY.md](SECURITY.md) — privately,
please.
