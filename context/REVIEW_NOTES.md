# AlphaWeb — Review Notes (2026-10-19)

Candid take on current state, database choice, and the two-tier tool access idea.
Analysis only, no code changed.

---

## 1. Where the project actually is vs the old context file

README.md is the current truth. `ALPHAWEB_MASTER_CONTEXT.md` is an older
planning doc and diverges in a few ways worth knowing:

- **DB**: old doc says "SQLite (dev), PostgreSQL (prod)". Current code is
  Postgres-only (`database.py` reads `Settings.DATABASE_URL`, compose files
  spin up Postgres). SQLite is gone.
- **Two-tier AI (Gemma 3 + AlphaLLM)**: described as a key innovation
  "in progress". There is a `gemma_client.py`, but this is still aspirational,
  not a shipped, load-bearing loop.
- **Tool seeding**: old doc implies all 25 tools are seeded in the DB.
  `TOOL_SEED_DATA` in `database.py` only seeds **13**. The full 25 live in
  `SUPPORTED_TOOLS` (validators.py). So the DB tool catalog and the validator
  allow-list are out of sync.
- Everything else (25 tools, SAST via Bandit/ESLint/patterns, anomaly
  detection, PDF reports) matches.

---

## 2. Is Postgres a good choice here?

**Short answer: yes, keep Postgres. But it's not your real problem.**

Why Postgres is fine / good:
- Concurrent scans writing rows without SQLite's single-writer lock.
- JSON/JSONB for `findings`, `parameters`, `result`.
- It's the honest "production" story for a multi-user hosted product, which
  is where the two-tier idea is pushing you.

The honest caveat:
- The app is **not multi-user yet**. `ScanJob.user_id` is a bare
  `String(36)` with **no users table, no auth, no foreign key**. So today
  Postgres is slightly ahead of where the app is — you're paying the
  operational cost of Postgres (a running server, compose, migrations) for
  what is still effectively a single-user local tool.
- For a pure local hackathon demo, SQLite would be *simpler* (zero setup,
  one file). For anything you intend to host or make multi-tenant, Postgres
  is the right call.

**The real missing layer is identity, not the database engine.** Your
two-tier idea literally requires a `user` concept and "does this user own
this domain" — neither exists yet. So the next architectural move isn't
about Postgres; it's: add a `users` table, real auth (even simple), and make
`user_id` a foreign key. Once that exists, Postgres is clearly the right home
for it.

---

## 3. The two-tier tool access idea

This is a **good idea, and it's more than a feature — it's what makes the
product legally and ethically defensible.** Running nmap/sqlmap/hydra against
arbitrary domains a user does not own is the difference between "a security
SaaS" and "a hosted attack tool". Gating intrusive tools behind proof of
domain ownership is exactly what legitimate platforms (Detectify, Intruder,
Qualys, etc.) do. Build it.

### The dividing line

The clean rule: **Tier 2 = any tool that sends active/intrusive traffic to a
live third-party host. Tier 1 = passive intel, offline lookups, or tools that
operate on an artifact the user uploaded (code, hashes, a repo).**

### Proposed tier mapping of the current 25 tools

**Tier 1 — no ownership required** (passive / public-source / offline /
operates on user-supplied data):

| Tool | Why Tier 1 |
|------|-----------|
| theharvester | OSINT from public sources |
| sublist3r / subfinder / subdominator | passive subdomain enum (public DNS/CT logs) |
| amass (passive mode only) | passive asset discovery |
| searchsploit | offline exploit-DB lookup, no network |
| gitleaks | scans a repo the user provides |
| john / hashcat | crack hashes the user uploads, no target |
| **SAST (Bandit/ESLint/patterns)** | runs on code the user uploads |

**Tier 2 — requires verified domain ownership** (active scanning / probing /
exploitation against a live target):

| Tool | Why Tier 2 |
|------|-----------|
| nmap, masscan | active port scanning |
| nikto, nuclei, wapiti, wpscan | active web vuln scanning |
| sqlmap, commix | active injection testing |
| ffuf, gobuster | active fuzzing / dir brute-forcing |
| hydra | active credential brute-forcing |
| tcpdump | packet capture (local/network) |

**Borderline — light but still live-target** (curl, httpx, testssl, cewl):
these send real requests but are low-impact. Safest default is **Tier 2**;
if you want them in Tier 1, add strict rate-limiting and a single-request cap.
I'd put them in Tier 2 for a clean, conservative story.

Note: `amass` is only Tier 1 in passive mode. If you expose active enum, it's
Tier 2. Best to split by mode, not just tool name.

---

## 4. How verification fits the data model and flow

### New table

```
verified_domains
  id            (PK)
  user_id       (FK -> users.id)      # needs the users table first
  domain        (registrable domain, e.g. mjcollege.ac.in)
  method        (dns_txt | html_file | meta_tag)
  token         (per-user-per-domain random, e.g. breachme-verify=<hex>)
  status        (pending | verified | failed | revoked)
  created_at
  verified_at
  last_checked_at
  UNIQUE(user_id, domain)
```

### Proof mechanics (matches your screenshot)

Generate one token per (user, domain): `breachme-verify=<32-hex>`.
- **DNS TXT**: user adds `_breachme IN TXT "breachme-verify=<token>"`.
  Verify server-side with a DNS resolver lookup.
- **HTML file**: user uploads `/.well-known/breachme-verify.txt` (or
  `/<token>.html`) at the domain root. Verify with an HTTP GET.
- **Meta tag**: `<meta name="breachme-verify" content="<token>">` on the
  homepage. Verify by fetching the page and parsing the tag.

"Check Verification" → server runs the chosen check → on success set
`status=verified, verified_at=now`.

### Gating in the scan flow

At scan creation (the `/scan` and `/execute` path in `app.py`):
1. Resolve the target to its **registrable domain** (strip subdomains:
   `app.mjcollege.ac.in` -> `mjcollege.ac.in`). Use a public-suffix list so
   `.ac.in` style TLDs are handled correctly.
2. Look up the requested tool's tier (store `tier` on `ToolDefinition`, or a
   static map — single source of truth, and fix the 13-vs-25 seed gap while
   you're there).
3. If Tier 2 and no `verified_domains` row with `status=verified` for
   (this user, this domain) → **reject with a "verify ownership" response**
   that carries the token + the three methods. That's exactly the modal in
   your screenshot.
4. Tier 1 tools skip the check entirely.

### Keep it honest over time
- Re-verify periodically (`last_checked_at`); a DNS record can be removed.
- Let users **revoke**; set `status=revoked` and the gate closes again.
- Keep your existing `BLOCKED_IP_RANGES` guard (no private/loopback targets)
  on top of ownership — they solve different problems (SSRF/abuse vs
  authorization).

---

## 5. Frankly: why the current version won't pull users, and what would

It's currently a web wrapper around 25 open-source CLI tools plus a local
LLM. On its own that's not a reason for anyone to switch — they already have
these tools, and "put them in a browser" isn't a pain worth adopting a new
product for. Three things would change that:

1. **Pick one sharp use case.** "Continuous attack-surface monitoring for
   domains you own" is a real, fundable wedge. "25 tools in a UI" is not.
   The ownership gating turns the first one into something you can legally
   offer as a hosted product.

2. **Sell the interpretation, not the tools.** The only defensible value is
   the orchestration + the LLM turning raw tool output into (a) a prioritized,
   plain-English finding and (b) the decision of what to run next. That's the
   product. Right now the tools are the headline; they should be plumbing.

3. **Make it continuous, not one-shot.** Scheduled re-scans of verified
   domains, diff against last run ("3 new open ports since Tuesday"), alerting.
   That's the thing people pay to keep running; a one-time scan is a free
   afternoon with nmap.

Plus the obvious trust basics: ownership verification (above), real auth,
and clean reports. Without the identity + ownership layer you can't be a
multi-user product at all, so that work is the unlock for everything else.
