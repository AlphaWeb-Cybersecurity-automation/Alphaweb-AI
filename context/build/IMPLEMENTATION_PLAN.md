# AlphaWeb-AI — Implementation Plan

*Concrete, ordered architectural changes to turn the current app into a
publishable system. Companion to MODEL_AND_RESEARCH_REVIEW.md and
EVAL_DESIGN.md. Written 2026-10-19 — implement in VS Code at your pace.*

Guiding principle: **constrained decoding >> model size >> finetune.** Build the
reliability + safety + eval layers; the model is the least important variable.

Phases are ordered by leverage. A + B are enough for the workshop paper; C + D
make it a full conference paper and a real product.

---

## Phase A — Reliability & model (the "interface" thesis)

**A1. Grammar-constrained JSON decoding** *(highest leverage, least code)*
`backend/llm_client.py`
- llama-server accepts a `json_schema` (or GBNF `grammar`) field on the
  completion request. Pass a schema for your tool-selection object with
  `tool_selected` as an **enum of `AVAILABLE_TOOLS` + null**.
- Effect: the decoder *cannot* emit invalid JSON or a tool outside the list.
  Hallucinated tool names and prose-wrapped JSON become impossible.
- Keep validating argument *values* in `validators.py` (grammar guarantees
  structure, not sane values).

**A2. Add an Ollama backend (reuse installed models)**
`backend/llm_client.py` (+ config)
- Add a backend switch: `llama-server` (current) | `ollama`. Ollama exposes an
  OpenAI-compatible API at `http://localhost:11434` and supports JSON-schema /
  format-constrained output too.
- Auto-discover installed models via `ollama list`; let the cookbook (A4) pick
  one. This is how "use a model you already have" works with ~no friction.

**A3. Make the model configurable; demote the finetune to one config**
`backend/config.py`
- Default to **Qwen2.5-7B-Instruct** (Q4_K_M or Q6_K). Keep BaronLLM and base
  Llama-3.1-8B as selectable configs for the ablation. KV cache ≥ Q8;
  `BARONLLM_N_CTX=4096` to stay inside 8 GB.

**A4. Capability-adaptive cookbook / setup**
new `backend/services/system_profiler.py` + an installer/setup script
- Detect RAM / VRAM / GPU → pick a tier:
  `<8 GB / CPU` → 3B or keyword-only; `8–16 GB` → 7–8B Q4/Q6; `24 GB+` → 14B.
- On startup: if a usable model is already present (Ollama or a local GGUF),
  reuse it; else fetch the tier-appropriate one. This is the one-command
  packaging story (`docker compose up` / one installer).

**A5. Keep the regex extractors (no change — document the design)**
`backend/llm_client.py::_extract_facts_deterministic`
- Regex is the **primary** path for structured tool output; the LLM is the
  second pass for ambiguous/narrative output + cross-tool summary. Write this
  split into a code comment / README so reviewers (and future-you) see it's
  deliberate.

---

## Phase B — Safety & identity (the contribution)

**B1. Users + auth**
`backend/database.py`, `app.py`
- Add a `users` table; make `ScanJob.user_id` a real FK. Even simple token auth
  is fine — the point is a real identity to attach ownership to.

**B2. Tool tiers as a single source of truth**
`backend/database.py` (`ToolDefinition`) or a static `tool_tiers.py`
- Add a `tier` field (1 | 2) per tool. **Fix the 13-vs-25 seed gap**
  (`TOOL_SEED_DATA` vs `SUPPORTED_TOOLS` in `validators.py`) so the DB catalog
  and the validator allow-list agree — the benchmark needs this consistency.
- Tier map per REVIEW_NOTES: Tier 1 = passive/OSINT/offline/operates-on-upload;
  Tier 2 = active traffic to a live target (default curl/httpx/testssl/cewl to
  Tier 2).

**B3. Domain-ownership verification**
new `verified_domains` table + `backend/services/ownership.py`
- Columns per REVIEW_NOTES (`user_id` FK, `domain`, `method`, `token`,
  `status`, timestamps, `UNIQUE(user_id, domain)`).
- Methods: DNS-TXT, HTML-file at `/.well-known/`, meta-tag. One token per
  (user, domain). "Check Verification" runs the chosen check server-side.

**B4. Gate the scan flow**
`backend/app.py` (`/scan`, `/execute`)
- Resolve target → **registrable domain** via a public-suffix list (handles
  `.ac.in` etc.). Look up the tool's tier. If Tier 2 and no `verified` row for
  (user, domain) → reject with a verify-ownership response (token + 3 methods).
  Tier 1 skips the check. Keep `BLOCKED_IP_RANGES` on top (SSRF/abuse ≠ authz).
- This gate + the decoy target = your **false-allow-rate = 0** headline.

---

## Phase C — Orchestration depth (the wedge)

**C1. Add attack-surface-mapping tools, wired into chains**
`backend/llm_client.py` (TOOL_DESCRIPTIONS), `tool_runner.py`,
`services/tool_decision_engine.py` (TOOL_CHAINS)
- Add ~5–8, each with a chain rule (not a flat list): `dnsx`, `naabu`
  (→ nmap), `katana` (→ ffuf/nuclei), `tlsx`, `wafw00f`/`whatweb`
  (→ wpscan/nuclei); `waybackurls`/`gau`; `osv-scanner` (Tier 1, on uploads).
- Avoid near-duplicates of existing tools (hurts selection-accuracy numbers).

**C2. Continuous monitoring + diffs**
new `backend/services/monitor.py` + a scheduler
- Scheduled re-scans of verified domains; diff vs last run ("3 new open ports
  since Tuesday"); store deltas. This is the "pay to keep it running" wedge and
  a second paper angle.

---

## Phase D — Evaluation harness (the paper)

**D1. Labeled request set** — `eval/labels.jsonl`
- Auto-generate candidate `{request, target_state, correct_tool,
  acceptable_tools(set), correct_next_tool, tier}` from `TOOL_CHAINS`, then
  hand-verify a gold set (~50–100). Parametrize identifiers + add canary strings
  (contamination guard).

**D2. Target lab** — `eval/targets/` (compose + VM notes)
- Containers for web (DVWA, Juice Shop, WebGoat); VM images for system-level
  (Metasploitable, HTB box). A decoy domain you do NOT own for the safety test.
  Document which vulns each target has (OWASP/MITRE).

**D3. Scoring + ablation runner** — `eval/run.py`
- Metrics: tool-selection F1, chain quality (sub-tasks by expected result),
  interpretation precision/recall (LLM vs regex baseline), false-allow rate,
  tokens + wall-clock.
- Ablations: finetune vs base vs Qwen; free-text vs constrained; model tiers;
  RAG on/off. **≥5 runs/model**, step limit **≥32**, report mean ± std.
- Baselines: keyword-only (floor), frontier API (ceiling), OWASP ZAP/Metasploit
  (automated). Publish all configs + seeds.

---

## Suggested order of attack
1. **A1 + A3** (constrained decoding + model swap) — immediate reliability win,
   and unblocks the first ablation.
2. **B2 + B3 + B4** (tiers + ownership + gate) — the safety contribution.
3. **D1 + D3** on the 4–5 narrow tools — first real numbers → workshop paper.
4. Then **A2/A4** (Ollama + cookbook), **C1/C2** (ASM + continuous), scale D.
