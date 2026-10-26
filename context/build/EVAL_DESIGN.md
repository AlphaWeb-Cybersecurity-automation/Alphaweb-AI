# AlphaWeb-AI — Evaluation Design

*Companion to MODEL_AND_RESEARCH_REVIEW.md. The paper's core contribution is
measurement: a reproducible benchmark for LLM tool-orchestration in security
testing. BreachSeek (arXiv 2409.03789) couldn't measure itself — one
Metasploitable box, ~150k tokens, qualitative. This is the gap.*

Written 2026-10-19. Analysis/design only — no code changed.

---

## 0. Positioning (say this in the paper)

Pitch the work as **"a benchmark + a safety-gated autonomous attack-surface
agent"**, NOT "another autonomous pentester." The benchmark is defensible and
citable even if the agent isn't state-of-the-art. The three legs:

1. **Authorization-aware orchestration** — domain-ownership-gated tool tiers
   (the safety story no prior agent treats as a first-class, enforced primitive).
2. **A benchmark** for LLM tool-selection + chain quality + interpretation +
   safety in security testing.
3. **An ablation** isolating what actually drives tool-orchestration quality:
   *constrained decoding >> model size >> cybersecurity finetune.*

---

## 1. Benchmark dataset

### 1a. Target lab (reproducible, Docker-composed)
Ship as compose files so a reviewer runs `docker compose up` and re-runs the
whole benchmark. Candidate targets:

| Target | Exercises |
|---|---|
| Metasploitable 2 | multi-service recon, open ports, legacy CVEs |
| DVWA | web injection (SQLi/XSS/CMDi) |
| OWASP Juice Shop | modern web app, API endpoints |
| WebGoat | guided web vuln classes |
| Vulnerable WordPress (wpscan target) | CMS-specific chain (nmap→whatweb→wpscan) |
| 1–2 HTB/VulnHub retired boxes | end-to-end path to goal |
| **Decoy: a domain you do NOT own** | the authorization gate (must be refused) |

The decoy target is important: it's how you measure false-allow rate.

### 1b. Labeled request set (the answer key)
~100–200 natural-language requests, each annotated:

```
{
  id,
  request,                 # "scan example.lab for open ports and web vulns"
  target,                  # which lab box
  target_state,           # what's true at this step (e.g. "port 80 open, nginx")
  correct_tool,           # ground-truth tool for this request/state
  acceptable_tools,       # set of defensible alternatives (avoid over-penalizing)
  correct_next_tool,      # expected follow-up given the finding
  tier,                   # 1 (no ownership) | 2 (ownership required)
  requires_ownership       # bool, for the safety metric
}
```

**You already own most of this ground truth.** `tool_decision_engine.py`
`TOOL_CHAINS` encodes the expert chain logic (nmap→nikto on web port,
subfinder→httpx, etc.). Formalize that into labels rather than inventing from
scratch. Use `acceptable_tools` (a set, not a single answer) so a defensible
alternative tool isn't scored as wrong.

---

## 2. Metrics

| Metric | Definition | Oracle / source |
|---|---|---|
| **Tool-selection accuracy / F1** | right tool for request+state vs labels | labeled set; comparable to Docker's ~0.9x F1 eval |
| **Chain quality** | reached-goal rate, steps-to-goal, wasted invocations | `TOOL_CHAINS` as expected path |
| **Interpretation precision/recall** | findings extracted vs ground-truth findings | compare LLM pass vs your regex extractor baseline |
| **Safety: false-allow rate** | Tier-2 tool fired at an unverified domain | target = 0 (headline result) |
| **Cost** | tokens + wall-clock to goal | beat BreachSeek's ~150k, report it |

Notes:
- **False-allow = 0** is the single most compelling number; nobody else reports
  authorization as a measured property.
- "Wasted invocations" (tools a human wouldn't have run) captures orchestration
  quality better than raw success/fail.
- The **LLM-vs-regex interpretation** comparison is itself a finding: if your
  deterministic extractor matches or beats the LLM on structured tool output,
  that argues for using the LLM only where parsing is genuinely ambiguous.

---

## 3. Ablations (what makes the paper land)

Run the full benchmark across each axis; hold everything else fixed.

1. **Model:** BaronLLM (cyber-finetune) vs base Llama-3.1-8B-Instruct vs
   Qwen2.5-7B-Instruct. *Hypothesis: finetune ≈ cosmetic for this task.*
2. **Decoding:** free-text JSON (current prompt) vs grammar-constrained
   JSON-schema + tool-name enum. *Hypothesis: biggest single lever.*
3. **Model tier (the cookbook ablation):** 14B → 7B → 3B → keyword-only, all
   with constrained decoding. *Hypothesis: constrained-3B ≈ 14B on selection.*
4. **RAG on/off** (if added): does retrieval over technique notes improve
   selection, or just cost?

**Expected headline:** *constrained decoding >> model size >> finetune.*
Slightly counterintuitive, cheap to demonstrate, genuinely useful — the kind of
result that gets cited.

---

## 4. Credibility bar (vs a demo)

- **Variance:** run each config 3–5×; report mean ± std. Small local models are
  noisy and a single run is not evidence.
- **Human-labeled gold set.** If you use LLM-as-judge for interpretation
  scoring, validate the judge against human labels on a subset and report
  agreement.
- **Reproducibility:** targets, labels, configs, seeds all shipped. One-command
  re-run. (This is also your product's "runs anywhere" story — reuse it.)
- **Baselines:** compare against (a) keyword-only selection and (b) a hosted
  frontier model as the ceiling, so your local numbers have both a floor and a
  ceiling.

---

## 5. Suggested milestones

1. **M1 — Formalize labels** from `TOOL_CHAINS` + hand-label ~50 requests on 2–3
   lab boxes. Get the harness scoring tool-selection F1 end to end on a small set.
2. **M2 — Add constrained decoding**, run ablation #2 (free-text vs constrained).
   This alone is a strong preliminary result.
3. **M3 — Model + tier ablations** (#1, #3) across Qwen/Llama/BaronLLM and sizes.
4. **M4 — Safety metric**: wire the ownership gate + decoy target, show
   false-allow = 0.
5. **M5 — Scale labels to 100–200**, add remaining targets, variance runs, write
   up.

M1+M2 is enough for a workshop paper; M1–M5 for a full conference submission.

---

## 6. Open questions for Talib (these shape scope)

1. **Venue + timeline?** Workshop (lighter, M1–M2 scope) vs full conference
   (M1–M5, more targets + variance). Changes how much to build.
2. **Solo or co-authors / tied to a course or the KFUPM group?** Affects
   labeling effort you can spread and how the related-work framing is pitched.
3. **Compute for the ablations?** Running 3–5× across 4 model configs needs some
   GPU time. Do you have a GPU (and access to a frontier API for the ceiling
   baseline), or should the design stay CPU/7B-friendly?
4. **Labeling appetite.** Are you up for hand-labeling ~100–200 requests, or
   should we bootstrap purely from `TOOL_CHAINS` and keep the set smaller?
5. **First-milestone tool scope.** Benchmark the handful of well-chained tools
   first (nmap/nikto/gobuster/httpx/sqlmap), or go broad across all 24 from the
   start? (I'd start narrow.)

---

## 7. Base papers / related-work anchors (added 2026-10-19)

- **PRIMARY ANCHOR — PentestGPT** (Deng et al., *USENIX Security 2024*). The
  foundational, peer-reviewed-at-a-top-venue LLM-pentest paper; open-source
  (6.5k+ GitHub stars); introduced an LLM pentest benchmark. Its own finding is
  our opening: *"LLMs are proficient at sub-tasks like using tools and
  interpreting output, but struggle to maintain whole-context."* Our
  chain-graph orchestration + authorization gating + tool-selection/safety
  benchmark is the differentiation. Cite as THE base paper.
- **CLOSEST TEMPLATE — HackSynth** (Muzsai et al., arXiv 2412.01778, 2024).
  "LLM agent + open evaluation framework" — Planner/Summarizer agent + two CTF
  benchmarks (PicoCTF + OverTheWire, 200 challenges), open source. This is the
  *format* a reviewer expects from a benchmark paper; model ours on it.
- **METHODS BACKBONE — "Benchmarking Practices in LLM-driven Offensive
  Security: Testbeds, Metrics, and Experiment Design"** (arXiv 2504.10112,
  2025). A how-to for exactly our benchmark. Follow it (see §8); cite it for
  methodological rigor.
- **CONTRAST — BreachSeek** (arXiv 2409.03789, 2024). Talib's closest-idea
  paper; the gap we exploit (no auth, no eval, one box).

## 8. Methodology refinements (from arXiv 2504.10112 — fold into §1–4)

These upgrade the design above and pre-empt reviewer objections:

- **Targets: VMs for system-level, containers only for web.** Containers can't
  host kernel-level vulns or Windows cases. So DVWA/Juice Shop/WebGoat as
  containers is fine; system-level targets (Metasploitable, HTB boxes) should be
  VM images.
- **Don't lean on multi-vuln boxes for coverage.** Metasploitable2 lets agents
  take trivial "simple paths," making coverage metrics unreliable. Use it, but
  **document exactly which vulns/attack-classes each target contains**, grounded
  in OWASP Top 10 / MITRE ATT&CK.
- **Sub-tasks defined by *expected result*, not tool invocation.** Refines our
  chain-quality metric: score "found the web service," not "ran nikto." This
  also handles equivalent tools (the paper's `cme` vs `nxc` example) — which is
  exactly why our labels use an `acceptable_tools` *set*. Validated.
- **Contamination guard.** Public CTF benchmarks may be in model training data.
  **Parametrize identifiers** (usernames, hostnames, passwords, paths) per
  instance and **embed canary strings** so you can detect memorization.
- **Sample size ≥5 runs per model** (not 3); **step limit ≥32 per sample**;
  report sample length.
- **LLM selection they recommend** (matches our plan): one cloud SOTA + one
  open-weight + one small <16B, and include an OpenAI model for comparability.
- **Add an automated baseline**: OWASP ZAP baseline scan and/or Metasploit,
  fully configured + documented, alongside our keyword-only floor and
  frontier-API ceiling.
- **Binary pass/fail hides progress** — always report sub-task progression, not
  just reached-goal. (We already track steps-to-goal; add per-sub-task.)
- **Publish everything**: build instructions, offline VM images where possible,
  baseline configs, LLM settings, seeds.

## 9. Scope decisions locked with Talib (2026-10-19)

- **Two-stage publishing:** workshop (M1–M2: labels + constrained-vs-free-text
  result) → extend same work to full conference (M3–M5).
- **Compute:** single GPU, **8 GB VRAM**. All local models run **quantized
  7–8B** (Q4–Q6 GGUF; 8B at FP16 won't fit, but Q6_K does — BaronLLM already
  proves it). Frontier "ceiling" baseline via **API**, not local. Ollama already
  installed → use it for model-swap ablations.
- **Labeling:** hybrid — auto-generate candidate `request→correct-tool` pairs
  from `TOOL_CHAINS`, then hand-verify a gold set (~50–100).
- **Tool scope:** start narrow (4–5 well-chained tools), expand later.
- **Keep the regex extractors.** Deterministic parsing of structured tool output
  is good architecture AND the baseline for the "LLM-vs-deterministic
  interpretation" metric. The LLM layers on top for ambiguous/narrative parts +
  cross-tool reasoning. Do NOT remove them.
