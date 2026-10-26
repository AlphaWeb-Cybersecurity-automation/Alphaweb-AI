# AlphaWeb-AI — Model Strategy & Research Angle Review

*Analysis only. No code changed. Written 2026-10-19.*

This answers three questions Talib raised: (1) is the BaronLLM cyber-finetune
actually worth it over the base model for your job, (2) what the better model
setup looks like for tool routing + output interpretation, and (3) how novel
the idea still is after arXiv 2409.03789 (BreachSeek) and where a real paper
contribution could sit.

---

## TL;DR (the opinionated version)

1. **Drop BaronLLM.** For *your* two jobs — pick a tool from a fixed list, and
   turn raw tool output into plain-English findings — an offensive-security
   finetune of Llama-3.1-8B buys you almost nothing, and the ones like
   BaronLLM are tuned to *write exploits / answer red-team questions*, which is
   a different skill than *emit a valid JSON tool call*. The evidence below
   shows even Cisco's rigorous security finetune of the same base barely moves
   the needle on anything that isn't security trivia, and moves it **not at
   all** on tool-calling.

2. **The finetune was never your bottleneck — the *interface* is.** Your
   reliability problem is "does the model emit a valid, in-schema tool call",
   and that's solved by **grammar-constrained / JSON-schema decoding**, not by
   a better-read model. You already have the right instinct (strict JSON schema
   in the system prompt + deterministic regex fact extraction + keyword
   fallback). Lean into that: constrain the decoder, and the model choice stops
   mattering much.

3. **Best split:** keep a small local model only where data sensitivity demands
   it, and use a hosted frontier model (or a strong local 7–14B with
   constrained decoding) for the reasoning. For a research/portfolio product
   the single highest-leverage swap is **BaronLLM → Qwen2.5-7B-Instruct (or
   Qwen2.5-14B) with llama.cpp grammar-constrained JSON**, keeping the keyword
   selector as the safety net it already is.

4. **On the paper:** BreachSeek has largely eaten the generic "LLM drives pentest
   tools" idea. Your defensible contribution is **not** "autonomous pentester
   #37". It's the **domain-ownership-gated, continuous attack-surface agent**
   plus an **evaluation benchmark for LLM tool-orchestration** — which is
   exactly the thing BreachSeek *doesn't* have (they tested on a single
   Metasploitable box, qualitatively). That gap is your opening.

---

## 1. Is the BaronLLM finetune worth it for your job?

### What BaronLLM actually is
`AlicanKiraz0/Cybersecurity-BaronLLM` is a Q6_K GGUF, base = **Llama-3.1-8B-Instruct**,
finetuned on offensive-security content (exploit writing, red-team Q&A). You run
it through `llama-server.exe` and fall back to keyword selection if it's
unavailable (`llm_client.py`). Good engineering — the fallback is the right
safety net.

### Your two actual jobs
Reading your code, the model does exactly two things:

- **Tool selection** — `SYSTEM_PROMPT` in `llm_client.py` asks for a strict JSON
  object `{tool_selected, confidence, parameters, rationale, safety_checks_passed,
  warnings}` from a fixed 24-tool list.
- **Output interpretation** — `interpret_output()` turns raw tool output into
  numbered facts, and you already do a lot of this **deterministically** with
  regex (`_extract_facts_deterministic` handles nmap/httpx/curl/testssl/sqlmap/
  nikto/nuclei/...). The LLM is a *second pass*, not the primary parser.

Neither of these is the skill an offensive-security finetune optimises. Writing
a working SQLi payload ≠ emitting `{"tool_selected":"sqlmap", ...}` in valid
JSON. The finetune is aimed at the former; your product needs the latter.

### The hard evidence
The cleanest data point is **Cisco's Foundation-Sec-8B** — a *serious*,
well-resourced cybersecurity finetune of the **same base** (Llama-3.1-8B). If a
rigorous security finetune of your exact base can't show big gains, a
community GGUF finetune certainly won't. Their own numbers (Foundation-Sec-8B
vs base Llama-3.1-8B):

| Benchmark | Foundation-Sec-8B | Llama-3.1-8B | Delta |
|---|---|---|---|
| CTI-MCQA (security knowledge) | 0.644 | 0.617 | **+0.03** |
| CTI-RCM (CVE→CWE mapping) | 0.692 | 0.558 | **+0.13** |
| CTI-VSP (CVSS scoring) | 0.802 | 0.815 | **−0.01** |
| IF-Eval (instruction following) | 0.811 | 0.791 | +0.02 |

Two things jump out:
- The gains are **on security *knowledge*** (classify a CVE, map to a CWE). Your
  product doesn't need the model to *know* security trivia — the tools and your
  regex do the knowing.
- There is **no tool-calling / agentic benchmark at all**, and on one task the
  finetune is *worse* than base. Cisco's own card even says the model "cannot
  access external systems or actively scan environments." The finetune is a
  knowledge/classification lift, not an orchestration lift.

**Conclusion:** for tool routing + output interpretation, the BaronLLM finetune
is **mostly cosmetic**. You're paying 8B-of-VRAM and llama-server startup cost
for a model whose special sauce (exploit knowledge) your architecture doesn't
use. The base Instruct model would do the same job; a *function-calling*-tuned
model would do it better.

---

## 2. The better setup for the real job

### 2a. Model choice
Ranked for *your* job (tool selection + interpretation), best first:

1. **Qwen2.5-7B-Instruct** (or **14B** if VRAM allows). Qwen2.5 is the current
   strong open small model for structured/tool-calling output; it was trained
   with Hermes-style tool tags and handles schema output well. A published
   tool-selection eval (Docker, 2025) put **Qwen3-8B at 0.933 F1 and Qwen3-14B
   at 0.971**, essentially matching **GPT-4 (0.974)** on tool selection. For a
   fixed 24-tool list this is more than enough.
2. **Llama-3.1-8B-Instruct (base, no finetune)** — reported ~89% tool-call
   accuracy with native tool-calling tokens. A fine, zero-cost swap from
   BaronLLM (same base, drop the finetune).
3. **A hosted frontier model** (Claude / GPT-4-class) for the *reasoning* only
   — see the split below.

Don't go bigger than 14B locally for this; tool selection from a fixed list is
not a reasoning-heavy task once the decoder is constrained.

### 2b. The thing that actually fixes reliability: constrained decoding
Your current approach asks the model *politely* for JSON ("Respond ONLY with a
JSON object"). Small models break that contract — they wrap it in prose, add
code fences, or hallucinate a tool name not in your list, especially as the
tool list grows. The fix isn't a smarter model, it's **grammar-constrained /
JSON-schema decoding**:

- **llama.cpp / llama-server** (which you already run!) supports GBNF grammars
  and a JSON-schema→grammar converter, and handles tool-call grammar
  automatically. Pass your schema and the decoder **cannot** emit invalid JSON
  or a tool name outside the enum. This turns "tool_selected must be one of the
  listed names" from a *hope* into a *guarantee*.
- Caveat it won't fix: valid-JSON-but-nonsense values (e.g. a bogus port). Keep
  validating argument *values* in `validators.py` — you already do.
- One quantization gotcha: **don't quantize the KV cache below Q8** — Q4 KV
  cache measurably degrades tool-call accuracy. Your Q6_K *weights* are fine;
  it's the KV cache setting to watch.

This single change (constrain the decoder to your schema + enum) will do more
for reliability than any model swap, and it works with *any* of the models
above.

### 2c. Structured/function-calling vs free-text selection
You're already on the right side of this — you ask for JSON, not prose. Finish
the job: move from "JSON in the prompt" to "JSON **enforced by the grammar**",
and define `tool_selected` as an **enum of your actual tool names** in the
grammar. That makes hallucinated tools impossible by construction, which is the
single most common small-model failure as the tool list grows.

### 2d. The smart split (local vs hosted)
For a security product, data-sensitivity is a real axis. The clean split:

- **Local small model (Qwen2.5-7B + constrained JSON):** anything touching
  sensitive target data or raw tool output you don't want leaving the box — i.e.
  **output interpretation** and tool selection. This is your privacy story and
  your offline story.
- **Hosted frontier model:** the *harder reasoning* — multi-step planning ("given
  these 3 findings, what's the attack-surface narrative and what do we run next
  and why"), and the plain-English executive summary. This is where frontier
  quality actually shows, and the input is already-sanitised findings, not raw
  secrets.

Framed another way: **local for the per-tool mechanical decisions, hosted for
the cross-tool judgement.** You get frontier reasoning where it matters and keep
raw/sensitive data local. The keyword selector stays as the always-available
safety net under all of it.

### 2e. Efficiency levers (ranked by payoff for you)
1. **Grammar-constrained decoding** — biggest reliability win, ~free. (above)
2. **Keep GGUF + llama.cpp for now.** vLLM is faster *under concurrent load* and
   has great structured-output support, but it's a server-grade, GPU-first
   stack. For a single-user local tool, llama.cpp is the right call; switch to
   vLLM only when you're hosting multi-user and need throughput.
3. **Quantization:** Q6_K weights are a good quality/size point — keep them. The
   lever to pull is **KV cache precision (keep ≥Q8)**, not weight quant.
4. **Speculative decoding** (small draft model proposes tokens, big model
   verifies) — real latency win for *long generations*. Your outputs are short
   JSON blobs and bounded fact lists (`_INTERPRET_MAX_TOKENS = 400`), so the
   payoff here is **small**. Deprioritise until generations get longer.
5. **Prompt caching** the big static system prompt (the 24-tool list never
   changes) — llama.cpp reuses the KV prefix; make sure you're not rebuilding
   context each call. You already pre-build `_TOOLS_LIST_STR` at module load,
   which is the right instinct.

---

## 3. The research-paper angle

### What BreachSeek (arXiv 2409.03789) actually did
KFUPM-area authors (Alshehri et al., Aug 2024). "BreachSeek: A Multi-Agent
Automated Penetration Tester." Key facts from the full paper:

- **Architecture:** LangChain + LangGraph multi-agent graph — Supervisor (plans),
  Pentester (shell + Python tools), Evaluator (judges output), Recorder (writes
  the report). Dockerised Kali on RunPod, Next.js + FastAPI UI.
- **Models:** **Claude 3.5 Sonnet** for development, **Llama 3.1** (variant/size
  unspecified) for testing and planned deployment.
- **Evaluation:** **a single Metasploitable 2 machine**, reached root using
  ~150,000 tokens. **Qualitative only — no success rates, no benchmark, one
  target.** Planned (not done) benchmarks: OWASP WSTG and OSCP content.
- **Stated future work:** human-in-the-loop approval, finetuning on pentest
  write-ups, RAG over past techniques, multimodal input.

### How novel is your idea after this?
Be honest with yourself: the **generic** framing — "an LLM reads a natural-language
request, selects/orchestrates open-source security tools, interprets output" — is
**no longer novel**. BreachSeek (and a wave of 2024–2025 autonomous-pentest
agents) covers that. If you pitch "LLM orchestrates Kali tools", a reviewer
rejects it as done.

**But** — and this is the good news — BreachSeek is *weak exactly where your
review notes already point you*:

- They have **no authorization/ownership model.** They run against a box they
  own on their LAN and hand-wave the rest. Running this against arbitrary
  third-party domains is the legal cliff every one of these papers walks up to
  and doesn't solve.
- They have **no real evaluation.** One machine, qualitative, "it got root."
  There is no benchmark for *how good the tool-orchestration decisions are*.
- They're **one-shot**, not continuous.

### Where a real, defensible contribution sits
Pick one (ideally the first + third together):

1. **Domain-ownership-gated autonomous attack-surface agent.** Your two-tier
   gating (passive/offline tools free; active/intrusive tools require verified
   domain ownership via DNS-TXT / HTML-file / meta-tag) is a **genuine research +
   systems contribution**, because it's the thing that makes autonomous
   offensive tooling *legally and ethically deployable as a hosted product*.
   No autonomous-pentest paper I can see treats authorization as a
   first-class, verified, enforced-in-the-scan-flow primitive. Frame it as
   *"safe autonomy: authorization-aware tool orchestration"* and you have a
   novel angle that's also your actual product differentiator.

2. **Continuous monitoring with diffs.** Scheduled re-scans of verified domains,
   diffing against the last run ("3 new open ports / 1 new subdomain since
   Tuesday"). BreachSeek is one-shot; *continuous attack-surface management
   driven by an LLM that decides what to re-run and escalates on deltas* is a
   different and more useful problem.

3. **An evaluation benchmark for LLM tool-orchestration in security testing.**
   This is the most *paper-shaped* contribution and the field's biggest gap.
   BreachSeek literally couldn't measure itself. A benchmark that scores an
   agent on **tool-selection correctness** (did it pick the right tool for the
   finding — you can label this against your chain rules), **chain correctness**
   (nmap→nikto when a web port appears, etc. — you already encode the ground
   truth in `TOOL_CHAINS`!), **cost** (tokens/time to a goal), and **safety**
   (did it respect the authorization gate) would be citable on its own. You are
   *unusually well-positioned* to build this because your `tool_decision_engine`
   already encodes expert ground-truth chains.

### What a credible paper would actually need to measure
If you want this to survive review, it must report numbers, not demos:

- **A target set** bigger than one box: a suite of deliberately-vulnerable VMs
  (Metasploitable 2/3, DVWA, OWASP Juice Shop, HackTheBox/VulnHub retired boxes,
  a few deliberately-safe decoys to test the authorization gate).
- **Tool-selection accuracy / F1** vs a human-labelled "right tool for this
  request/finding" set. (You can seed labels from `TOOL_CHAINS`.)
- **Chain/path quality:** did the agent reach the goal, in how many steps, with
  how many wasted/incorrect tool invocations.
- **Cost:** tokens and wall-clock to goal (BreachSeek's one honest number was
  "~150k tokens" — beat it and report it).
- **Interpretation quality:** precision/recall of extracted findings vs ground
  truth (your deterministic extractor gives you a strong baseline to compare the
  LLM pass against — that comparison is itself interesting).
- **Safety/authorization:** false-allow rate (did it ever run a Tier-2 tool
  against an unverified domain) — ideally **zero**, and that's a headline result.
- **An ablation:** base model vs cyber-finetune vs constrained-decoding — which
  actually matters. (My bet, from §1–2: constrained decoding >> model choice >>
  finetune. *Proving that* is a clean, honest finding that would genuinely
  interest the community.)

> Note: your old literature-survey sheet
> (`docs.google.com/.../1d3XSa1Rx...`) wasn't reachable from here — it needs
> sign-in / isn't public. If you make it link-viewable or paste the columns,
> I'll fold its papers into a proper related-work table and position your
> contribution against each.

---

## Concrete next steps (small, high-leverage, in order)
1. **Swap the model:** BaronLLM → Qwen2.5-7B-Instruct (or keep Llama-3.1-8B base).
   Pure config/weights change; `llm_client.py` barely changes.
2. **Add grammar-constrained JSON** to the llama-server call, with
   `tool_selected` as an **enum** of your real tool names. Biggest reliability
   win for the least code.
3. **Keep the keyword fallback** exactly as-is — it's your safety net and your
   "works with no model" story.
4. **Fix the 13-vs-25 tool seed gap** (noted in REVIEW_NOTES) so your eval
   ground-truth and runtime allow-list agree — you'll need that consistency for
   any benchmark.
5. **For the paper:** commit to *authorization-aware + continuous + benchmarked*,
   not "autonomous pentester". Build the benchmark around your existing
   `TOOL_CHAINS` ground truth.

---

### Sources
- BreachSeek — arXiv 2409.03789 (Alshehri et al., 2024): https://arxiv.org/abs/2409.03789
- Foundation-Sec-8B-Instruct (Cisco; Llama-3.1-8B finetune + benchmarks): https://huggingface.co/fdtn-ai/Foundation-Sec-8B-Instruct
- Foundation-Sec-8B base technical report: https://arxiv.org/pdf/2504.21039
- Best local LLMs for function calling (Qwen/Llama tool-call numbers, Docker F1 eval): https://insiderllm.com/guides/function-calling-local-llms/
- Reliable JSON / structured output from local LLMs (grammar, KV-cache caveat): https://insiderllm.com/guides/structured-output-local-llms/
- BaronLLM model card: https://huggingface.co/AlicanKiraz0/Cybersecurity-BaronLLM_Offensive_Security_LLM_Q6_K_GGUF
