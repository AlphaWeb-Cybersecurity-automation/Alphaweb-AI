# AlphaWeb flags and change log

Two parts: the runtime switches that change behaviour, and every change made so far with where it lives and how it was checked. Newest information goes in the tables, not in prose. Nothing here is committed to git yet. Context: `alpha-context.md`. Design: `engineering.md`.

## 1. Runtime flags

Set in `backend/.env` (git-ignored) or the process environment. Defaults come from `backend/config.py`.

| Flag | Default | Effect |
|---|---|---|
| `OWNERSHIP_ENFORCEMENT` | `enforce` | `enforce`: Tier-2 tools only run on a domain the user verified. `off`: skip the gate (local lab use only). |
| `AUTH_REQUIRED` | `false` | `false`: requests with no token run as `default-user`. `true`: every request needs a token. A wrong token is always rejected. |
| `LLM_MODEL` | `auto` | `auto`: the cookbook picks the best local model that fits and can run. Or a name from `backend/model_catalog.py`. |
| `LLM_HF_MODEL` | (set by `auto`) | Force a Hugging Face repo or directory, served by `hf_server.py`. |
| `LLM_HF_PYTHON` | `<root>/.venv-hf/Scripts/python.exe` | Interpreter of the Hugging Face model-server virtualenv. |
| `BARONLLM_MODEL_PATH` | (derived) | Explicit GGUF path. Overrides everything else. |
| `LLM_MODELS_DIR` | `models` | Folder searched for GGUF files. |
| `BARONLLM_N_CTX`, `BARONLLM_N_GPU_LAYERS`, `BARONLLM_TEMPERATURE`, `BARONLLM_CONFIDENCE_THRESHOLD` | 4096, 35, 0.1, 0.7 | Layer-2 model parameters. The prefix is legacy; they apply to whichever model is active. |
| `GEMMA_ENABLED`, `GEMMA_MODEL` | `true`, `qwen2.5:1.5b` | Layer-1 router through Ollama. Keyword fallback when unavailable. |
| `POSTGRES_PORT` | `5432` (5544 on the dev machine) | Port of the project's Postgres. |
| `MAX_TOOLS_PER_SCAN`, `WORKFLOW_MAX_DEPTH`, `WORKFLOW_MAX_TOOLS` | 3, 3, 3 | Orchestration caps. |

## 2. Change log

Status: **done** = implemented and checked as described; **partial** = implemented, part not verified; **open** = not built.

### Reliability and models

| ID | Change | Status | Where | Checked how |
|---|---|---|---|---|
| A1 | Schema-constrained tool selection: `tool_selected` is an enum of the real tool names plus null; `_chat` takes `schema=`, `seed=`; `analyze(constrained=)` | done on the Hugging Face backend; partial for llama.cpp | `backend/llm_client.py` | Fake-tool curl test on the HF server (3 seeds); 52-request benchmark, 0% invalid. llama.cpp not run, no binary |
| A3 | Model chosen by name, default Qwen2.5-7B, BaronLLM and Llama-3.1 selectable | done, superseded by the catalog | `backend/config.py` | Config resolution cases tested. An earlier single-file Qwen GGUF name was wrong (the official repo splits it); the catalog now uses single-file repos |
| A4 | Cookbook: hardware detection, local model discovery (models folder, HF cache, Ollama blobs), runtime detection, pick or recommend, download, `GET /api/system` | done | `backend/services/system_profiler.py`, `backend/model_catalog.py`, `config.resolve_llm_model` | Run on the dev machine: found GPU, rejected the base model, auto-selected the instruct model |
| HF | Hugging Face backend: OpenAI-style server over transformers and bitsandbytes with lm-format-enforcer; own virtualenv | done | `backend/hf_server.py`, `backend/requirements-hf.txt`, `.venv-hf/` | Loads on the RTX 5060; app spawns and stops it; fixes for null-enum, trailing commas, whitespace padding, object-only JSON mode |
| A2 | Ollama as a model backend | open | | The cookbook only reuses Ollama's GGUF files through llama-server |
| A5 | Regex extractors and keyword fallback kept | done (no change) | `backend/llm_client.py`, `backend/app.py` | Not removed, by decision |

### Safety and identity

| ID | Change | Status | Where | Checked how |
|---|---|---|---|---|
| B1 | `users` table, `scan_jobs.user_id` foreign key, API tokens (hashed), `POST /api/users` | done | `database.py`, `services/ownership.py`, `app.py` | Legacy-table migration tested (stray user ids backfilled, key added once); token, bad token, duplicate email |
| B2 | Tool tiers as single source of truth; seed gap 13 to 25 closed | done | `backend/tool_tiers.py`, `validators.py`, `database.py` | Real Postgres: 13-row table without `tier` upgraded to 25 rows, 9 Tier 1; repeat run unchanged |
| B3 | Domain ownership: DNS TXT, `/.well-known` file, meta tag; registrable-domain parsing; challenge, verify, list, revoke endpoints | done | `services/ownership.py`, `app.py` | 35 checks against real Postgres with the network fetches stubbed. A real positive check was not run |
| B4 | Gate applied to `/api/scan`, `/chat`, `/chat/stream`, `/execute`, and every orchestrator step | partial | `app.py`, `services/shannon_orchestrator.py` | All paths tested except `/api/scan`, which needs the model in the loop |

### Evaluation

| ID | Change | Status | Where | Checked how |
|---|---|---|---|---|
| D1 | 52 selection labels and 11 chain fixtures, `{target}` placeholders, canary string | done, unreviewed | `eval/make_labels.py`, `eval/labels.jsonl` | Chain fixtures run against the rule engine (found the masscan gap) |
| D3 | Runner: accuracy, macro-F1, invalid rate, chain accuracy, latency, tokens, false-allow | done | `eval/run.py` | Keyword and LLM arms run. Five-run instruct comparison was interrupted and has no saved results |
| D2 | Target lab (DVWA, Juice Shop and others) | open | | |

### Platform, tools and repo

| ID | Change | Status | Where | Checked how |
|---|---|---|---|---|
| IMG | All 25 tool images build. `subdominator` Dockerfile added. Go tools moved from `golang:1.24-alpine` to `golang:alpine` (latest releases need Go 1.25 or newer). `theharvester` moved to Python 3.14. `amass` builds from source (the `ghcr.io` base image is denied) | done | `backend/tools/*/Dockerfile` | `docker images` lists 25; amass and subdominator run `--help` |
| FE | Global frontend polish: web fonts actually loaded, shared radius, shadow and motion tokens, focus rings, smoother scrollbars, reduced-motion support | partial | `frontend/index.html`, `index.css`, `App.css` | Builds and serves; not reviewed visually. Per-component CSS untouched |
| DEPS | Removed unused `llama-cpp-python`; added `dnspython`, `tldextract` | done | `backend/requirements.txt` | Fresh venv install, backend starts |
| GIT | `.gitignore`: `.venv/`, `.venv-hf/`, `*.gguf`, `*.safetensors`, `eval/results/`, tool caches | done | `.gitignore` | `git check-ignore` on each pattern |
| DOCS | Planning docs moved: implementation plans to `context/build/`, other background to `context/`; maintained summaries in `knowledge/` | done | repo root | `README.md` stays at the root |
| DB | Project Postgres moved to port 5544 because a local Postgres owns 5432 | done | `backend/.env` | Backend connects and initialises |

### New tools (plan phase C1)

Status: **open, scoped**. Not started in code. Proposed in three groups, five to eight tools, attack-surface mapping first:

| Group | Tools | Tier | Chain role |
|---|---|---|---|
| Attack-surface mapping | dnsx, naabu, katana, tlsx, one fingerprinting tool (whatweb or wafw00f) | 2 (they touch the live target) | dnsx resolves what subfinder or amass found; naabu feeds nmap; katana feeds ffuf and nuclei; tlsx feeds testssl or nuclei; fingerprinting routes to wpscan or nuclei |
| Passive and OSINT | waybackurls or gau, dnsrecon, optionally Shodan or Censys through an API key | 1 | feed katana, ffuf and nuclei with known URLs |
| Supply chain (runs on uploads) | osv-scanner or grype, next to trivy and gitleaks | 1 | operates on user-supplied artifacts |

Rules agreed for this phase: every new tool must fill a gap in the chain graph; no near-duplicates of existing tools (another directory brute-forcer or subdomain tool lowers tool-selection accuracy); no exploitation frameworks (Metasploit, C2). Adding a tool touches about 13 places today: its Dockerfile and compose entry, `tool_tiers.py`, `database.py` seed, `llm_client.py` descriptions, `validators.py` dangerous flags, `tool_runner.py` timeout, `shannon_orchestrator.py` default args, `target_extractor.py`, `tool_specs.py`, `tool_decision_engine.py` chains, `semantic_router.py`, `app.py` keyword map, and three frontend files. The README's four-step checklist is out of date.

## 3. Known defects found along the way

| Defect | Status |
|---|---|
| Chain rules do not recognise masscan output (`Discovered open port 443/tcp`) | open, not fixed |
| `lm-format-enforcer` accepts trailing commas in free-form objects; rejects a string enum that includes null | worked around in `hf_server.py` |
| Ownership is not re-verified over time and has no UI | open |
| Tool arguments are not checked for extra hosts | open |
| README "adding a tool" steps are out of date | open |
