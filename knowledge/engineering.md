# AlphaWeb engineering

What the stack is, how the pieces fit, and the rules the code follows. For the project's current status see `alpha-context.md`; for every change made so far see `flags.md`.

## 1. What is being built

AlphaWeb is a security-testing platform where a user describes a task in plain language, an LLM-assisted orchestrator picks and chains containerised security tools, and the results are turned into readable findings and reports. It also analyses uploaded code for vulnerabilities.

The design thesis, which the code is organised around: **the interface around the model matters more than the model.** Constrained decoding, deterministic parsing, enforced authorization and measurement carry the reliability; the model is a swappable component.

## 2. Stack

| Layer | Technology |
|---|---|
| Frontend | React 18, Vite 4, plain CSS with CSS-variable theming (dark and light). No UI library. VS Code-style layout. |
| Backend API | Python 3.12, FastAPI, uvicorn, Pydantic v2 |
| Persistence | PostgreSQL 16 (Docker), SQLAlchemy, psycopg2 |
| Tool execution | Docker. One image per tool in `backend/tools/<tool>/Dockerfile`, built by `backend/docker-compose.tools.yml` |
| Layer-1 router | Ollama, default `qwen2.5:1.5b` (`gemma_client.py`, `GEMMA_*` settings) |
| Layer-2 LLM | A model from `backend/model_catalog.py`, served either by llama.cpp `llama-server` (GGUF) or by `backend/hf_server.py` (Hugging Face weights) |
| HF model server | Own virtualenv `.venv-hf`: torch (cu128), transformers 4.x, bitsandbytes, lm-format-enforcer, FastAPI |
| Semantic routing | sentence-transformers `BAAI/bge-small-en-v1.5` maps phrases to tool commands |
| Reports | reportlab (PDF), JSON and HTML under `backend/logs/reports/` |
| Domain checks | dnspython (TXT lookup), tldextract (public-suffix list, bundled snapshot, no runtime fetch) |
| Code analysis | Bandit (Python), ESLint with security plugins (JS), regex rule sets (Java, PHP, Go) |

Ports: frontend 5173 (Vite proxies `/api/*` to the backend with the prefix stripped), backend 8000, model server 8081 (llama-server and `hf_server.py` use the same port and the same OpenAI-style API), Postgres 5432 by default (5544 on the dev machine, see `alpha-context.md`).

## 3. How a request flows

**Scan (`POST /api/scan`).** Validate target (SSRF guard, private ranges blocked) and rate limit. Layer 1 picks a tool, with a keyword fallback if Ollama is unavailable or unsure. The ownership gate then checks the tool's tier. The job is stored and queued; a worker runs `ShannonOrchestrator`, which executes the tool in Docker, parses findings, asks `tool_decision_engine` for a follow-up tool from the `TOOL_CHAINS` rules, and repeats up to `WORKFLOW_MAX_DEPTH`. Each step re-checks the gate, because a chain can move from a Tier-1 tool into a Tier-2 one. Anomaly detection runs at the end.

**Chat (`POST /chat/stream`).** The request names a target and a prompt. Tools come from the explicit selection, the Layer-1 router, or keyword detection. For each tool: input pre-check, ownership gate, target normalisation, semantic command selection, then a streamed container run (Server-Sent Events). Output is interpreted into facts (regex first, LLM second) and a report is saved.

**Direct execute (`POST /execute`).** Validated single tool run, same gate.

## 4. Reliability design

- **Constrained decoding.** The tool-selection call sends a JSON schema whose `tool_selected` is an enum of the real tool names plus null (`TOOL_SELECTION_SCHEMA` in `llm_client.py`). llama.cpp enforces it through grammar; `hf_server.py` enforces it with lm-format-enforcer. The model cannot emit an invalid tool name or malformed JSON for the typed fields.
- **Deterministic parsing first.** `_extract_facts_deterministic` (regex per tool) is the primary path for structured tool output. The LLM is a second pass for ambiguous or narrative output and for cross-tool summaries. This split is deliberate and is also the baseline for the LLM-versus-deterministic interpretation metric. Do not remove the regex extractors.
- **Keyword fallback.** If the LLM is unavailable, tool selection falls back to keyword matching. Do not remove it.
- **Chain rules are code, not model output.** `TOOL_CHAINS` maps a tool and a condition to the next tool, so the chain can never branch to a tool that does not exist.
- **Argument values are still validated** in `validators.py`; the grammar guarantees structure, not sane values.

## 5. Safety design

- **Single source of truth for the catalog:** `backend/tool_tiers.py` (`TOOL_TIERS`, tool name to tier). `validators.SUPPORTED_TOOLS` is derived from it, and `database.py` refuses to import if the seed data disagrees with it.
- **Tiers.** Tier 1: passive, offline, or operating on a user-supplied artifact. Tier 2: sends active traffic to a live target. Unknown tools are treated as Tier 2.
- **Identity.** `users` table; API token (stored as a SHA-256 hash) via `Authorization: Bearer` or `X-API-Key`. With no token the request runs as the built-in `default-user` unless `AUTH_REQUIRED=true`. A bad token is always rejected.
- **Ownership gate** (`services/ownership.py`). Tier-2 tools only run against a registrable domain the user verified through DNS TXT, a file at `/.well-known/alphaweb-verify.txt`, or a meta tag. Verification fetches refuse private addresses and do not follow redirects. A denial returns the token and the three methods. `OWNERSHIP_ENFORCEMENT=off` disables the gate for local lab use.
- **Existing guards stay:** blocked IP ranges and hostnames, forbidden characters in targets, dangerous-flag lists, rate limits, per-tool timeouts, container memory and CPU limits.

## 6. Model layer (the cookbook)

- `backend/model_catalog.py` is the list of supported models, in preference order. Each entry has a backend (`gguf` or `hf`), a download repo, a size and a minimum memory.
- `backend/services/system_profiler.py` detects RAM, NVIDIA GPU and VRAM, finds models already on disk (models folder, Hugging Face cache, Ollama's blob store), checks which runtimes are installed, and picks the most-preferred model that fits and can run. If none qualifies it recommends a download. Base models are never auto-picked.
- `config.resolve_llm_model` turns that choice into `BARONLLM_MODEL_PATH` (GGUF) or `LLM_HF_MODEL` (Hugging Face). Resolution order: explicit `BARONLLM_MODEL_PATH`, else `LLM_MODEL` (a catalog name or `auto`), with `LLM_HF_MODEL` able to force any Hugging Face repo.
- `BaronLLM` in `llm_client.py` lazy-loads: the model server starts on the first call that needs it and stops on `shutdown()`.
- `hf_server.py` details that matter: pre-quantised bitsandbytes checkpoints load as-is; full-precision ones are quantised to 4-bit; a windowed repetition penalty mimics llama.cpp; it blocks runs of whitespace tokens; it repairs trailing commas that lm-format-enforcer allows in free-form objects; a JSON enum containing null is rewritten to `anyOf` because lm-format-enforcer rejects the mixed form.

## 7. Evaluation harness (`eval/`)

- `make_labels.py` writes `labels.jsonl`: selection requests with `{target}` placeholders, plus chain fixtures. Every record starts `verified: false`.
- `run.py --system keyword|llm-free|llm-constrained --runs N [--safety] [--verified-only]` reports accuracy, macro-F1, invalid-output rate, chain accuracy, latency, tokens, and (with `--safety`) the false-allow rate of the real ownership gate. Each run uses a fresh random hostname and seed. Results go to `eval/results/` (git-ignored).
- The three systems are the ablation axes: keyword floor, JSON-mode only, schema-constrained.

## 8. Conventions

- Configuration is environment variables read in `backend/config.py`, with `backend/.env` for local values (git-ignored). New behaviour switches belong there.
- Setting names keep the legacy `BARONLLM_` prefix; they apply to whichever model is active.
- Repo files mostly use Windows (CRLF) line endings. Patch them in a way that preserves that.
- Prefer one source of truth over parallel lists: the tool catalog (`tool_tiers.py`), the model list (`model_catalog.py`).
- Verify against a real Postgres and real containers where possible; do not claim a change works from a compile check alone.
- Design and plan documents live in `context/`; implementation plans in `context/build/`; this folder (`knowledge/`) is the maintained summary of how things are and what changed.

## 9. Where things live

| Path | What |
|---|---|
| `backend/app.py` | API routes, scan worker, chat and execute flows |
| `backend/config.py` | All settings and model resolution |
| `backend/database.py` | Models: users, verified_domains, scan_jobs, tool_definitions, execution_logs, workflow_steps, anomalies |
| `backend/tool_tiers.py` | Tool catalog and tiers |
| `backend/validators.py` | Target and argument validation, rate limits |
| `backend/llm_client.py` | Layer-2 client, schema, server spawn |
| `backend/hf_server.py` | Hugging Face model server |
| `backend/model_catalog.py` | Model list |
| `backend/services/` | `ownership`, `system_profiler`, `shannon_orchestrator`, `tool_decision_engine`, `workflow_engine`, `anomaly_detector`, `semantic_router`, `code_analyzer`, report builders |
| `backend/tools/<tool>/` | One Dockerfile per tool |
| `frontend/` | React app (`components/` per panel) |
| `eval/` | Benchmark labels and runner |
| `context/`, `context/build/` | Background, reviews, plans |
