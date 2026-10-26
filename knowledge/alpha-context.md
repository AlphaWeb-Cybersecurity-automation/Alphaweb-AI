# AlphaWeb: current state

Snapshot of where the project stands. Last updated 2026-10-26. Stack and design are in `engineering.md`; the change history is in `flags.md`. Update this file whenever the state changes.

## What it is

A platform that takes a plain-language security task, lets an LLM-assisted orchestrator choose and chain containerised tools (nmap, nikto, httpx and so on), and turns the output into findings and reports. It also analyses uploaded code. The research angle: a reproducible benchmark for LLM tool orchestration in security testing, plus an authorization-gated agent, with the result that constrained decoding matters more than model size, which matters more than a cybersecurity finetune.

## Running right now (dev machine)

- Machine: Windows 11, NVIDIA RTX 5060 Laptop GPU (8 GB), 15.4 GB RAM. A separate local Postgres already owns port 5432.
- Project Postgres: Docker container `backend-db-1` on **port 5544** (set by `POSTGRES_PORT=5544` in `backend/.env`).
- Backend: uvicorn on port 8000. `/health` reports database, docker and the model layer healthy. The Layer-1 router (`gemma`) reports false because Ollama has no `qwen2.5:1.5b`; tool selection then falls back to keywords. Fix with `ollama pull qwen2.5:1.5b`, or set `GEMMA_ENABLED=false`.
- Frontend: Vite dev server on port 5173; its `/api` proxy reaches the backend.
- Layer-2 model: `unsloth/mistral-7b-instruct-v0.3-bnb-4bit`, chosen automatically by the cookbook, served by `hf_server.py` from `.venv-hf` (about 3 to 4 GB of VRAM). Starts on first use, not at backend startup.
- Other models on disk: base `unsloth/mistral-7b-v0.3-bnb-4bit` (ignored by the cookbook, it is not instruction-tuned) and Ollama's `llama3.2:3b` (unusable until llama-server is installed).

## How to run it

1. Database (once): from `backend/`, run `docker compose -f docker-compose.postgres.yml up -d` with `POSTGRES_HOST_PORT=5544`.
2. Backend: from `backend/`, run `..\.venv\Scripts\python -m uvicorn app:app --port 8000`. First start downloads the small semantic-routing model.
3. Frontend: from the project root, run `npm run dev`, then open http://localhost:5173.
4. Tool images: all 25 are built (`backend/docker-compose.tools.yml`). Rebuild one with `docker compose -f docker-compose.tools.yml build <tool>` from `backend/`.
5. Tier-2 (active) tools are refused until you verify the target domain (see `engineering.md` section 5). For lab testing on targets you do not own, set `OWNERSHIP_ENFORCEMENT=off` in `backend/.env`.
6. Cookbook report: `python -m services.system_profiler` from `backend/`, or `GET /api/system`.

## What works, with the evidence

| Area | State | Evidence |
|---|---|---|
| Backend starts on a fresh database; migrations | Works | Started against empty Postgres; legacy-table upgrade path tested separately |
| 25-tool catalog consistent (allow-list, DB seed, tiers, LLM tool list) | Works | Import-time check; `GET /tools` returns 25; DB seed upgrade from 13 rows tested |
| Tool images | All 25 build | `docker images` shows 25; `amass` and `subdominator` Dockerfiles added or rewritten, Go and Python base versions bumped |
| Real tool run through the backend | Works | `searchsploit` container ran via `POST /execute` (Tier 1, no verification needed) |
| Ownership gate | Works | Unverified Tier-2 request returns 403 with token and three methods; verify, subdomain match, per-user isolation, revoke and the off switch tested with the network checks stubbed. 35 checks passed against real Postgres |
| Schema-constrained decoding on the Hugging Face backend | Works | Fake-tool prompt never yields an off-list tool; 52-request benchmark had 0% invalid output |
| Cookbook | Works | Detected GPU and VRAM, found Ollama and cache models, rejected the base model, auto-selected the instruct model; `/api/system` returns it |
| Frontend | Builds and serves | `vite build` succeeds, dev server up, `/api` proxy reaches the backend. Not reviewed visually |
| Benchmark harness | Works | Keyword baseline with `--safety` on Postgres; LLM arms on the base Mistral |

## Benchmark results so far (exploratory, not publishable)

Single run each, 52 selection requests, **base** Mistral 7B (not instruction-tuned): constrained decoding 51.9% accuracy and 0% invalid output; JSON-mode-only 11.5% accuracy and 80.8% invalid output; keyword baseline 59.6%. A five-run comparison on the instruct model was started and interrupted; no saved results exist yet. Labels are an unreviewed draft (every record `verified: false`).

## Not verified yet

- The llama.cpp (GGUF) path: no `llama-server` binary is installed here.
- `POST /api/scan` end to end with the model in the loop, and a Tier-2 tool run in a real container.
- A real positive DNS TXT or HTTP ownership check against a domain you control (negative paths and parsing are tested).
- The UI by eye, including the CSS polish.
- The instruct model's benchmark numbers.

## Known issues

- Chain rules miss masscan output: masscan prints `Discovered open port 443/tcp`, but the check expects nmap's `443/tcp open`, so masscan never chains to nmap.
- `lm-format-enforcer` allows trailing commas in free-form objects and rejects enums mixing strings and null; `hf_server.py` works around both.
- Ownership is not re-checked over time and has no UI; it is API-only.
- Tool arguments are not scanned for extra hosts; the gate only looks at the target field.
- DNS rebinding between the safety check and the verification fetch is not fully closed.
- The Qwen Hugging Face entry in the model catalog needs 8 GB or more and is skipped on this GPU; its memory requirement is a conservative estimate, not a measurement.

## Decisions and open questions

- Postgres versus SQLite for a purely local setup: Postgres is not required locally. Switching means reworking the Postgres-only statements added for users and migrations. Not decided.
- Ollama as a model backend (plan item A2) is not built. The cookbook reuses Ollama's GGUF files through llama-server instead, which needs llama-server.
- The new-tools work (plan phase C1) is in progress; see `flags.md`.
- The target lab (D2), label review, and the five-run model comparison are the remaining benchmark work.

## Git state

Nothing from this work is committed. The last commit is the merge of PR #2. All changes are in the working tree. Planning documents were moved into `context/` and `context/build/`.
