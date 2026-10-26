# AlphaWeb — AI-Powered Cybersecurity Automation Platform

## Overview

AlphaWeb is a web-based security automation platform combining:
- **AI-driven threat analysis** via AlphaLLM (local LLM inference)
- **Code vulnerability detection** using Bandit (Python), ESLint (JavaScript), and pattern-based rules
- **Container-orchestrated security tools** — 25 tools across recon, exploitation, fuzzing, password cracking, and vulnerability scanning
- **Interactive UI** with real-time code analysis, file upload, and terminal output streaming

---

## Architecture

```
alphaweb/
├── frontend/              # React + Vite SPA
│   ├── components/        # UI modules
│   │   ├── ActivityBar/   # Left nav (Scanner, Reporting, Orchestration)
│   │   ├── SideBar/       # File upload & explorer
│   │   ├── Editor/        # Code viewer + live analysis
│   │   ├── AgentChat/     # Right panel: AI agent chat
│   │   ├── Terminal/      # Output console
│   │   ├── StatusBar/     # Footer info
│   │   └── QuickActions/  # Fast action buttons
│   ├── App.jsx            # Main component tree
│   ├── vite.config.js     # Vite build config (port 5173)
│   └── index.html         # Entry point
│
├── backend/               # Python FastAPI + SQLAlchemy
│   ├── app.py             # Main API routes (944 lines)
│   ├── config.py          # Environment config
│   ├── database.py        # SQLAlchemy models (ScanJob, ExecutionLog, Anomaly, WorkflowStep)
│   ├── llm_client.py      # BaronLLM inference client
│   ├── tool_runner.py     # Docker-based tool executor
│   ├── validators.py      # Input validation, rate limiting
│   ├── services/
│   │   ├── code_analyzer.py    # Multi-language code vulnerability analysis
│   │   ├── workflow_engine.py  # Tool orchestration & decision trees
│   │   ├── shannon_orchestrator.py # Advanced workflow orchestration
│   │   ├── anomaly_detector.py     # Output anomaly detection
│   │   ├── execution_graph.py      # Execution tracing
│   │   └── tool_decision_engine.py # AI-driven tool selection
│   ├── tools/             # Static analysis configs
│   │   └── js/            # ESLint + security plugins
│   ├── models/            # BaronLLM .gguf file location
│   ├── data/              # Wordlists, temp files
│   ├── logs/              # Execution logs + saved reports (json/html)
│   ├── services/pdf_builder.py   # reportlab PDF report generator
│   ├── docker-compose.yml         # Full stack: Postgres + orchestrator
│   ├── docker-compose.postgres.yml # Postgres only (local dev)
│   ├── requirements.txt    # Python dependencies
│   └── Dockerfile         # Container image
│
├── package.json           # Frontend deps
├── vite.config.js         # Frontend build config
└── README.md              # This file
```

---

## Key Features

### 1. Code Analysis Engine
- **Python**: Bandit security linter
- **JavaScript**: ESLint + eslint-plugin-security + eslint-plugin-no-unsanitized
- **Java, PHP, Go**: Pattern-based regex rules (XSS, SQLi, eval, hardcoded secrets, weak crypto)
- **Real-time UI**: Upload code → editor displays content → click "Analyze" → see vulnerability highlights + panel

### 2. Multi-Tool Orchestration
- **Docker containers** for isolated tool execution
- **Per-tool timeout map**: nmap 300s, sqlmap 900s, john 3600s, etc.
- **Resource limits**: configurable memory (512m), CPU (1.0)
- **Terminal streaming**: live output to browser console

### 3. AlphaLLM Integration
- Local GGUF model inference via llama-server.exe (no external API calls)
- Numbered-fact output format — no speculation, no raw tokens
- Context-aware code analysis fallback
- Chat interface for security queries

### 4. Database Persistence
- PostgreSQL with SQLAlchemy ORM (default port 5432)
- Tables: `ScanJob`, `ExecutionLog`, `Anomaly`, `WorkflowStep`, `ToolDefinition`
- Audit trail of all scans and workflow executions
- **User-initiated reset**: `POST /database/reset` wipes scan data + saved reports, keeps tool definitions (Reset DB button in AgentChat header)

### 4b. PDF Reports
- Per-run report persisted as JSON + HTML under `logs/reports/`
- **Generate PDF**: combined PDF of every scan report via `GET /reports/pdf`, single run via `GET /report/{id}/pdf` (reportlab, no system deps)

### 5. UI Components
- **Activity Bar**: Project views (Scanner, Reporting, Orchestration)
- **SideBar**: File upload + explorer
- **Editor**: Code viewer + live line-by-line vulnerability highlighting
- **AgentChat**: AI-powered threat analysis — labels as `[AlphaLLM]`
- **Terminal**: Real-time tool output — TOOL ORCHESTRATION CONSOLE + PROBLEMS tabs
- **StatusBar**: AlphaLLM model indicator, Scan Progress bar, Tools drop-up (25 tools list)

---

## Setup Instructions

### Prerequisites
- **Node.js** 20+ (frontend build)
- **Python** 3.9+ (backend)
- **Docker** (for security tool containers)
- **Java** 8+ (PMD integration when available)
- **npm** 9+ (frontend package manager)

---

### Backend Setup

#### 1. Install Python Dependencies
```bash
cd backend
pip install -r requirements.txt
```

**Dependencies:**
- `fastapi` — Web framework
- `uvicorn[standard]` — ASGI server
- `pydantic` — Data validation
- `sqlalchemy` — ORM
- `psycopg2-binary` — PostgreSQL driver
- `reportlab` — PDF report generation
- AlphaLLM inference needs no Python package here: it talks HTTP to llama-server (GGUF) or `backend/hf_server.py` (see the cookbook section)
- `bandit` — Python security linter
- `semgrep` — SAST scanner (Windows encoding issues; pattern fallback used)

#### 2. Configure Environment Variables
Create a `.env` file or export:
```bash
# FastAPI server
ORCHESTRATOR_HOST=0.0.0.0
ORCHESTRATOR_PORT=8000

# AlphaLLM model: "auto" (default) = cookbook picks the best local model for this hardware,
# or a name from backend/model_catalog.py (qwen2.5-7b-instruct, mistral-7b-instruct-v0.3, ...)
LLM_MODEL=auto
# BARONLLM_MODEL_PATH=models/custom.gguf   # optional explicit path, overrides LLM_MODEL
BARONLLM_N_CTX=4096
BARONLLM_N_GPU_LAYERS=35
BARONLLM_TEMPERATURE=0.1
BARONLLM_CONFIDENCE_THRESHOLD=0.7

# Database (PostgreSQL — default port 5432)
# Either set DATABASE_URL directly, or the discrete POSTGRES_* vars below.
DATABASE_URL=postgresql+psycopg2://alphaweb:alphaweb@localhost:5432/alphaweb
POSTGRES_USER=alphaweb
POSTGRES_PASSWORD=alphaweb
POSTGRES_HOST=localhost
POSTGRES_PORT=5432
POSTGRES_DB=alphaweb

# Docker
DOCKER_SOCKET=unix:///var/run/docker.sock
DOCKER_MEMORY_LIMIT=512m
DOCKER_CPU_LIMIT=1.0

# Tool timeouts (seconds)
DEFAULT_TOOL_TIMEOUT=300
TOOL_EXECUTION_TIMEOUT_SECS=900

# Logging
LOG_LEVEL=INFO
LOG_DIR=./logs
```

#### 3. Start PostgreSQL + Initialize Database
PostgreSQL must be running before the backend boots (`init_db` creates tables and
seeds tool definitions on first connect).
```bash
cd backend
# Spin up Postgres only (local dev — backend runs on host)
docker compose -f docker-compose.postgres.yml up -d

# If host port 5432 is already taken (e.g. a locally-installed Postgres),
# map the container to a free host port and point the backend at it:
#   POSTGRES_HOST_PORT=5544 docker compose -f docker-compose.postgres.yml up -d
#   POSTGRES_PORT=5544 python -m uvicorn app:app --port 8000

# Tables auto-create on backend startup. To init manually:
python -c "from database import init_db; init_db()"
```

#### 4. Download AlphaLLM Model
Run the cookbook from `backend/`:

```bash
python -m services.system_profiler              # detect hardware, find local models, recommend
python -m services.system_profiler --download   # fetch the recommended GGUF into backend/models/
```

It detects RAM/GPU/VRAM, then looks for models you already have (in `backend/models/`, the Hugging Face cache, and Ollama's store, whose blobs are plain GGUFs) and uses the best one that fits. If none fits it recommends a download. The same report is at `GET /api/system`. Only GGUF files work: Hugging Face safetensors / bitsandbytes (`*-bnb-4bit`) exports are flagged as unusable. Pin a model with `LLM_MODEL=<name>`, or point `BARONLLM_MODEL_PATH` at any GGUF.

**Using a Hugging Face model instead (no llama.cpp):** set `LLM_HF_MODEL=<repo id or local dir>` in `backend/.env` (e.g. `unsloth/mistral-7b-v0.3-bnb-4bit`). The backend then starts `backend/hf_server.py` from the virtualenv at `<project root>/.venv-hf` (see `backend/requirements-hf.txt` for setup; override the interpreter with `LLM_HF_PYTHON`). It serves the same API on port 8081 with the same schema-constrained decoding, via lm-format-enforcer. Pre-quantized bitsandbytes checkpoints load as-is; full-precision ones are quantized to 4-bit on load. Base (non-instruct) models work but select tools poorly; prefer an `-Instruct` model. Also requires `binaries/llama-server.exe` in the project root. Graceful fallback to keyword-based tool selection if model unavailable.

#### 5. Start Backend
```bash
cd backend
python -m uvicorn app:app --host 0.0.0.0 --port 8000 --reload
```

Server runs on `http://localhost:8000`. Health check: `GET /health`

#### 6. Verify Services
```bash
# Check Bandit
bandit --version

# Check code analyzer
curl -X POST http://localhost:8000/analyze-code \
  -H "Content-Type: application/json" \
  -d '{"code":"eval(x)","filename":"test.py"}'
```

---

### Frontend Setup

#### 1. Install Dependencies
```bash
npm install
```

**Key Dependencies:**
- `react` 18.2.0
- `react-dom` 18.2.0
- `vite` 4.3.0 (build tool)

#### 2. Configure Vite Proxy
File: `vite.config.js`
- Frontend port: `5173`
- Backend proxy: `/api/*` → `http://localhost:8000`
- **Note**: Current proxy configuration requires backend routes WITHOUT `/api` prefix (e.g., `/analyze-code`, `/chat`, `/execute`)

#### 3. Start Dev Server
```bash
npm run dev
```

Frontend runs on `http://localhost:5173`. Vite auto-reloads on file changes.

#### 4. Build for Production
```bash
npm run build
```

Output: `dist/` directory (static SPA).

---

### Docker Setup (Security Tools)

#### 1. Verify Docker Installation
```bash
docker --version
docker ps
```

#### 2. Build Tool Images
```bash
cd backend
docker-compose -f docker-compose.tools.yml build
```

Builds all 25 tool images. Each tool has its own `Dockerfile` under `backend/tools/<toolname>/`.

#### 3. Run Tool Execution
Tools are invoked dynamically from `tool_runner.py`:
```python
from tool_runner import run_tool_sync
result = run_tool_sync(
    tool_name="nmap",
    args="-p 80,443",
    target="example.com",
    settings=settings
)
print(result.raw_output, result.exit_code)
```

**Tool Timeout Map** (in `tool_runner.py`):
```python
TOOL_TIMEOUTS = {
    "curl": 60,       "nmap": 300,      "masscan": 120,   "nikto": 600,
    "sqlmap": 900,    "ffuf": 600,      "gobuster": 600,  "hydra": 1800,
    "john": 3600,     "tcpdump": 60,    "nuclei": 600,    "hashcat": 3600,
    "gitleaks": 300,  "theharvester": 300, "sublist3r": 300, "testssl": 300,
    "wapiti": 900,    "wpscan": 600,    "cewl": 300,      "trivy": 300,
    "amass": 600,     "commix": 900,    "searchsploit": 60, "subdominator": 300,
    "httpx": 120,
}
```

**All 25 supported tools:**

| Tool | Category | Docker Image |
|------|----------|--------------|
| nmap | Port scanning / service discovery | `nmap:latest` |
| masscan | Fast mass port scanning | `masscan:latest` |
| nikto | Web server vulnerability scanning | `nikto:latest` |
| sqlmap | SQL injection testing | `sqlmap:latest` |
| ffuf | Web fuzzing / endpoint discovery | `ffuf:latest` |
| gobuster | Directory brute-forcing / DNS enum | `gobuster:latest` |
| hydra | Credential brute-forcing | `hydra:latest` |
| john | Password hash cracking | `john:latest` |
| curl | HTTP requests / API testing | `curl:latest` |
| tcpdump | Network packet capture | `tcpdump:latest` |
| nuclei | Template-based vuln scanning | `nuclei:latest` |
| hashcat | GPU-accelerated hash cracking | `hashcat:latest` |
| gitleaks | Git secret scanning | `gitleaks:latest` |
| theharvester | OSINT email/subdomain harvesting | `theharvester:latest` |
| sublist3r | Passive subdomain enumeration | `sublist3r:latest` |
| testssl | TLS/SSL configuration auditing | `testssl:latest` |
| wapiti | Web application vulnerability scanner | `wapiti:latest` |
| wpscan | WordPress vulnerability scanner | `wpscan:latest` |
| cewl | Custom wordlist generator | `cewl:latest` |
| trivy | Container / filesystem vuln scanner | `trivy:latest` |
| amass | DNS enumeration / asset discovery | `amass:latest` |
| commix | Command injection detection | `commix:latest` |
| searchsploit | Offline exploit DB search | `searchsploit:latest` |
| subdominator | Subdomain takeover detection | `subdominator:latest` |
| httpx | HTTP probing / web fingerprinting | `httpx:latest` |

**Notes:**
- `masscan` requires resolved IP (not hostname) — tool_runner resolves via nmap
- `gobuster` uses built-in wordlist at `/wordlists/common.txt` inside container
- `ffuf` accepts wordlist via stdin (`/dev/stdin`)
- `hydra` uses URI format: `https-get://target/`
- `testssl` image cloned from GitHub (includes required `/opt/testssl/etc/` data files)
- `commix` image cloned from GitHub (`python3 /opt/commix/commix.py`)

---

## Running the Full Stack

### Terminal 1: Backend
```bash
cd backend
# Postgres must be up first (default localhost:5432)
docker compose -f docker-compose.postgres.yml up -d
python -m uvicorn app:app --host 0.0.0.0 --port 8000 --reload
```

> Or run the whole backend stack (Postgres + orchestrator) in containers:
> `cd backend && docker compose up`

### Terminal 2: Frontend
```bash
npm run dev
```

### Terminal 3: Docker (if running tools)
```bash
cd backend
docker-compose -f docker-compose.tools.yml up
```

### Access
- **Frontend**: `http://localhost:5173`
- **Backend API**: `http://localhost:8000`
- **API Docs**: `http://localhost:8000/docs`

---

## API Endpoints

### Code Analysis
```bash
POST /analyze-code
Content-Type: application/json

{
  "code": "eval(userInput)",
  "language": "javascript",
  "filename": "app.js"
}

Response:
{
  "analysis_id": "uuid",
  "language": "javascript",
  "total_vulnerabilities": 2,
  "critical": 0, "high": 1, "medium": 1, "low": 0,
  "vulnerabilities": [
    {
      "type": "eval_injection",
      "severity": "high",
      "line": 1,
      "code_snippet": "eval(userInput)",
      "issue": "eval() executes arbitrary code...",
      "fix": "Use JSON.parse() for data or refactor...",
      "cwe": "CWE-95"
    }
  ]
}
```

### Scan Creation
```bash
POST /api/scan
{
  "target": "example.com",
  "tool": "nmap",
  "parameters": "-p 80,443,8000-9000"
}
```

### Chat (AI Analysis)
```bash
POST /api/chat
{
  "prompt": "scan for open ports",
  "domain": "example.com"
}
```

### Tool Execution
```bash
POST /execute
{
  "tool_name": "nmap",
  "args": "-sV -p 80,443",
  "target": "example.com"
}
```

### Health Check
```bash
GET /health
Response: {
  "status": "healthy",
  "components": {
    "baronllm": true,
    "database": true,
    "docker": true
  }
}
```

### Reports (PDF / HTML)
```bash
GET /report/{run_id}            # view rendered HTML report
GET /report/{run_id}/download   # download HTML
GET /report/{run_id}/pdf        # download single-run PDF
GET /reports/pdf                # combined PDF of ALL scan reports
GET /reports/pdf?run_ids=a,b,c  # combined PDF of a subset
```

### Database Reset (user-initiated)
```bash
POST /database/reset
Response: {
  "reset": true,
  "deleted": { "scan_jobs": 12, "execution_logs": 40, "workflow_steps": 18, "anomalies": 5 },
  "reports_deleted": 12
}
# Wipes scan data + saved reports. Keeps seeded tool_definitions.
```

---

## Code Analysis Details

### Supported Languages
- **Python**: Bandit (SAST) + pattern rules (supplement)
- **JavaScript**: ESLint + security plugins (primary) + pattern rules (supplement)
- **Java**: Pattern rules (XSS, SQLi, eval, deserialization, hardcoded secrets, weak crypto)
- **PHP**: Pattern rules (eval, unvalidated input, SQLi, XSS, command injection, weak hash)
- **Go**: Pattern rules (command injection, SQLi, hardcoded secrets, TLS bypass, weak random)

### Analysis Chain
1. **Python**: Bandit JSON output → CWE mapping + fix text
2. **JavaScript**: ESLint (`eslint-plugin-security`) + rules deduplication
3. **Others**: Regex pattern matching with CWE/severity/fix metadata

### ESLint Configuration
Location: `backend/tools/js/.eslintrc.json`
```json
{
  "plugins": ["security", "no-unsanitized"],
  "rules": {
    "security/detect-eval-with-expression": "error",
    "security/detect-child-process": "error",
    "no-unsanitized/method": "error",
    "no-eval": "error",
    ...
  }
}
```

---

## Project Structure Reference

### Frontend Components

| Component | Purpose | Key State |
|-----------|---------|-----------|
| `ActivityBar` | Left nav tabs | activeView (scanner/reporting/orchestration) |
| `SideBar` | File explorer + upload | files[], dragging, domain input |
| `Editor` | Code viewer + analysis | activeFile, openFiles[], vulnLines |
| `AgentChat` | AI security chat | messages[], domain, input, loading |
| `Terminal` | Tool output console | logs[], clearKey, maximized |
| `StatusBar` | Footer metrics | activeFile, AlphaLLM status, Scan Progress, Tools drop-up |

### Backend Services

| Service | Purpose | Key Functions |
|---------|---------|---|
| `code_analyzer.py` | Multi-language SAST | analyze(), run_eslint(), run_bandit(), run_pattern_analysis() |
| `workflow_engine.py` | Tool orchestration | build execution DAG, multi-step workflows |
| `shannon_orchestrator.py` | Advanced workflow | confidence scoring, anomaly detection |
| `tool_decision_engine.py` | AI tool selection | LLM-guided tool picking |
| `anomaly_detector.py` | Output anomalies | Parse & flag suspicious results |

---

## Database Schema

### ScanJob
```
id (PK)
task_id (unique)
status (pending/running/completed/failed)
tool_selected (str)
target (str)
created_at (timestamp)
completed_at (timestamp)
result (JSON)
```

### ExecutionLog
```
id (PK)
scan_id (FK)
execution_order (int)
tool_name (str)
command_line (str)
raw_output (text)
exit_code (int)
execution_time (float)
timestamp (timestamp)
```

### Anomaly
```
id (PK)
scan_id (FK)
severity (critical/high/medium/low)
anomaly_type (str)
description (text)
detected_at (timestamp)
```

### WorkflowStep
```
id (PK)
scan_id (FK)
step_id (unique)
parent_step_id (FK)
execution_order (int)
tool_name (str)
parameters (JSON)
findings (JSON)
execution_time (float)
status (pending/completed/failed)
```

---

## Debugging & Troubleshooting

### Backend Won't Start
```bash
# Check Python version
python --version  # Must be 3.9+

# Check port in use
lsof -i :8000

# Rebuild dependencies
pip install --upgrade --force-reinstall -r requirements.txt
```

### Frontend Build Errors
```bash
# Clear node_modules and reinstall
rm -rf node_modules package-lock.json
npm install

# Check Node version
node --version  # Must be 20+
```

### Code Analysis Not Working
```bash
# Check Bandit installed
pip install bandit

# Check ESLint installed
cd backend/tools/js && npm install --legacy-peer-deps

# Test manually
python -c "from services.code_analyzer import analyze; print(analyze('eval(x)', None, 'test.py'))"
```

### Docker Tools Not Running
```bash
# Check Docker daemon
docker ps

# Build images
cd backend && docker-compose -f docker-compose.tools.yml build

# Run single tool test
docker run --rm <tool-image> --help
```

### Database Reset / Wipe
```bash
# Wipe scan data + reports via the API (keeps tool definitions)
curl -X POST http://localhost:8000/database/reset

# Or nuke the Postgres volume for a total clean slate, then restart
cd backend
docker compose -f docker-compose.postgres.yml down -v
docker compose -f docker-compose.postgres.yml up -d
```

### Cannot connect to database
```bash
# Confirm Postgres is up and listening on 5432
cd backend && docker compose -f docker-compose.postgres.yml ps
# Check DATABASE_URL matches POSTGRES_* creds (default alphaweb/alphaweb)
```

---

## Environment Variables Summary

| Variable | Default | Purpose |
|----------|---------|---------|
| `ORCHESTRATOR_HOST` | 0.0.0.0 | FastAPI bind address |
| `ORCHESTRATOR_PORT` | 8000 | FastAPI port |
| `LLM_MODEL` | auto | `auto` (cookbook picks from local models) or a name in `backend/model_catalog.py` |
| `LLM_MODELS_DIR` | models | Directory holding GGUF files (cookbook also checks the HF cache and Ollama) |
| `BARONLLM_MODEL_PATH` | (derived from `LLM_MODEL`) | Explicit GGUF path; overrides `LLM_MODEL` |
| `DATABASE_URL` | postgresql+psycopg2://alphaweb:alphaweb@localhost:5432/alphaweb | SQLAlchemy connection string |
| `POSTGRES_USER` / `POSTGRES_PASSWORD` | alphaweb / alphaweb | DB credentials (used to build DATABASE_URL) |
| `POSTGRES_HOST` / `POSTGRES_PORT` / `POSTGRES_DB` | localhost / 5432 / alphaweb | DB host, port, name |
| `DOCKER_SOCKET` | unix:///var/run/docker.sock | Docker daemon socket |
| `DOCKER_MEMORY_LIMIT` | 512m | Container memory limit |
| `DOCKER_CPU_LIMIT` | 1.0 | Container CPU limit |
| `TOOL_EXECUTION_TIMEOUT_SECS` | 900 | Global tool timeout override |
| `LOG_LEVEL` | INFO | Python logging level |

---

## Performance Tuning

### Code Analysis Optimization
- ESLint rule checks run in parallel for JS files
- Pattern analysis uses compiled regex (fast)
- Python Bandit runs in subprocess (isolated)

### Docker Tool Optimization
- Resource limits prevent runaway processes
- Per-tool timeout map prevents hanging
- No tool output retries (timeout = failed)

### Database Optimization
- PostgreSQL — handles concurrent scans without write-lock contention
- Add indexes on `scan_id`, `status` columns for large datasets
- Connection pooling via SQLAlchemy engine (default pool)

---

## Development Workflow

### Adding a New Security Tool
1. Build/pull Docker image
2. Update `TOOL_TIMEOUTS` in `tool_runner.py`
3. Register in `SUPPORTED_TOOLS` list in `validators.py`
4. Test: `run_tool_sync(tool_name="...", args="...", target="...", settings=settings)`

### Adding a New Code Analysis Rule
1. Add regex pattern to `PATTERN_RULES[language]` in `services/code_analyzer.py`
2. Include: pattern, type, severity, issue, fix, CWE
3. Test: `run_pattern_analysis(code, language)`

### Adding UI Feature
1. Create component in `frontend/components/`
2. Import in `frontend/App.jsx`
3. Pass props & callbacks
4. Style with CSS (follow `--bg-*`, `--text-*` variables)

---

## Technologies

### Frontend
- **React** 18.2 — UI framework
- **Vite** 4.3 — Build tool & dev server
- **CSS3** — Styling (CSS variables, Grid, Flexbox)

### Backend
- **FastAPI** — Web framework (async)
- **SQLAlchemy** — ORM
- **PostgreSQL** + **psycopg2** — Persistent storage
- **reportlab** — PDF report generation
- **Uvicorn** — ASGI server
- **Pydantic** — Data validation
- **llama-cpp-python** + **llama-server.exe** — Local AlphaLLM inference

### Security Analysis
- **Bandit** — Python SAST
- **ESLint** + plugins — JavaScript linter
- **Regex patterns** — Fallback for Java, PHP, Go
- **Docker** — Tool isolation

### Database
- **PostgreSQL 16** — primary store (Docker, default port 5432)
- **SQLAlchemy** — ORM / engine abstraction

---

## License & Contact

Project: AlphaWeb v0.1.0  
Author: flexsyyy  
Last Updated: 2026-04-26

---

## Quick Start (TL;DR)

```bash
# Backend
cd backend
pip install -r requirements.txt
pip install bandit
docker compose -f docker-compose.postgres.yml up -d   # Postgres on :5432
python -m uvicorn app:app --host 0.0.0.0 --port 8000

# Frontend (new terminal)
npm install
npm run dev

# Visit
# http://localhost:5173
```

Upload a Python/JS file → Click "Analyze" → See vulnerabilities with line numbers, CWE codes, and actionable fixes.
