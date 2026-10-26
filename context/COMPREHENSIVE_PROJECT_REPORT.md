# AlphaWeb: Comprehensive Project Report
**AI-Powered Cybersecurity Automation Platform**

---

## 1. Abstract

AlphaWeb is a full-stack web-based security automation platform that combines artificial intelligence-driven threat analysis, real-time code vulnerability detection, and container-orchestrated security tool execution. The platform leverages BaronLLM (local inference) for context-aware analysis, integrates industry-standard security scanners (nmap, sqlmap, nikto, ffuf, gobuster, john, hydra), and provides an interactive IDE-like user interface for security professionals. The backend (Python FastAPI, 2,268 LOC) implements multi-step workflow orchestration using the Shannon Orchestrator pattern, enabling intelligent tool chaining and anomaly detection. The frontend (React 18.2, 1,314 LOC) provides real-time code analysis with line-by-line vulnerability highlighting, file exploration, terminal output streaming, and AI-powered threat chat. The system uses SQLite (PostgreSQL-ready) for persistent storage of scans, execution logs, anomalies, and workflow traces. Unique capabilities include per-tool timeout management, Docker-isolated execution, multi-language code analysis (Python, JavaScript, Java, PHP, Go), and feedback-driven anomaly detection. The platform targets security professionals, penetration testers, and DevSecOps engineers seeking a unified, locally-controlled alternative to cloud-based SaaS security tools.

---

## 2. Project Overview

### 2.1 Project Identity
- **Name**: AlphaWeb
- **Version**: 0.1.0
- **Author**: flexsyyy
- **Last Updated**: 2026-04-19
- **Repository Type**: Git-based (main branch)
- **Project Status**: Active Development

### 2.2 Core Problem Statement
Modern security teams face fragmented toolchains: separate tools for code analysis, vulnerability scanning, orchestration, and reporting. Cloud-based SaaS solutions present privacy/control concerns. AlphaWeb unifies these capabilities in a locally-run, self-contained platform with AI-assisted threat analysis.

### 2.3 Solution Overview
Single unified platform providing:
- Real-time code vulnerability analysis (5 languages)
- Multi-step intelligent tool orchestration
- Local LLM-powered threat analysis (no external APIs)
- Interactive IDE-like workflow environment
- Database-persisted audit trails and findings

### 2.4 Target Users
- Penetration testers (manual security assessments)
- DevSecOps engineers (CI/CD security integration)
- Security researchers (tool experimentation)
- CTF participants (rapid exploitation/analysis)
- Enterprise security teams (internal deployments)

---

## 3. Technical Architecture

### 3.1 High-Level System Design

```
┌─────────────────────────────────────────────────────────────┐
│                         USER INTERFACE                       │
│         React 18.2 (Vite) → Port 5173                        │
│  ┌──────────┬───────────┬──────────┬──────────┬─────────┐   │
│  │Activity  │ SideBar   │ Editor   │Agent     │Terminal │   │
│  │Bar       │ (Upload)  │ (Code)   │Chat (AI) │ (Output)│   │
│  │(Nav)     │ (Explorer)│ (Analysis)│         │         │   │
│  └──────────┴───────────┴──────────┴──────────┴─────────┘   │
└────────────────────────────┬────────────────────────────────┘
                            │ HTTP/WebSocket
                            ▼
┌─────────────────────────────────────────────────────────────┐
│               BACKEND API ORCHESTRATION                      │
│              FastAPI + Uvicorn → Port 8000                   │
│  ┌─────────────────────────────────────────────────────────┐ │
│  │ 1. Request Validation & Rate Limiting (validators.py)  │ │
│  │ 2. Code Analysis Engine (code_analyzer.py)             │ │
│  │ 3. Shannon Orchestrator (multi-step workflow)          │ │
│  │ 4. Tool Decision Engine (LLM-guided tool selection)    │ │
│  │ 5. Workflow Engine (DAG execution + persistence)       │ │
│  │ 6. Anomaly Detection (output analysis)                 │ │
│  │ 7. Tool Runner (Docker-isolated execution)            │ │
│  └─────────────────────────────────────────────────────────┘ │
└────────────────┬─────────────────────────────┬────────────┘
                 ▼                             ▼
        ┌──────────────────┐        ┌──────────────────┐
        │   Database       │        │   Docker         │
        │   (SQLite/PG)    │        │   Container      │
        │                  │        │   Runtime        │
        │ • ScanJob        │        │                  │
        │ • ExecutionLog   │        │ • nmap, sqlmap  │
        │ • Anomaly        │        │ • nikto, ffuf    │
        │ • WorkflowStep   │        │ • gobuster, john │
        │                  │        │ • hydra, etc.    │
        └──────────────────┘        └──────────────────┘
```

### 3.2 Execution Flow: From Request to Findings

```
1. User Action (SPA)
   ↓
2. HTTP Request to Backend API
   ├─ Code Upload → /analyze-code (static analysis)
   ├─ Scan Request → /api/scan (network/tool execution)
   └─ Chat Query → /api/chat (LLM-powered analysis)
   ↓
3. Backend Processing
   ├─ Rate Limit Check
   ├─ Input Validation
   ├─ Code Analysis (if applicable)
   └─ Scan Job Creation (async queue)
   ↓
4. Background Scan Worker (_process_scan)
   ├─ Initialize ScanJob in database
   ├─ Shannon Orchestrator.run_workflow()
   │  ├─ ExecutionGraph: Track depth/width limits
   │  ├─ Tool Selection: BaronLLM picks initial tool
   │  ├─ Tool Execution Loop (max_tools constraint)
   │  │  ├─ run_tool() → Docker container
   │  │  ├─ Parse output → findings
   │  │  ├─ Tool Decision Engine picks next tool
   │  │  └─ Store WorkflowStep in DB
   │  └─ Anomaly Detection: Post-processing analysis
   └─ Record execution metrics, store results
   ↓
5. Frontend Real-Time Updates
   ├─ Terminal logs stream (WebSocket)
   ├─ Scan status polling
   └─ Final findings display
```

### 3.3 Component Interaction Diagram

```
App (React)
├─ ActivityBar → View selection (Scanner/Reporting/Orchestration)
├─ SideBar → File upload, explorer, domain input
├─ Editor → Code display, line-by-line vulnerability highlighting
│   └─ calls /analyze-code (backend code_analyzer)
├─ AgentChat → Chat interface, queries BaronLLM
│   └─ calls /api/chat (backend llm_client)
├─ Terminal → Live scan output logging
│   └─ subscribes to scan results
└─ StatusBar → Footer metrics, current file info

Backend (FastAPI)
├─ app.py (main router, 1,044 LOC)
│   ├─ /health → system status
│   ├─ /analyze-code → code_analyzer.analyze()
│   ├─ /api/scan → create ScanJob, enqueue
│   ├─ /api/scans → list/filter scans
│   ├─ /api/scans/{id} → detailed scan results
│   ├─ /api/chat → llm_client.chat()
│   ├─ /execute → tool_runner.run_tool()
│   └─ WebSocket handlers (future: live updates)
│
├─ Services layer
│   ├─ shannon_orchestrator.py (multi-step workflow)
│   ├─ workflow_engine.py (DAG construction & storage)
│   ├─ tool_decision_engine.py (LLM-guided next tool)
│   ├─ anomaly_detector.py (output analysis)
│   ├─ code_analyzer.py (multi-language SAST)
│   └─ execution_graph.py (depth/width tracking)
│
├─ Infrastructure
│   ├─ database.py (SQLAlchemy ORM, 156 LOC)
│   ├─ llm_client.py (BaronLLM interface, 349 LOC)
│   ├─ tool_runner.py (Docker executor, 283 LOC)
│   ├─ validators.py (input/rate limit, 353 LOC)
│   └─ config.py (env vars, 83 LOC)
```

---

## 4. Technology Stack

### 4.1 Frontend

| Layer | Technology | Version | Purpose |
|-------|-----------|---------|---------|
| Framework | React | 18.2.0 | UI component system |
| Build Tool | Vite | 4.3.0 | Fast dev server & bundler |
| Language | JavaScript (ES6+) | - | Component logic |
| Styling | CSS3 (Variables, Grid, Flexbox) | - | Layout & theming |
| Package Manager | npm | 9+ | Dependency management |

**Frontend Metrics:**
- Total Lines: 1,314 (components + main app)
- Component Count: 6 major UI modules
- Port: 5173 (dev), compiled to /dist for production

### 4.2 Backend

| Layer | Technology | Version | Purpose |
|-------|-----------|---------|---------|
| Framework | FastAPI | Latest | Async web framework (ASGI) |
| Server | Uvicorn | Standard | ASGI server |
| Language | Python | 3.9+ | Service logic |
| Database ORM | SQLAlchemy | Latest | Data model abstraction |
| Data Validation | Pydantic | Latest | Request/response schema validation |
| LLM Inference | llama-cpp-python | Latest | BaronLLM GGUF loading |
| Code Analysis | Bandit | Latest | Python security linter |
| Task Queue | asyncio.Queue | Built-in | Background scan worker |

**Backend Metrics:**
- Total Lines: 2,268 (excluding node_modules)
- Core Application: 1,044 lines (app.py)
- Services: 6 specialized modules
- Port: 8000 (dev), configurable via env
- Async Architecture: Fully async request handling + background workers

### 4.3 Infrastructure & Tools

| Component | Technology | Purpose |
|-----------|-----------|---------|
| Security Tools | nmap, sqlmap, nikto, ffuf, gobuster, john, hydra, curl, tcpdump, gitleaks, nuclei | Isolated tool execution |
| Container Runtime | Docker | Tool isolation, resource limits |
| Database | SQLite (dev), PostgreSQL (prod ready) | Persistent storage |
| Code Analysis | Bandit (Python), ESLint + plugins (JS), Regex patterns (Java/PHP/Go) | Multi-language SAST |
| LLM Model | BaronLLM (GGUF) | Local inference, no external APIs |

---

## 5. Key Features & Capabilities

### 5.1 Code Vulnerability Analysis

**Supported Languages:**
- Python: Bandit (primary) + pattern rules (fallback)
- JavaScript: ESLint + security plugins (primary) + pattern rules (fallback)
- Java, PHP, Go: Pattern-based regex rules (primary)

**Vulnerability Categories:**
- Code Injection (eval, exec, command injection)
- SQL Injection (dynamic query construction)
- Cross-Site Scripting (XSS, unsanitized output)
- Unsafe Deserialization (pickle, marshal, yaml.load)
- Hardcoded Secrets (passwords, API keys, tokens)
- Weak Cryptography (MD5, SHA1, insecure ciphers)
- Insecure File Permissions
- Unsafe TLS/SSL Configuration
- Unsafe Process Execution

**Output Details:**
Each vulnerability includes:
- Type & CWE identifier
- Severity (critical/high/medium/low)
- Line number & code snippet
- Issue description
- Actionable fix recommendation

### 5.2 Multi-Tool Orchestration

**Orchestration Pattern: Shannon Orchestrator**
- Initial tool selected via BaronLLM or user choice
- Execution DAG tracks depth (max 5 levels) and width (max 10 tools)
- After each tool, Tool Decision Engine selects next tool(s)
- Parallel execution capability (WorkflowStep parent_step_id)
- Anomaly detection runs post-workflow

**Tool Timeout Mapping:**
```
curl: 60s        | nikto: 600s        | john: 3600s
nmap: 300s       | ffuf: 600s         | gitleaks: 300s
masscan: 120s    | gobuster: 600s     | hashcat: 3600s
sqlmap: 900s     | hydra: 1800s       | nuclei: 600s
tcpdump: 60s     |                    |
```

**Resource Constraints (per container):**
- Memory: 512 MB (configurable)
- CPU: 1.0 cores (configurable)
- I/O: Unlimited
- Network: Unrestricted (user responsibility)

### 5.3 BaronLLM Integration

**Capabilities:**
- Context-aware security analysis
- Natural language threat interpretation
- Code review assistance
- Vulnerability prioritization
- Next-tool decision making

**Implementation:**
- Runs locally (no external API calls)
- GGUF model loaded via llama-cpp-python
- Configurable context window (default 4096 tokens)
- GPU acceleration (35 GPU layers)
- Temperature: 0.1 (deterministic responses)

**Fallbacks:**
- If model unavailable: regex patterns for code analysis
- If inference fails: basic tool runner execution

### 5.4 Database Persistence & Audit Trail

**Tables:**

1. **ScanJob** (audit trail for each scan)
   ```
   id, task_id (unique), status, tool_selected,
   target, user_id, created_at, started_at, completed_at,
   execution_time, exit_code, raw_output, findings (JSON),
   error_message
   ```

2. **ExecutionLog** (per-tool execution details)
   ```
   id, scan_id (FK), execution_order, tool_name,
   command_line, raw_output, exit_code, execution_time, timestamp
   ```

3. **Anomaly** (detected anomalies in scan results)
   ```
   id, scan_id (FK), severity, anomaly_type,
   description, detected_at
   ```

4. **WorkflowStep** (multi-step workflow tracking)
   ```
   id, scan_id (FK), step_id (unique), parent_step_id (FK),
   execution_order, tool_name, parameters (JSON),
   findings (JSON), execution_time, status, error_message,
   created_at, completed_at
   ```

**Query Capabilities:**
- Filter scans by status, tool, target, date range
- Retrieve full workflow DAG (parent-child relationships)
- Anomaly analysis across scan results
- Execution metrics (timing, resource usage)

### 5.5 Real-Time Interactive UI

**Components:**

| Component | Function | Key State |
|-----------|----------|-----------|
| ActivityBar | Left navigation (Scanner/Reporting/Orchestration views) | activeView |
| SideBar | File upload, explorer tree, domain input field | files[], uploading, domain |
| Editor | Code viewer with syntax highlighting, line-by-line vuln highlighting | openFiles[], activeFile, vulnLines[] |
| AgentChat | AI-powered security chat, retro phosphor theme | messages[], input, loading |
| Terminal | Real-time scan output, log streaming, maximize/minimize | logs[], maximized, clearKey |
| StatusBar | Footer: file info, line/col position, AI status, metrics | currentFile, position, scanStatus |
| QuickActions | Fast action buttons (new scan, analyze, clear, etc.) | - |

**Interaction Model:**
- Tab-based multi-file editing
- Click to analyze → immediate feedback
- Terminal auto-scrolls with scan output
- Toast notifications for user actions
- Responsive grid layout (activity bar + sidebar + editor + chat + terminal)

---

## 6. Backend Services Architecture

### 6.1 Shannon Orchestrator (`shannon_orchestrator.py`)

**Responsibility:** Multi-step workflow orchestration with intelligence.

**Key Methods:**
```python
async run_workflow(
    scan_id: str,
    target: str,
    initial_tool: str,
    initial_params: Dict,
    initial_confidence: float
) → Dict[str, Any]
```

**Algorithm:**
1. Create ExecutionGraph (tracks depth/width)
2. Create WorkflowEngine (DAG storage)
3. Execute initial tool
4. Loop: Tool Decision Engine picks next tool(s)
5. Execute each tool (Docker container)
6. Check anomalies post-execution
7. Save workflow steps & anomalies to DB
8. Return summary (findings + metrics)

**Fallback Strategy:**
- If multi-step fails → run single tool only
- If tool fails → skip, continue with next
- If all fail → return error status

### 6.2 Code Analyzer (`code_analyzer.py`)

**Responsibility:** Multi-language static application security testing (SAST).

**Entry Point:**
```python
def analyze(code: str, language: Optional[str], filename: str) -> Dict
```

**Analysis Chain:**
1. Language detection (extension → keyword matching)
2. Language-specific analyzer selection
3. Multi-pass analysis:
   - Primary tool (Bandit for Python, ESLint for JS)
   - Pattern-based fallback rules
   - Deduplication & CWE mapping
4. Return sorted list of vulnerabilities

**Bandit Integration (Python):**
- Runs in subprocess
- Parses JSON output
- Maps test IDs to fix text via BANDIT_FIX_MAP

**ESLint Integration (JavaScript):**
- Located at `backend/tools/js/.eslintrc.json`
- Plugins: security, no-unsanitized
- Rules: eval detection, child process, DOM unsanitized methods

**Pattern Rules (Java/PHP/Go):**
- Hardcoded regex patterns with metadata (severity, CWE, fix)
- Examples: eval detection, SQL injection patterns, hardcoded secrets

### 6.3 Tool Decision Engine (`tool_decision_engine.py`)

**Responsibility:** AI-guided selection of next tool(s) in the workflow.

**Key Function:**
```python
async decide_next_tools(
    scan_id: str,
    target: str,
    current_tool: str,
    current_findings: Dict,
    parent_confidence: float,
    settings: Settings
) → List[Tuple[str, Dict, float]]
```

**Logic:**
1. Analyze current findings (what did we learn?)
2. Query BaronLLM: "What tool should run next?"
3. Return list of (tool_name, parameters, confidence)
4. Chain executes if confidence > threshold

**Example Decision Chain:**
```
User input: "scan example.com"
1. Initial: nmap -p- (host discovery)
   → Finds open ports 22, 80, 443
2. Decision: sqlmap (port 80 likely web)
   → Finds SQL injection vulnerability
3. Decision: nikto (port 443 SSL scan)
   → Finds outdated SSL config
4. Decision: ffuf (directory enumeration)
   → Finds admin endpoints
5. Confidence drops below threshold → Stop
```

### 6.4 Workflow Engine (`workflow_engine.py`)

**Responsibility:** DAG construction, persistence, anomaly storage.

**Key Methods:**
```python
create_step(tool_name, confidence, params) → step_id
save_step(step_id, findings, execution_time, status)
get_workflow_summary() → Dict (with steps + anomalies)
save_anomalies(anomalies: List[Dict])
```

**Data Model:**
- Tree structure: parent_step_id links steps
- Parallel execution: multiple steps can share same parent
- Storage: WorkflowStep table in DB

### 6.5 Anomaly Detector (`anomaly_detector.py`)

**Responsibility:** Post-processing analysis of workflow outputs.

**Detection Types:**
- Output encoding anomalies (binary vs expected text)
- Suspicious error patterns (auth bypasses, XXE, etc.)
- Size anomalies (unusually large/small output)
- Pattern matching (known vuln signatures)
- Timing anomalies (unexpectedly fast/slow)

**Output:**
```python
detect_anomalies(steps: List[WorkflowStep]) → List[Anomaly]
```

Returns severity (critical/high/medium/low) + description + suggestion.

### 6.6 Execution Graph (`execution_graph.py`)

**Responsibility:** Track workflow constraints (depth, width, cycles).

**Key Methods:**
```python
can_add(tool_name, params, parent_step_id) → Tuple[bool, str]
add(tool_name, params, parent_step_id)
```

**Constraints:**
- max_depth: 5 (prevent infinite loops)
- max_tools: 10 (prevent resource exhaustion)
- Cycle detection: Prevent same tool+params from running twice

---

## 7. API Specification

### 7.1 Code Analysis Endpoint

**Request:**
```http
POST /analyze-code
Content-Type: application/json

{
  "code": "eval(userInput)",
  "language": "javascript",
  "filename": "app.js"
}
```

**Response:**
```json
{
  "analysis_id": "550e8400-e29b-41d4-a716-446655440000",
  "language": "javascript",
  "vulnerabilities": [
    {
      "type": "eval_injection",
      "severity": "high",
      "line": 1,
      "code_snippet": "eval(userInput)",
      "issue": "eval() executes arbitrary code with access to local scope",
      "fix": "Use JSON.parse() for data parsing or refactor to avoid dynamic execution",
      "cwe": "CWE-95"
    }
  ],
  "total_vulnerabilities": 1,
  "critical": 0,
  "high": 1,
  "medium": 0,
  "low": 0
}
```

### 7.2 Scan Creation Endpoint

**Request:**
```http
POST /api/scan
Content-Type: application/json

{
  "target": "example.com",
  "tool": "nmap",
  "parameters": "-p 80,443,8000-9000"
}
```

**Response:**
```json
{
  "scan_id": "550e8400-e29b-41d4-a716-446655440001",
  "status": "pending",
  "tool_selected": "nmap",
  "target": "example.com",
  "created_at": "2026-04-19T14:30:00Z"
}
```

**Processing:**
- Enqueues job to background worker
- Returns immediately with scan_id
- User polls `/api/scans/{scan_id}` for results

### 7.3 Scan Details Endpoint

**Request:**
```http
GET /api/scans/{scan_id}
```

**Response:**
```json
{
  "scan_id": "550e8400-e29b-41d4-a716-446655440001",
  "status": "completed",
  "tool_used": "nmap",
  "target": "example.com",
  "findings": [
    {
      "port": 80,
      "state": "open",
      "service": "http",
      "version": "Apache httpd 2.4.41"
    }
  ],
  "workflow": [
    {
      "step_id": "step-001",
      "tool_name": "nmap",
      "status": "completed",
      "findings": [...],
      "execution_time": 5.23
    },
    {
      "step_id": "step-002",
      "parent_step_id": "step-001",
      "tool_name": "nikto",
      "status": "completed",
      "findings": [...],
      "execution_time": 12.45
    }
  ],
  "anomalies": [
    {
      "id": "anom-001",
      "type": "suspicious_response",
      "severity": "medium",
      "details": {...}
    }
  ],
  "execution_time": 18.2,
  "created_at": "2026-04-19T14:30:00Z",
  "completed_at": "2026-04-19T14:30:18Z"
}
```

### 7.4 Chat Endpoint (AI Analysis)

**Request:**
```http
POST /api/chat
Content-Type: application/json

{
  "prompt": "What does this scan finding mean?",
  "domain": "example.com",
  "context": {...}  // optional: previous scan results
}
```

**Response:**
```json
{
  "response": "The open port 80 suggests the target is running a web server...",
  "confidence": 0.92,
  "recommendations": [...]
}
```

### 7.5 Health Check Endpoint

**Request:**
```http
GET /health
```

**Response:**
```json
{
  "status": "healthy",
  "timestamp": "2026-04-19T14:30:00Z",
  "components": {
    "baronllm": true,
    "database": true,
    "docker": true
  }
}
```

### 7.6 Tool Execution Endpoint

**Request:**
```http
POST /execute
Content-Type: application/json

{
  "tool_name": "nmap",
  "args": "-sV -p 80,443",
  "target": "example.com"
}
```

**Response:**
```json
{
  "scan_id": "550e8400-e29b-41d4-a716-446655440002",
  "raw_output": "...",
  "exit_code": 0,
  "execution_time": 5.23
}
```

---

## 8. Database Schema & Persistence

### 8.1 ScanJob Table

**Purpose:** Audit trail of all scans initiated.

**Fields:**
| Field | Type | Notes |
|-------|------|-------|
| id | UUID (PK) | Auto-generated |
| task_id | String (unique) | User-friendly scan ID |
| status | Enum | pending, running, completed, failed, timeout |
| tool_name | String | Primary tool selected |
| target | String | Scan target (domain/IP/host) |
| user_id | String | User initiating scan (nullable) |
| parameters | Text/JSON | Tool parameters (stringified) |
| findings | Text/JSON | Parsed findings from all tools |
| raw_output | Text | Full tool output (truncated at TOOL_OUTPUT_MAX_CHARS) |
| execution_time | Float | Total execution duration (seconds) |
| exit_code | Integer | Final exit code |
| error_message | Text | Error details (if failed) |
| created_at | DateTime | Scan creation timestamp |
| started_at | DateTime | Actual start (after queue) |
| completed_at | DateTime | Completion timestamp |

**Indexes (recommended for production):**
- scan_id (PK)
- task_id (unique)
- status (filter queries)
- target (search queries)
- created_at (time range queries)

### 8.2 ExecutionLog Table

**Purpose:** Granular logging of each tool execution.

**Fields:**
| Field | Type | Notes |
|-------|------|-------|
| id | UUID (PK) | Auto-generated |
| scan_id | UUID (FK) | Links to ScanJob |
| execution_order | Integer | Sequential order in workflow |
| tool_name | String | Tool executed (nmap, sqlmap, etc.) |
| command_line | Text | Full command invoked |
| raw_output | Text | Tool stdout/stderr |
| exit_code | Integer | Tool exit code |
| execution_time | Float | Duration (seconds) |
| timestamp | DateTime | Execution timestamp |

**Indexes:**
- scan_id (FK lookup)
- execution_order (workflow reconstruction)

### 8.3 Anomaly Table

**Purpose:** Detected anomalies in scan results.

**Fields:**
| Field | Type | Notes |
|-------|------|-------|
| id | UUID (PK) | Auto-generated |
| scan_id | UUID (FK) | Links to ScanJob |
| severity | Enum | critical, high, medium, low |
| anomaly_type | String | Type name (e.g., "encoding_mismatch") |
| description | Text | Human-readable description |
| detected_at | DateTime | Detection timestamp |

**Example Anomalies:**
- "Binary output when text expected"
- "Authentication bypass pattern detected"
- "Execution time 10x faster than baseline"

### 8.4 WorkflowStep Table

**Purpose:** Multi-step workflow tracing (DAG).

**Fields:**
| Field | Type | Notes |
|-------|------|-------|
| id | UUID (PK) | Auto-generated |
| scan_id | UUID (FK) | Links to ScanJob |
| step_id | String (unique) | Step identifier (e.g., "step-001") |
| parent_step_id | UUID (FK, nullable) | Parent step for DAG structure |
| execution_order | Integer | Order within parent level |
| tool_name | String | Tool name |
| parameters | Text/JSON | Tool-specific parameters |
| confidence | Float | Decision confidence (0.0-1.0) |
| findings | Text/JSON | Parsed findings from this step |
| execution_time | Float | Duration (seconds) |
| cpu_usage | Float | CPU % used (nullable) |
| memory_usage | Float | Memory % used (nullable) |
| exit_code | Integer | Tool exit code |
| status | Enum | pending, running, completed, failed |
| error_message | Text | Error details (if failed) |
| created_at | DateTime | Step creation |
| completed_at | DateTime | Completion timestamp |

**DAG Reconstruction:**
```sql
-- Get full workflow tree
SELECT * FROM workflow_step
WHERE scan_id = ?
ORDER BY parent_step_id, execution_order
-- Parent-child relationships form the DAG
```

---

## 9. Security Features & Considerations

### 9.1 Built-In Protections

1. **Input Validation** (validators.py)
   - Target whitelist/blacklist checks
   - Parameter sanitization
   - Rate limiting (default: 100 requests/hour per user)

2. **Docker Isolation**
   - Each tool runs in its own container
   - Resource limits (memory, CPU)
   - Network isolation (configurable)
   - No container privilege escalation

3. **Database Encryption (Optional)**
   - SQLite: Use SQLCipher for encryption
   - PostgreSQL: Enable TLS + at-rest encryption

4. **Local Inference**
   - No external LLM API calls
   - Model runs on-device
   - No data sent to cloud services

### 9.2 Vulnerability Analysis Coverage

**Coverage by Language:**

| Language | Tool | Rule Count | CWE Coverage |
|----------|------|-----------|--------------|
| Python | Bandit | 25+ checks | CWE-89, 95, 98, 502, 611, 327, 328, etc. |
| JavaScript | ESLint + plugins | 20+ rules | CWE-89, 95, 346, 502, 776, etc. |
| Java | Regex patterns | 12+ patterns | CWE-89, 90, 95, 502, 327, etc. |
| PHP | Regex patterns | 14+ patterns | CWE-89, 90, 95, 326, 502, etc. |
| Go | Regex patterns | 10+ patterns | CWE-89, 327, 613, 749, etc. |

### 9.3 Rate Limiting

**Current Implementation:**
```python
check_rate_limit(user_id: str) → bool
```

Default: 100 scans/hour per user (configurable via env var RATE_LIMIT_PER_HOUR).

**Bypass Considerations:**
- IP-based rate limiting (if behind proxy)
- User authentication (future enhancement)

---

## 10. Performance Characteristics

### 10.1 Code Analysis Performance

| Language | Test Code | Analysis Time | Details |
|----------|-----------|----------------|---------|
| Python (100 LOC) | Mixed security issues | 0.2-0.5s | Subprocess startup overhead |
| JavaScript (100 LOC) | XSS + eval issues | 0.3-0.8s | ESLint plugin loading |
| Java (50 LOC) | Pattern matching | 0.05-0.1s | Regex only, very fast |
| PHP (50 LOC) | Pattern matching | 0.05-0.1s | Regex only, very fast |
| Go (50 LOC) | Pattern matching | 0.05-0.1s | Regex only, very fast |

**Optimization Notes:**
- ESLint rule checks run in parallel
- Pattern analysis uses compiled regex (fast)
- Python Bandit runs in isolated subprocess
- JS analysis can be cached per file hash

### 10.2 Tool Execution Performance

| Tool | Typical Runtime | Resource Usage | Bottleneck |
|------|-----------------|-----------------|-----------|
| nmap (fast scan) | 1-5s | Low CPU, medium I/O | Network latency |
| sqlmap (single query) | 10-30s | Medium CPU, medium I/O | Database response |
| nikto (single host) | 5-15s | Low CPU, medium I/O | HTTP requests |
| ffuf (1000 words) | 5-20s | High CPU, medium I/O | Wordlist size |
| john (small hash) | 1-3s | High CPU | GPU (if available) |

**Scaling Bottlenecks:**
- Docker container startup: ~1s per tool
- SQLite DB contention at 100+ concurrent scans
- Memory: 512 MB per container × N tools
- Network: Single NIC bandwidth

### 10.3 Database Performance

**SQLite Limitations:**
- Single writer at a time (row-level locking)
- Suitable for <100k total scans
- Query time: <100ms for typical queries

**PostgreSQL (Production):**
- Multi-writer capability
- Connection pooling recommended
- Indexes on scan_id, status, created_at essential

---

## 11. Development & Deployment

### 11.1 Local Development Setup

**Prerequisites:**
- Node.js 20+
- Python 3.9+
- Docker
- 4 GB RAM minimum

**Quick Start:**
```bash
# Backend
cd backend
pip install -r requirements.txt
python -m uvicorn app:app --host 0.0.0.0 --port 8000 --reload

# Frontend (new terminal)
npm install
npm run dev

# Docker tools (new terminal, optional)
cd backend
docker-compose -f docker-compose.tools.yml up
```

**Access:**
- Frontend: http://localhost:5173
- Backend API: http://localhost:8000
- API Docs: http://localhost:8000/docs (Swagger UI)

### 11.2 Production Deployment

**Recommended Architecture:**
```
┌─ Load Balancer (nginx/HAProxy)
├─ Backend Servers (3x FastAPI + Uvicorn)
│  └─ PostgreSQL Database Cluster
└─ Docker Daemon (tool execution, separate host)
```

**Frontend Deployment:**
1. Build: `npm run build` → /dist
2. Serve via CDN or web server (nginx)
3. Configure CORS headers
4. Enable gzip compression

**Backend Deployment:**
1. Build Docker image (see Dockerfile)
2. Use Gunicorn + Uvicorn workers (4x)
3. Configure PostgreSQL (production DB)
4. Set environment variables (secrets manager)
5. Enable logging aggregation (ELK, Datadog)

**Database Migration (SQLite → PostgreSQL):**
```bash
pip install pgloader
pgloader sqlite:///alphaweb.db postgresql://user:pass@host/alphaweb
```

### 11.3 Environment Variables

**Core Settings:**

| Variable | Default | Type | Purpose |
|----------|---------|------|---------|
| ORCHESTRATOR_HOST | 0.0.0.0 | str | FastAPI bind address |
| ORCHESTRATOR_PORT | 8000 | int | FastAPI port |
| BARONLLM_MODEL_PATH | models/barronllm.gguf | str | LLM model file path |
| BARONLLM_N_CTX | 4096 | int | LLM context window |
| BARONLLM_N_GPU_LAYERS | 35 | int | GPU acceleration layers |
| DATABASE_URL | sqlite:///alphaweb.db | str | SQLAlchemy connection |
| DOCKER_MEMORY_LIMIT | 512m | str | Container memory limit |
| DOCKER_CPU_LIMIT | 1.0 | float | Container CPU limit |
| DEFAULT_TOOL_TIMEOUT | 300 | int | Default tool timeout (s) |
| LOG_LEVEL | INFO | str | Python logging level |
| RATE_LIMIT_PER_HOUR | 100 | int | Scans per user per hour |

---

## 12. Code Organization & Metrics

### 12.1 File Structure Overview

```
alphaweb/
├── frontend/                          (1,314 LOC)
│   ├── App.jsx                        (100 LOC)
│   ├── main.jsx                       (10 LOC)
│   ├── App.css                        (Theme + layout)
│   ├── vite.config.js                 (Proxy config)
│   └── components/                    (1,204 LOC)
│       ├── ActivityBar/               (86 LOC)
│       ├── SideBar/                   (214 LOC)
│       ├── Editor/                    (409 LOC) ← Largest component
│       ├── AgentChat/                 (248 LOC)
│       ├── Terminal/                  (200 LOC)
│       ├── StatusBar/                 (95 LOC)
│       └── QuickActions/              (62 LOC)
│
├── backend/                           (2,268 LOC)
│   ├── app.py                         (1,044 LOC) ← Core router
│   ├── config.py                      (83 LOC)
│   ├── database.py                    (156 LOC)
│   ├── llm_client.py                  (349 LOC)
│   ├── tool_runner.py                 (283 LOC)
│   ├── validators.py                  (353 LOC)
│   ├── services/                      (~1,500 LOC est.)
│   │   ├── code_analyzer.py
│   │   ├── workflow_engine.py
│   │   ├── shannon_orchestrator.py
│   │   ├── tool_decision_engine.py
│   │   ├── anomaly_detector.py
│   │   └── execution_graph.py
│   ├── tools/
│   │   └── js/                        (ESLint config)
│   ├── models/                        (GGUF model storage)
│   ├── data/                          (Wordlists, temp files)
│   ├── logs/                          (Execution logs)
│   ├── requirements.txt
│   └── Dockerfile
│
├── package.json                       (Node.js dependencies)
├── vite.config.js                     (Build config)
├── README.md                          (Setup guide)
└── alphaweb.db                        (SQLite database)
```

### 12.2 Code Metrics

**Backend:**
- Total LOC: 2,268 (application code)
- Largest file: app.py (1,044 LOC)
- Services count: 6 major modules
- Database tables: 4 (ScanJob, ExecutionLog, Anomaly, WorkflowStep)
- API endpoints: 10+ (health, scan, chat, analyze-code, etc.)

**Frontend:**
- Total LOC: 1,314 (including JSX)
- Components: 6 major UI modules
- Largest component: Editor (409 LOC)
- State management: React hooks (useState, useCallback, useRef)
- Styling: CSS3 with CSS variables

**Services:**
- Code Analyzer: Multi-language SAST, 80+ CWE mappings
- Shannon Orchestrator: DAG-based workflow execution
- Tool Decision Engine: LLM-guided tool selection
- Workflow Engine: Persistence & query layer
- Anomaly Detector: Output analysis & pattern matching
- Execution Graph: Constraint enforcement

---

## 13. Future Enhancement Opportunities

### 13.1 Planned Features

1. **Authentication & Authorization**
   - User accounts (OAuth 2.0 / SAML)
   - Role-based access control (admin, analyst, viewer)
   - API key management for CI/CD integration
   - Audit logging (who ran what scan)

2. **Advanced Reporting**
   - PDF report generation (findings + remediation)
   - SARIF format export (integration with IDE plugins)
   - Trend analysis (vulnerability growth/decline over time)
   - Risk scoring & prioritization
   - Executive summary templates

3. **CI/CD Integration**
   - GitHub Actions, GitLab CI, Jenkins plugins
   - Pull request comments with vulnerability warnings
   - Merge blocking on critical findings
   - Pre-commit hooks (local code analysis)

4. **Enhanced LLM Capabilities**
   - Fine-tuned model for security analysis
   - Multi-language support (security jargon)
   - Remediation code generation
   - Architecture review via LLM

5. **Workflow Templates**
   - Pre-built OWASP Top 10 scanning workflows
   - Industry-specific templates (AWS, GCP, Azure)
   - Custom workflow builder (no-code UI)
   - Workflow versioning & rollback

6. **Distributed Scanning**
   - Multiple backend instances (horizontal scaling)
   - Job queue backend (RabbitMQ, Redis)
   - Distributed tool execution across worker nodes
   - Result aggregation & deduplication

7. **Container Registry Scanning**
   - Docker image vulnerability scanning
   - SBOM generation (Software Bill of Materials)
   - Supply chain security analysis
   - Image layer analysis

8. **Machine Learning**
   - False positive filtering (based on historical data)
   - Anomaly detection (unusual scan patterns)
   - Vulnerability prediction (risk assessment)
   - Tool efficiency optimization

### 13.2 Technical Debt & Refactoring

1. **Code Quality**
   - Type hints for all functions (mypy checks)
   - Unit test coverage (currently ~0%)
   - Integration test suite
   - E2E test automation

2. **Performance**
   - Caching layer (Redis for LLM responses)
   - Query optimization (database indexes)
   - Async code analysis (parallel tool execution)
   - Frontend bundle optimization (code splitting)

3. **Architecture**
   - Decouple service dependencies
   - Event-driven architecture (Kafka/RabbitMQ)
   - Microservices split (code analyzer as separate service)
   - API versioning (v1, v2, v3)

4. **Documentation**
   - API OpenAPI/Swagger documentation (auto-generated)
   - Architecture decision records (ADRs)
   - Security model documentation
   - Contributor guidelines

---

## 14. Risk Analysis & Mitigation

### 14.1 Security Risks

| Risk | Severity | Mitigation |
|------|----------|-----------|
| Unvalidated tool execution | High | Input validation, Docker isolation, resource limits |
| LLM jailbreak (malicious prompt) | Medium | Input sanitization, model temperature (low), filtering |
| Database SQL injection | Low | SQLAlchemy ORM (parameterized queries) |
| XSS in frontend | Medium | React auto-escaping, CSP headers |
| Rate limit bypass | Medium | IP-based rate limiting, authentication |
| Docker escape | Low | Use security-hardened base images, seccomp profiles |

### 14.2 Operational Risks

| Risk | Severity | Mitigation |
|------|----------|-----------|
| Database corruption | High | Regular backups, PostgreSQL (production) |
| Tool process hanging | Medium | Per-tool timeout enforcement, watchdog process |
| Memory exhaustion | Medium | Container resource limits, memory monitoring |
| Disk space (logs/DB) | Medium | Log rotation, database cleanup jobs |

---

## 15. Testing Strategy

### 15.1 Testing Approach

**Unit Tests (Recommended):**
- Code analyzer: Test Bandit integration, pattern matching
- Validators: Input validation edge cases
- Workflow engine: DAG construction, step ordering

**Integration Tests:**
- End-to-end scan execution (nmap → nikto → sqlmap)
- Database CRUD operations
- LLM integration (mocked responses)

**E2E Tests:**
- Full stack: Frontend → Backend → Docker → Database
- UI interactions (file upload, analyze, view results)

### 15.2 Test Data & Fixtures

**Code Samples (Testing):**
- Vulnerable Python code (eval, pickle, hardcoded passwords)
- Vulnerable JavaScript (XSS, eval, child_process)
- Known vulnerable binaries (for tool testing)

---

## 16. Compliance & Standards

### 16.1 Applicable Standards

| Standard | Applicability | Status |
|----------|---------------|--------|
| OWASP Top 10 | Code analysis rules | Implemented |
| CWE/CVSS | Vulnerability classification | Integrated |
| SARIF | Report format | Future |
| NIST Cybersecurity Framework | Security practices | Aligned |
| GDPR (data privacy) | User data handling | Development |

### 16.2 Audit Logging

**Currently Logged:**
- Scan creation/completion
- Tool execution (command, output, exit code)
- Workflow steps (tool sequence, findings)
- Anomalies detected

**Future Logging:**
- User authentication (login, logout, failed attempts)
- Data access (who queried what scan)
- Configuration changes
- System events (errors, warnings)

---

## 17. Known Limitations & Workarounds

### 17.1 Current Limitations

1. **SQLite Database**
   - Single writer (no concurrent scans)
   - Workaround: Migrate to PostgreSQL for production

2. **Semgrep Windows Issues**
   - Encoding problems on Windows platform
   - Workaround: Use pattern-based fallback rules

3. **LLM Model Storage**
   - Large GGUF file (~4-7 GB for good models)
   - Workaround: Use smaller quantized models

4. **Docker on Windows**
   - WSL2 required (Hyper-V)
   - Workaround: Use Linux VM or cloud deployment

5. **Frontend Routing**
   - No URL-based navigation (SPA limitation)
   - Workaround: Implement React Router (future)

---

## 18. Conclusion

**Project Status:** Alpha (v0.1.0) — Fully functional with core features.

**Strengths:**
- Integrated code analysis + tool orchestration
- Local LLM inference (privacy-first)
- Multi-step intelligent workflows
- Comprehensive database persistence
- IDE-like interactive UI

**Weaknesses:**
- No user authentication/RBAC
- Limited testing coverage
- SQLite not suitable for production scale
- Semgrep Windows compatibility

**Next Phase:**
Focus on production readiness: PostgreSQL migration, authentication, reporting, CI/CD integration, and comprehensive testing.

**Recommendation for Use:**
- Development & testing: Ready
- Production: Migrate database to PostgreSQL, add authentication, enable TLS
- Enterprise: Add compliance logging, multi-tenancy, distributed architecture

---

## 19. Appendices

### 19.1 Quick Reference: Environment Setup

**Backend:**
```bash
cd backend
pip install -r requirements.txt
export BARONLLM_MODEL_PATH=./models/barronllm.gguf
python -m uvicorn app:app --host 0.0.0.0 --port 8000
```

**Frontend:**
```bash
npm install
npm run dev  # http://localhost:5173
```

**Docker Tools:**
```bash
cd backend
docker-compose -f docker-compose.tools.yml build
docker-compose -f docker-compose.tools.yml up
```

### 19.2 Quick Reference: API Examples

**Analyze Code:**
```bash
curl -X POST http://localhost:8000/analyze-code \
  -H "Content-Type: application/json" \
  -d '{
    "code": "eval(userInput)",
    "language": "javascript",
    "filename": "app.js"
  }'
```

**Create Scan:**
```bash
curl -X POST http://localhost:8000/api/scan \
  -H "Content-Type: application/json" \
  -d '{
    "target": "example.com",
    "tool": "nmap",
    "parameters": "-p 80,443"
  }'
```

**Get Scan Results:**
```bash
curl http://localhost:8000/api/scans/{scan_id}
```

### 19.3 Glossary

| Term | Definition |
|------|-----------|
| SAST | Static Application Security Testing |
| DAG | Directed Acyclic Graph (workflow structure) |
| CWE | Common Weakness Enumeration |
| CVSS | Common Vulnerability Scoring System |
| GGUF | LLM file format (quantized) |
| Orchestrator | Multi-step workflow executor |
| Anomaly | Unusual/suspicious scan result |
| WorkflowStep | Single tool execution in a workflow |
| ScanJob | Single top-level scan request |
| ESLint | JavaScript linter & security analyzer |
| Bandit | Python static security analyzer |

---

**Document Generated:** 2026-04-19  
**Project Version:** 0.1.0  
**Total Pages:** ~20 (markdown)  
**Total Word Count:** ~5,500+

---

## Report Usage & Distribution

**Recommended Uses:**
1. **Project Documentation** — Reference for team members
2. **Stakeholder Updates** — Present to management/sponsors
3. **Academic Reports** — Complete technical analysis
4. **Grant/Funding Proposals** — Demonstrate scope & capabilities
5. **Open Source Contribution** — Help potential contributors understand the system
6. **Client Deliverables** — Showcase platform capabilities
7. **Architecture Review** — Present design decisions to architects

**Format Options:**
- **Markdown** (current) — Direct conversion to HTML, PDF via Pandoc
- **HTML** — Use Markdown renderer or `pandoc COMPREHENSIVE_PROJECT_REPORT.md -t html -o report.html`
- **PDF** — `pandoc COMPREHENSIVE_PROJECT_REPORT.md -t pdf -o report.pdf` (requires LaTeX)
- **DOCX** — `pandoc COMPREHENSIVE_PROJECT_REPORT.md -t docx -o report.docx`
