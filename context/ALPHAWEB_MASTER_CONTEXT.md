# AlphaWeb — Master Context Document
*For export to new chat sessions*

---

## Project Identity

**Name:** AlphaWeb — AI-Powered Cybersecurity Automation Platform
**Status:** Working MVP, actively being refined for hackathon submission
**Platform category:** Web (browser-based interface, runs locally — no cloud deployment)
**Owner:** 4th-year CS student (batch 2027), MJCET Hyderabad

---

## Core Concept

AlphaWeb unifies three traditionally separate security workflows — network/web vulnerability scanning, static code analysis (SAST), and manual tool orchestration — into a single AI-driven platform. It automates the "mechanical layer" of security work (running tools, interpreting output, deciding what to run next) so professionals can focus on actual analysis, and makes findings interpretable for non-experts.

**Problem it solves:** Security professionals waste 60-70% of their time manually running and switching between fragmented tools. Output requires expertise to interpret. Non-security people (developers, small teams) have no accessible path to knowing if their code/infrastructure is secure without expensive consultants or steep learning curves.

---

## CRITICAL NAMING CONVENTION

In all external-facing docs, prompts, README, and submissions:
- The LLM must always be called **AlphaLLM** — never "BaronLLM"
- The execution/workflow coordination layer must always be called the **Orchestrator** or **orchestration layer** — never "Shannon"

Internally, the underlying base model is a fine-tuned BaronLLM model (from HuggingFace: AlicanKiraz0/Cybersecurity-BaronLLM_Offensive_Security_LLM_Q6_K_GGUF, cybersecurity-specialized GGUF/Q6_K quant), but this is never surfaced by name anywhere public-facing.

---

## Architecture

### Five-Layer System
Presentation → API Gateway → Core Services → Infrastructure → Security Tools layers, each independently developable/testable/evolvable.

### Two-Tier Agentic AI System (key innovation, in progress)

- **Layer 1 — Gemma 3 4B (Execution Agent):** Fast, lightweight model handling tool selection, command/parameter generation, Docker orchestration, raw output capture (<500ms per decision).
- **Layer 2 — AlphaLLM (Analysis Agent):** Larger local model (fine-tuned, quantized GGUF) that interprets tool findings, maps to CWE/severity, detects anomalies/contradictions, and recommends the next tool based on evidence. Confidence threshold default 0.7.

**Loop:** User objective → AlphaLLM (strategy) → Gemma 3 (execute tool) → raw output → AlphaLLM (analyze + decide next) → repeat until objective met.

### Orchestrator
DAG-based multi-step workflow engine chaining 25 tools with constraint enforcement (max depth 5, max tools per workflow 10).

---

## Tech Stack

**Frontend:**
- React 18.2 + Vite 4.3
- 6-panel IDE-like SPA: ActivityBar, SideBar (file explorer/upload), Editor (live vulnerability highlighting), AgentChat (AI chat), Terminal (live output streaming), StatusBar
- CSS3 (Grid, Flexbox, CSS Variables)

**Backend:**
- Python FastAPI, SQLAlchemy ORM, Uvicorn, Pydantic
- Key modules: app.py (main routes), tool_runner.py (Docker execution), validators.py (safety/rate-limiting), config.py
- Services: code_analyzer.py, workflow_engine.py, shannon_orchestrator.py (internal name only), anomaly_detector.py, execution_graph.py, tool_decision_engine.py

**AI/LLM:**
- AlphaLLM — local GGUF quantized model (fine-tuned BaronLLM base), via llama-cpp-python / llama-server.exe
- Gemma 3 4B — execution agent (planned/in-progress layer)
- Zero cloud API dependency — complete local inference

**Security Analysis (SAST):**
- Python: Bandit
- JavaScript: ESLint + eslint-plugin-security + eslint-plugin-no-unsanitized
- Java, PHP, Go: pattern-based regex rules (XSS, SQLi, eval, hardcoded secrets, weak crypto)
- Semgrep (supplementary, had Windows encoding issues — pattern fallback used)
- CWE mapping + severity + remediation suggestions for all languages

**Database:**
- SQLite (development), PostgreSQL (production)
- Four tables: ScanJob, ExecutionLog, Anomaly, WorkflowStep — full audit traceability

**Infrastructure:**
- Docker (tool isolation), Docker Compose
- Per-tool resource limits (512MB RAM, 1 CPU default) and timeouts

---

## The 25 Security Tools

| Tool | Category |
|------|----------|
| Nmap | Port scanning / service discovery |
| Masscan | Fast mass port scanning |
| Nikto | Web server vulnerability scanning |
| SQLMap | SQL injection testing |
| FFUF | Web fuzzing / endpoint discovery |
| Gobuster | Directory brute-forcing / DNS enum |
| Hydra | Credential brute-forcing |
| John the Ripper | Password hash cracking |
| Curl | HTTP requests / API testing |
| Tcpdump | Network packet capture |
| Nuclei | Template-based vulnerability scanning |
| hashcat | GPU-accelerated hash cracking |
| gitleaks | Git secret scanning |
| theHarvester | OSINT email/subdomain harvesting |
| Sublist3r | Passive subdomain enumeration |
| testssl.sh | TLS/SSL configuration auditing |
| Wapiti | Web application vulnerability scanner |
| WPScan | WordPress vulnerability scanner |
| CeWL | Custom wordlist generator |
| Trivy | Container/filesystem vuln scanner |
| Amass | DNS enumeration / asset discovery |
| Commix | Command injection detection |
| SearchSploit | Offline exploit DB search |
| Subdominator | Subdomain takeover detection |
| httpx | HTTP probing / web fingerprinting |

All tools are 100% free/open-source — zero licensing cost.

---

## Database Schema

**ScanJob:** id, task_id, status, tool_selected, target, created_at, completed_at, result (JSON)

**ExecutionLog:** id, scan_id (FK), execution_order, tool_name, command_line, raw_output, exit_code, execution_time, timestamp

**Anomaly:** id, scan_id (FK), severity, anomaly_type, description, detected_at

**WorkflowStep:** id, scan_id (FK), step_id, parent_step_id, execution_order, tool_name, parameters (JSON), findings (JSON), execution_time, status

---

## Anomaly Detection (4-5 Methods)

1. **Statistical** — z-score based, baseline metrics per tool, flag if |z-score| > 3
2. **Rule-based** — tool crashes (exit code ≠ 0, output < 50 bytes), resource exhaustion (memory > 90%, CPU > 80%), timeouts, format mismatches
3. **Finding contradictions** — same port open/closed conflict, service/OS mismatches, impossible states
4. **Pattern anomalies** — impossibly high finding counts, severity distribution outliers, unusual execution time trends
5. *(Planned/ambitious extension)* Isolation Forest, Autoencoders, ARIMA, K-Means ensemble voting — not required for MVP, statistical + rule-based + contradiction + pattern is sufficient and already strong

Each anomaly returns: type, severity (critical/high/medium/low), confidence (0-1), details, remediation suggestion.

---

## Code Analysis Feature (Side Feature — Left Panel)

Rule-based static analysis only — **no ML model training needed/recommended** for this part.

**Flow:** User pastes/uploads code → language auto-detected → Bandit (Python) or ESLint (JS) or pattern rules (Java/PHP/Go) run → vulnerabilities returned with line numbers, severity, CWE code, fix suggestion.

**Endpoint:** `POST /analyze-code`
```json
Request: { "code": "...", "language": "python", "filename": "app.py" }
Response: {
  "analysis_id": "uuid",
  "language": "python",
  "total_vulnerabilities": 3,
  "critical": 1, "high": 1, "medium": 1, "low": 0,
  "vulnerabilities": [
    { "type": "sql_injection", "severity": "critical", "line": 45,
      "code_snippet": "...", "issue": "...", "fix": "...", "cwe": "CWE-89" }
  ]
}
```

**3 test cases created** (vulnerable Python web app, vulnerable Node.js/Express app, advanced Python vulnerabilities) covering SQLi, XSS, command injection, hardcoded secrets, eval(), insecure deserialization, XXE, SSRF, race conditions, weak crypto, etc. — used to validate the analyzer.

---

## Known Issues / Open Problems

- **Docker execution reliability:** Tools were failing to run — root cause likely permission issues (tcpdump/masscan need elevated access for raw sockets/packet capture; most others like nmap/nikto/sqlmap/nuclei don't need special perms for standard HTTP-based scanning). Decision point reached: either (a) simplify to host-based `subprocess` execution with sudo prompts for tools that need it, or (b) properly fix Docker networking/permissions (`--network host`, proper entrypoints, resource mounts). Leaning toward "vibe coding" a working version fast rather than over-engineering Docker from scratch.
- **LLM hallucination observed:** AlphaLLM given raw CeWL word-list output invented a fictional website narrative (e-commerce platform, JS framework, etc.) not supported by the sparse keyword data. Fix direction: constrain prompts to factual extraction only (no open-ended "describe this website"), separate observation vs inference in structured JSON output, use regex/pattern matching for tech-stack detection instead of LLM inference, validate LLM claims against raw data before accepting.

---

## Fine-Tuning Approach (AlphaLLM)

User fine-tuned the base BaronLLM model (not trained from scratch — correctly identified as not worth the effort/resources for an academic project).

**Recommended approach to describe in defense:** QLoRA (Quantized Low-Rank Adaptation) on the quantized base model — custom dataset of security request → tool mapping examples (500+), including edge cases (ambiguous requests, safety violations, parameter variations), low GPU memory requirement.

**For code analysis feature specifically:** Explicitly decided AGAINST training a custom ML/LLM vulnerability-detection model (would need 10,000+ labeled examples, weeks of GPU time, not worth it). Using battle-tested rule-based SAST tools (Bandit/ESLint/pattern rules) instead — correct academic and engineering decision.

---

## Anomaly Detection Model Training (Scan Metrics, Separate from Code Analysis)

For the scan-execution anomaly detection (not code analysis), training an Isolation Forest (and/or statistical baselines) on real scan metrics is worthwhile and achievable:
- Collect 50-200+ real scans across tools, export metrics (execution_time, cpu_usage, memory_usage, findings_count) to CSV
- Train on Google Colab (free, fast, easy to show as proof) or locally
- Save as `.pkl`, load into backend for inference
- This is legitimate, explainable, and impressive without being a huge time sink

---

## SDG Mapping (for academic submission)

- **SDG 9** (Industry, Innovation & Infrastructure) — accessible automated cybersecurity infrastructure via AI innovation
- **SDG 16** (Peace, Justice & Strong Institutions) — strengthens institutional resilience through accessible security tooling
- **SDG 4** (Quality Education) — democratizes cybersecurity learning/tool access
- **SDG 8** (Decent Work & Economic Growth) — improves security job quality, enables SMEs to implement professional security

---

## Tool Execution Time Reference

Most tools finish in 1-5 minutes — good for live demos. Exceptions: Hydra, John, hashcat (password cracking) can take minutes to days depending on wordlist/hash complexity — always set hard timeouts and return partial results. Fast demo-friendly tools: Nmap (~10s), theHarvester (~30s), Sublist3r (~1-2min), WPScan (~1min).

---

## Cost

**Total software/tool licensing cost: $0** — all 25 tools are open-source (GPL/MIT/Apache licenses), no restrictions for academic or commercial use. Only infra cost would be hosting (if ever deployed, not required since it's designed to run locally).

---

## Branding

**Logo concept finalized:** Dark navy/black background, glowing teal (#00c8a8) alpha (α) symbol center, radar/targeting-ring motif (concentric circles + corner brackets, suggesting scanning/reconnaissance), "ALPHAWEB" wordmark below in white with letter spacing, tagline "CYBERSECURITY AUTOMATION" in teal.

---

## Academic Submission Materials Already Drafted

- Project abstract (polished, submission-ready)
- 6-point conclusion (AlphaLLM + orchestration layer naming applied)
- Primary objectives (6 bullet points: 5-layer architecture, Orchestrator, React frontend, DB schema, privacy, SAST)
- Secondary objectives (4 bullet points: literature review, system analysis with 20+ functional/16+ non-functional requirements, 6-category testing, documentation/GitHub)
- "Fragmented Toolchain Problem" section (refined)
- "What problem does it solve" hackathon answer (refined, no em-dashes per user preference)
- "Where it fits in security workflow" section (mentions 25 tools + SAST explicitly)
- Technologies-used list for GitHub
- 3 GitHub README bullet points
- Future scope / roadmap (Near-term 0-6mo, Medium-term 6-12mo, Long-term 1-2yr, Research opportunities) — condensed version done

---

## User Writing/Output Preferences (apply when producing content for this project)

- Avoid em-dashes (—) in generated prose when user flags it — use periods/commas instead
- No markdown headers/bold when user asks for "just points" — plain bullet lists only, no bolded lead-ins
- Prompts for Claude Opus (code generation) should contain **zero code snippets** — describe objectives/requirements only, let Opus write the implementation
- Keep prompts structured with exact JSON schemas, exact DB schema (SQL), example request/response payloads, and one fully worked end-to-end example when asked for "ambitious"/detailed prompts
- Two-phase prompt splitting works well: Phase 1 = foundation (API, LLM integration, DB, validators), Phase 2 = advanced (anomaly detection, orchestrator integration, tool expansion, frontend integration)
- User is time-constrained ("vibe coding" is an explicitly accepted strategy) — prioritize working over perfect, pragmatic over theoretically ideal
