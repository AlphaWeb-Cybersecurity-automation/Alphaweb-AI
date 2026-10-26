from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import time
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import Depends, FastAPI, Header, HTTPException, Query
from pydantic import BaseModel, Field

from config import Settings
from database import Anomaly, ExecutionLog, ScanJob, SessionLocal, WorkflowStep, init_db
from llm_client import get_baron
from services.shannon_orchestrator import (
    ShannonOrchestrator,
    _ensure_url,
    _normalize_target,
    precheck_tool_input,
)
import services.semantic_router as semantic_router
from services.target_extractor import validate_target_for_tool
from services.alert_extractor import extract_alerts, severity_counts
from services.report_builder import (
    build_report,
    delete_all_reports,
    load_all_reports,
    load_report,
    load_report_html,
    save_report,
)
from services.pdf_builder import render_reports_pdf
from services.system_profiler import build_profile
from services.ownership import (
    check_tool_access,
    check_verification,
    create_user,
    denial_text,
    get_or_create_challenge,
    list_domains,
    registrable_domain,
    resolve_user_id,
    revoke_domain,
)
from services.workflow_engine import WorkflowEngine
from tool_runner import cancel_run, run_tool, run_tool_streaming
from validators import (
    SUPPORTED_TOOLS,
    ExecuteRequest,
    ExecuteResponse,
    ScanRequest,
    ValidateRequest,
    ValidationResult,
    check_rate_limit,
    parse_and_validate_execute_request,
    record_scan_end,
    record_scan_start,
    validate_parameters,
    validate_target_enhanced,
)

settings = Settings()

os.makedirs(settings.LOG_DIR, exist_ok=True)

logger = logging.getLogger("orchestrator")
logger.setLevel(getattr(logging, settings.LOG_LEVEL, logging.INFO))

_fmt = logging.Formatter("%(asctime)s %(levelname)s %(message)s")

_file_handler = logging.FileHandler(settings.LOG_FILE)
_file_handler.setFormatter(_fmt)
logger.addHandler(_file_handler)

_stream_handler = logging.StreamHandler()
_stream_handler.setFormatter(_fmt)
logger.addHandler(_stream_handler)


# --- Response models ---

class ScanCreateResponse(BaseModel):
    scan_id: str
    status: str
    tool_selected: Optional[str]
    target: str
    created_at: str


class Finding(BaseModel):
    port: Optional[int] = None
    state: Optional[str] = None
    service: Optional[str] = None
    version: Optional[str] = None


class WorkflowStepResponse(BaseModel):
    step_id: str
    parent_step_id: Optional[str] = None
    execution_order: int
    tool_name: str
    confidence: float = 0.0
    parameters: Dict[str, Any] = {}
    findings: Any = []
    execution_time: Optional[float] = None
    cpu_usage: Optional[float] = None
    memory_usage: Optional[float] = None
    exit_code: Optional[int] = None
    status: str = "pending"
    error_message: Optional[str] = None
    created_at: Optional[str] = None
    completed_at: Optional[str] = None


class AnomalyResponse(BaseModel):
    id: str
    step_id: Optional[str] = None
    type: str
    severity: str
    confidence: float = 0.0
    details: Dict[str, Any] = {}
    suggestion: Optional[str] = None


class ScanDetailResponse(BaseModel):
    scan_id: str
    status: str
    tool_used: Optional[str]
    target: str
    parameters: Dict[str, Any] = {}
    findings: Any = []
    execution_time: Optional[float] = None
    cpu_usage: Optional[float] = None
    memory_usage: Optional[float] = None
    exit_code: Optional[int] = None
    created_at: str
    completed_at: Optional[str] = None
    workflow: List[WorkflowStepResponse] = []
    anomalies: List[AnomalyResponse] = []
    execution_depth: int = 0


class WorkflowResponse(BaseModel):
    scan_id: str
    steps: List[WorkflowStepResponse] = []
    anomalies: List[AnomalyResponse] = []
    execution_depth: int = 0
    total_tools_run: int = 0


class AnalyzeCodeRequest(BaseModel):
    code: str
    language: Optional[str] = None
    filename: Optional[str] = None


class CodeVulnerability(BaseModel):
    type: Optional[str] = None
    severity: str
    line: Optional[int] = None
    code_snippet: Optional[str] = None
    issue: str
    fix: Optional[str] = None
    cwe: Optional[str] = None


class AnalyzeCodeResponse(BaseModel):
    analysis_id: str
    language: str = "unknown"
    vulnerabilities: List[CodeVulnerability] = []
    total_vulnerabilities: int = 0
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0


class ScanListItem(BaseModel):
    scan_id: str
    status: str
    tool_used: Optional[str]
    target: str
    created_at: str


class ScanListResponse(BaseModel):
    scans: List[ScanListItem]
    total: int
    page: int
    limit: int


class ValidateResponse(BaseModel):
    valid: bool
    tool_selected: Optional[str] = None
    confidence: Optional[float] = None
    rationale: Optional[str] = None
    warnings: List[str] = []


class HealthResponse(BaseModel):
    status: str
    timestamp: str
    components: Dict[str, bool]


# --- Job queue ---

scan_queue: asyncio.Queue = asyncio.Queue()
_worker_task: Optional[asyncio.Task] = None


def _log_to_db(scan_id: str, level: str, message: str) -> None:
    db = SessionLocal()
    try:
        db.add(ExecutionLog(scan_id=scan_id, log_level=level, message=message))
        db.commit()
    finally:
        db.close()


async def _process_scan(job_id: str) -> None:
    db = SessionLocal()
    try:
        scan = db.query(ScanJob).filter(ScanJob.id == job_id).first()
        if not scan:
            logger.error(f"Scan {job_id} not found in database")
            return

        scan.status = "running"
        scan.started_at = datetime.now(timezone.utc)
        db.commit()
        _log_to_db(job_id, "INFO", f"Starting scan with {scan.tool_name} against {scan.target}")

        record_scan_start(scan.user_id)

        try:
            params = json.loads(scan.parameters) if scan.parameters else {}
            start_time = time.time()

            # Use Shannon orchestrator for multi-step workflow
            orchestrator = ShannonOrchestrator(settings)
            try:
                summary = await orchestrator.run_workflow(
                    scan_id=job_id,
                    target=scan.target,
                    initial_tool=scan.tool_name,
                    initial_params=params,
                    initial_confidence=0.85,
                    user_id=scan.user_id,
                )
                elapsed = time.time() - start_time

                scan.execution_time = round(elapsed, 2)
                scan.findings = json.dumps(summary.get("all_findings", []))
                scan.status = "completed"
                scan.exit_code = 0
                scan.completed_at = datetime.now(timezone.utc)

                _log_to_db(
                    job_id, "INFO",
                    f"Workflow completed in {elapsed:.1f}s — "
                    f"{summary.get('total_tools_run', 1)} tools, "
                    f"depth {summary.get('execution_depth', 1)}"
                )

            except Exception as orch_err:
                # Fallback to single-tool execution if orchestration fails
                logger.warning(f"Orchestration failed, falling back to single tool: {orch_err}")
                _log_to_db(job_id, "WARNING", f"Orchestration failed: {orch_err} — running single tool")

                try:
                    result_single = await orchestrator.run_single_tool(
                        scan_id=job_id,
                        target=scan.target,
                        tool_name=scan.tool_name,
                        params=params,
                        confidence=0.85,
                        user_id=scan.user_id,
                    )
                    elapsed = time.time() - start_time

                    scan.raw_output = result_single.get("raw_output", "")[:settings.TOOL_OUTPUT_MAX_CHARS]
                    scan.execution_time = round(elapsed, 2)
                    scan.findings = json.dumps(result_single.get("findings", []))
                    scan.exit_code = result_single.get("exit_code", 0)
                    scan.status = "completed"
                    scan.completed_at = datetime.now(timezone.utc)

                    _log_to_db(job_id, "INFO", f"Single-tool scan completed in {elapsed:.1f}s")

                except Exception as single_err:
                    raise single_err

        except asyncio.TimeoutError:
            scan.status = "timeout"
            scan.error_message = "Scan exceeded maximum execution time"
            scan.completed_at = datetime.now(timezone.utc)
            _log_to_db(job_id, "ERROR", "Scan timed out")

        except Exception as e:
            scan.status = "failed"
            scan.error_message = str(e)
            scan.completed_at = datetime.now(timezone.utc)
            _log_to_db(job_id, "ERROR", f"Scan failed: {e}")
            logger.exception(f"Scan {job_id} failed")

        finally:
            record_scan_end(scan.user_id)
            db.commit()

    finally:
        db.close()


async def _worker() -> None:
    logger.info("Background scan worker started")
    while True:
        job_id = await scan_queue.get()
        try:
            await _process_scan(job_id)
        except Exception as e:
            logger.exception(f"Worker error processing {job_id}: {e}")
        finally:
            scan_queue.task_done()


# --- App lifecycle ---

@asynccontextmanager
async def lifespan(app: FastAPI):
    global _worker_task

    # Startup
    logger.info("Initializing AlphaWeb Phase 2...")
    init_db()
    logger.info("Database initialized")

    # BaronLLM (Layer 2 — summary) is NOT loaded here. It sleeps until the
    # first tool summary is needed, then lazy-loads on demand (see
    # baron.ensure_loaded in interpret_output). Keeps its 6.6GB GPU model out
    # of memory while only routing/tool execution is happening.
    logger.info("BaronLLM deferred — will lazy-load on first summary")

    # Initialize semantic router (BAAI/bge-small-en-v1.5 embeddings).
    # Non-blocking — if sentence-transformers isn't installed it degrades gracefully.
    try:
        from services.tool_specs import TOOL_SPECS
        await asyncio.to_thread(semantic_router.initialize, TOOL_SPECS)
    except Exception as e:
        logger.warning(f"Semantic router init failed: {e}")

    # Warm Gemma (Layer 1 — tool routing) so the first scan isn't cold.
    if settings.GEMMA_ENABLED:
        try:
            from gemma_client import get_gemma
            gemma = get_gemma(settings)
            warmed = await asyncio.to_thread(gemma.warmup)
            logger.info(f"Gemma warmup: {'ok' if warmed else 'unavailable'}")
        except Exception as e:
            logger.warning(f"Gemma warmup error: {e}")

    # Start background worker
    _worker_task = asyncio.create_task(_worker())
    logger.info("Background worker started")

    yield

    # Shutdown
    if _worker_task:
        _worker_task.cancel()
        try:
            await _worker_task
        except asyncio.CancelledError:
            pass

    # Shutdown AlphaLLM server
    baron = get_baron(settings)
    baron.shutdown()

    logger.info("AlphaWeb shut down")


app = FastAPI(title="AlphaWeb - Cybersecurity Automation Platform", lifespan=lifespan)

# CORS for frontend dev server
from fastapi.middleware.cors import CORSMiddleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://localhost:5174", "http://localhost:5175", "http://localhost:3000", "http://127.0.0.1:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# --- Identity ---

def current_user_id(
    authorization: Optional[str] = Header(default=None),
    x_api_key: Optional[str] = Header(default=None),
) -> str:
    """Resolve the caller from `Authorization: Bearer <token>` or `X-API-Key`."""
    token = x_api_key
    if not token and authorization and authorization.lower().startswith("bearer "):
        token = authorization[7:].strip()
    user_id = resolve_user_id(token, settings.AUTH_REQUIRED)
    if user_id is None:
        raise HTTPException(status_code=401, detail="Missing or invalid API token")
    return user_id


class CreateUserRequest(BaseModel):
    email: Optional[str] = Field(default=None, max_length=255)


class DomainRequest(BaseModel):
    domain: str = Field(min_length=1, max_length=2048)


class VerifyDomainRequest(DomainRequest):
    method: str


def _domain_or_400(raw: str) -> str:
    domain = registrable_domain(raw)
    if domain is None:
        raise HTTPException(status_code=400, detail="Could not derive a verifiable domain or IP from input")
    return domain


# --- Endpoints ---

@app.get("/api/system")
async def system_profile() -> Any:
    """Cookbook view: detected hardware, local models, active choice, recommendation."""
    return await asyncio.to_thread(build_profile, settings.LLM_MODELS_DIR, settings.LLM_MODEL, settings.LLM_HF_MODEL)


@app.post("/api/users", status_code=201)
async def create_user_endpoint(req: CreateUserRequest) -> Any:
    """Create a user. The API token is returned once and cannot be recovered."""
    try:
        return await asyncio.to_thread(create_user, req.email)
    except Exception as e:
        raise HTTPException(status_code=409, detail="Could not create user (email already used?)") from e


@app.post("/api/domains")
async def request_domain_challenge(req: DomainRequest, user_id: str = Depends(current_user_id)) -> Any:
    """Start (or fetch) the ownership challenge for a domain: token + 3 methods."""
    domain = _domain_or_400(req.domain)
    return await asyncio.to_thread(get_or_create_challenge, user_id, domain)


@app.get("/api/domains")
async def list_user_domains(user_id: str = Depends(current_user_id)) -> Any:
    return {"domains": await asyncio.to_thread(list_domains, user_id)}


@app.post("/api/domains/verify")
async def verify_domain(req: VerifyDomainRequest, user_id: str = Depends(current_user_id)) -> Any:
    domain = _domain_or_400(req.domain)
    try:
        return await asyncio.to_thread(check_verification, user_id, domain, req.method)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    except LookupError as e:
        raise HTTPException(status_code=404, detail=str(e)) from e


@app.delete("/api/domains/{domain}")
async def revoke_user_domain(domain: str, user_id: str = Depends(current_user_id)) -> Any:
    reg = _domain_or_400(domain)
    if not await asyncio.to_thread(revoke_domain, user_id, reg):
        raise HTTPException(status_code=404, detail="Domain not found")
    return {"domain": reg, "status": "revoked"}


@app.post("/api/scan", response_model=ScanCreateResponse, status_code=201)
async def create_scan(req: ScanRequest, user_id: str = Depends(current_user_id)) -> Any:
    # Rate limit check
    rate_check = check_rate_limit(user_id, settings.MAX_CONCURRENT_SCANS, settings.SCANS_PER_HOUR_LIMIT)
    if not rate_check.valid:
        raise HTTPException(status_code=429, detail=rate_check.errors)

    # Validate target
    target_check = validate_target_enhanced(req.target)
    if not target_check.valid:
        raise HTTPException(status_code=400, detail=target_check.errors)

    # Queue depth check
    if scan_queue.qsize() >= settings.MAX_QUEUE_DEPTH:
        raise HTTPException(status_code=503, detail="Scan queue is full, try again later")

    # Tool selection — Layer 1 (Gemma) first, deterministic keyword fallback.
    analysis = await asyncio.to_thread(_select_tool_for_scan, req.request, req.target)

    if not analysis.get("safety_checks_passed", False):
        raise HTTPException(status_code=400, detail={
            "error": "Safety checks failed",
            "rationale": analysis.get("rationale", ""),
            "warnings": analysis.get("warnings", []),
        })

    tool_selected = analysis.get("tool_selected")
    if not tool_selected:
        raise HTTPException(status_code=400, detail={
            "error": "Could not determine appropriate tool",
            "rationale": analysis.get("rationale", ""),
        })

    # Ownership gate: Tier-2 tools need a verified domain (Tier 1 passes).
    denial = await asyncio.to_thread(check_tool_access, user_id, tool_selected, req.target)
    if denial:
        raise HTTPException(status_code=403, detail=denial)

    # Sanitize LLM-generated parameters before validation
    params = analysis.get("parameters", {})
    if "ports" in params:
        # Strip ports value if LLM returned something non-numeric (e.g. "common", "top100")
        ports_val = str(params["ports"]).strip()
        if not all(c in "0123456789,- " for c in ports_val) or not ports_val:
            del params["ports"]

    param_check = validate_parameters(tool_selected, params)
    if not param_check.valid:
        raise HTTPException(status_code=400, detail=param_check.errors)

    # Create scan job in DB
    scan_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc)

    db = SessionLocal()
    try:
        scan = ScanJob(
            id=scan_id,
            user_id=user_id,
            target=req.target,
            tool_name=tool_selected,
            status="pending",
            parameters=json.dumps(params),
            created_at=now,
        )
        db.add(scan)
        db.commit()
    finally:
        db.close()

    # Enqueue for background processing
    await scan_queue.put(scan_id)
    logger.info(f"Scan {scan_id} queued: {tool_selected} -> {req.target}")

    return ScanCreateResponse(
        scan_id=scan_id,
        status="pending",
        tool_selected=tool_selected,
        target=req.target,
        created_at=now.isoformat() + "Z",
    )


@app.get("/api/scan/{scan_id}", response_model=ScanDetailResponse)
async def get_scan(scan_id: str) -> Any:
    db = SessionLocal()
    try:
        scan = db.query(ScanJob).filter(ScanJob.id == scan_id).first()
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")

        params = {}
        if scan.parameters:
            try:
                params = json.loads(scan.parameters)
            except json.JSONDecodeError:
                pass

        findings = []
        if scan.findings:
            try:
                findings = json.loads(scan.findings)
            except json.JSONDecodeError:
                pass

        # Fetch workflow steps and anomalies
        workflow_engine = WorkflowEngine(scan_id)
        summary = workflow_engine.get_workflow_summary()

        workflow_steps = [
            WorkflowStepResponse(**step) for step in summary.get("steps", [])
        ]
        anomalies = [
            AnomalyResponse(**a) for a in summary.get("anomalies", [])
        ]

        return ScanDetailResponse(
            scan_id=scan.id,
            status=scan.status,
            tool_used=scan.tool_name,
            target=scan.target,
            parameters=params,
            findings=findings,
            execution_time=scan.execution_time,
            cpu_usage=scan.cpu_usage,
            memory_usage=scan.memory_usage,
            exit_code=scan.exit_code,
            created_at=scan.created_at.isoformat() + "Z" if scan.created_at else "",
            completed_at=scan.completed_at.isoformat() + "Z" if scan.completed_at else None,
            workflow=workflow_steps,
            anomalies=anomalies,
            execution_depth=summary.get("execution_depth", 0),
        )
    finally:
        db.close()


@app.get("/api/scans", response_model=ScanListResponse)
async def list_scans(
    page: int = Query(1, ge=1),
    limit: int = Query(10, ge=1, le=100),
) -> Any:
    db = SessionLocal()
    try:
        total = db.query(ScanJob).count()
        offset = (page - 1) * limit
        scans = (
            db.query(ScanJob)
            .order_by(ScanJob.created_at.desc())
            .offset(offset)
            .limit(limit)
            .all()
        )

        items = [
            ScanListItem(
                scan_id=s.id,
                status=s.status,
                tool_used=s.tool_name,
                target=s.target,
                created_at=s.created_at.isoformat() + "Z" if s.created_at else "",
            )
            for s in scans
        ]

        return ScanListResponse(scans=items, total=total, page=page, limit=limit)
    finally:
        db.close()


@app.get("/api/scan/{scan_id}/workflow", response_model=WorkflowResponse)
async def get_scan_workflow(scan_id: str) -> Any:
    db = SessionLocal()
    try:
        scan = db.query(ScanJob).filter(ScanJob.id == scan_id).first()
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")
    finally:
        db.close()

    workflow_engine = WorkflowEngine(scan_id)
    summary = workflow_engine.get_workflow_summary()

    return WorkflowResponse(
        scan_id=scan_id,
        steps=[WorkflowStepResponse(**s) for s in summary.get("steps", [])],
        anomalies=[AnomalyResponse(**a) for a in summary.get("anomalies", [])],
        execution_depth=summary.get("execution_depth", 0),
        total_tools_run=summary.get("total_tools_run", 0),
    )


@app.post("/analyze-code", response_model=AnalyzeCodeResponse)
async def analyze_code(req: AnalyzeCodeRequest) -> Any:
    from services.code_analyzer import analyze as _analyze

    try:
        result = await asyncio.to_thread(_analyze, req.code, req.language, req.filename)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    tool_error = result.pop("tool_error", None)

    # Fall back to baron/regex if static tool missing
    if tool_error and "Tool not found" in tool_error:
        logger.warning(f"Static analysis tool unavailable: {tool_error} — falling back")
        baron = get_baron(settings)
        if baron.is_loaded:
            fallback = await asyncio.to_thread(
                baron.analyze_code, req.code, result["language"], req.filename
            )
            raw_vulns = fallback.get("vulnerabilities", [])
        else:
            raw_vulns = _fallback_code_analysis(req.code, req.filename)

        counts: Dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for v in raw_vulns:
            sev = v.get("severity", "low").lower()
            if sev in counts:
                counts[sev] += 1

        return AnalyzeCodeResponse(
            analysis_id=result["analysis_id"],
            language=result["language"],
            vulnerabilities=[CodeVulnerability(**v) for v in raw_vulns],
            total_vulnerabilities=len(raw_vulns),
            **counts,
        )

    vulns = [CodeVulnerability(**v) for v in result.pop("vulnerabilities", [])]
    return AnalyzeCodeResponse(vulnerabilities=vulns, **result)


@app.post("/api/validate", response_model=ValidateResponse)
async def validate_scan(req: ValidateRequest) -> Any:
    # Validate target
    target_check = validate_target_enhanced(req.target)
    if not target_check.valid:
        return ValidateResponse(
            valid=False,
            warnings=target_check.errors,
        )

    # Tool selection preview — same path as /api/scan (Gemma → keyword).
    analysis = await asyncio.to_thread(_select_tool_for_scan, req.request, req.target)

    return ValidateResponse(
        valid=analysis.get("safety_checks_passed", False) and analysis.get("tool_selected") is not None,
        tool_selected=analysis.get("tool_selected"),
        confidence=analysis.get("confidence"),
        rationale=analysis.get("rationale"),
        warnings=analysis.get("warnings", []),
    )


@app.get("/health", response_model=HealthResponse)
async def health() -> Any:
    now = datetime.now(timezone.utc)

    # BaronLLM (Layer 2) lazy-loads on first summary. Report it healthy if it
    # is either already loaded or able to load (model + binary present).
    baron = get_baron(settings)
    baronllm_ok = baron.is_loaded or baron.can_load()

    # Gemma (Layer 1) tool routing via Ollama.
    gemma_ok = False
    try:
        from gemma_client import get_gemma
        gemma_ok = (not settings.GEMMA_ENABLED) or get_gemma(settings).is_available()
    except Exception:
        pass

    # Check database
    db_ok = False
    try:
        db = SessionLocal()
        db.execute(__import__("sqlalchemy").text("SELECT 1"))
        db_ok = True
        db.close()
    except Exception:
        pass

    # Check Docker
    docker_ok = False
    try:
        import subprocess
        result = await asyncio.to_thread(
            subprocess.run,
            ["docker", "info"],
            capture_output=True,
            timeout=5,
        )
        docker_ok = result.returncode == 0
    except Exception:
        pass

    all_ok = baronllm_ok and db_ok and docker_ok
    return HealthResponse(
        status="healthy" if all_ok else "degraded",
        timestamp=now.isoformat() + "Z",
        components={
            "baronllm": baronllm_ok,
            "gemma": gemma_ok,
            "database": db_ok,
            "docker": docker_ok,
        },
    )


# --- Chat endpoint (used by AgentChat frontend) ---

class ChatRequest(BaseModel):
    prompt: str = Field(min_length=1, max_length=4096)
    domain: str = Field(min_length=1, max_length=2048)
    # Optional explicit tool selection. When provided and non-empty, these
    # tools are run instead of keyword auto-detection from the prompt.
    tools: Optional[List[str]] = None
    # Optional client-supplied run id, so the client can cancel mid-run.
    run_id: Optional[str] = None
    # Optional per-tool arg overrides — key: tool name, value: arg string.
    # When present, overrides the default args for that tool.
    tool_args: Optional[Dict[str, str]] = None


class ChatResponse(BaseModel):
    ai_message: str
    tool_used: Optional[str] = None
    raw_output: Optional[str] = None
    error: Optional[str] = None
    run_id: Optional[str] = None
    report_url: Optional[str] = None
    next_tool: Optional[str] = None
    suggestion: Optional[str] = None


class CancelRequest(BaseModel):
    run_id: str = Field(min_length=1, max_length=64)


TOOL_DEFAULT_ARGS: Dict[str, str] = {
    "nmap":          "-sV -sC --top-ports 1000",
    "masscan":       "-p1-1000 --rate=500",
    "nikto":         "-h",
    "sqlmap":        "--dbs --batch -u",
    "ffuf":          "-u",
    "gobuster":      "dir -w /wordlists/common.txt -u",
    "hydra":         "",
    "john":          "",
    "tcpdump":       "-c 20",
    "curl":          "-sv",
    "nuclei":        "-u",
    "hashcat":       "",
    "gitleaks":      "detect",
    "theharvester":  "-b all -l 100 -d",
    "subfinder":     "-d",
    "testssl":       "",
    "wapiti":        "-u",
    "wpscan":        "--url",
    "cewl":          "",
    "trivy":         "image",
    "amass":         "enum -passive -d",
    "commix":        "--url",
    "searchsploit":  "",
    "subdominator":  "-d",
    "httpx":         "-silent -status-code -title -tech-detect -u",
}


def _resolve_chat_invocation(
    tool_name: str,
    target: str,
    tool_args: Optional[Dict[str, str]] = None,
) -> tuple[str, str]:
    """Return (args, run_target) for a /chat tool invocation.

    tool_args overrides the default args when provided for this tool.
    The target is normalised per-tool: host-only tools get a bare hostname;
    URL tools get an http(s):// URL.
    """
    run_target = _normalize_target(tool_name, target)

    # Client-supplied arg override takes priority
    if tool_args and tool_name in tool_args:
        return tool_args[tool_name], run_target

    if tool_name == "ffuf":
        url = (_ensure_url(target)).rstrip("/")
        return f"-w /wordlists/common.txt -u {url}/FUZZ", run_target

    args = TOOL_DEFAULT_ARGS.get(tool_name, "")
    return args, run_target


def _resolve_tools(req: "ChatRequest") -> List[str]:
    """Pick the tools to run, in priority order:

      1. Explicit client selection (req.tools) — honoured exactly.
      2. Explicit-intent keyword/tool-name match — unambiguous curated map.
      3. Semantic routing (BAAI/bge-small-en-v1.5) — embedding similarity
         with configurable confidence threshold (default 0.75).
      4. Gemma (Layer 1) natural-language routing — Ollama-based fallback.
      5. Keyword fallback with nmap default — last resort.
    """
    cap = settings.MAX_TOOLS_PER_SCAN
    if req.tools:
        normalized = [TOOL_ALIASES.get(t, t) for t in req.tools]
        valid = [t for t in normalized if t in SUPPORTED_TOOLS]
        if valid:
            seen: set = set()
            out: List[str] = []
            for t in valid:
                if t not in seen:
                    seen.add(t)
                    out.append(t)
                    if len(out) == cap:
                        break
            return out

    # 2. Explicit deterministic intent beats both semantic and Gemma.
    strict = _detect_tools_strict(req.prompt)
    if strict:
        return strict[:cap]

    # 3. Semantic routing — fast, local, no external API.
    sem_results = semantic_router.select_tools(req.prompt, top_k=cap)
    if sem_results:
        top_tool, top_conf = sem_results[0]
        threshold = settings.SEMANTIC_CONFIDENCE_THRESHOLD
        if top_conf >= threshold:
            selected = [t for t, c in sem_results if c >= threshold]
            logger.info(f"Semantic router selected {selected} (top_conf={top_conf:.3f})")
            return selected[:cap]
        else:
            logger.info(
                f"Semantic confidence {top_conf:.3f} < {threshold} "
                "— falling through to Gemma/keyword"
            )

    # 4. Gemma natural-language routing for genuinely ambiguous prompts.
    gemma_tools = _gemma_select_tools(req.prompt, req.domain.strip())
    if gemma_tools:
        return gemma_tools[:cap]

    # 5. Keyword fallback (defaults to nmap when nothing matches).
    return _detect_all_tools(req.prompt)[:cap]


def _gemma_select_tools(prompt: str, target: str) -> List[str]:
    """Use Gemma to pick tools from NL. Returns [] if unavailable/low-confidence.

    The returned names are guaranteed valid (GemmaClient validates against the
    registry); we only additionally apply the confidence gate here.
    """
    if not settings.GEMMA_ENABLED:
        return []
    try:
        from gemma_client import get_gemma
        gemma = get_gemma(settings)
        if not gemma.is_available():
            return []
        sel = gemma.select_tools(prompt, target)
    except Exception as e:
        logger.warning(f"Gemma selection failed: {e}")
        return []

    if not sel or not sel.get("safe", True):
        return []
    if sel.get("confidence", 0.0) < settings.GEMMA_CONFIDENCE_THRESHOLD:
        logger.info(
            f"Gemma confidence {sel.get('confidence'):.2f} below threshold "
            f"{settings.GEMMA_CONFIDENCE_THRESHOLD} — using keyword fallback"
        )
        return []
    tools = [t["tool"] for t in sel.get("tools", [])]
    if tools:
        logger.info(f"Gemma selected tools: {tools} (conf={sel.get('confidence'):.2f})")
    return tools


# Run ids that have been asked to cancel. Checked by the stream loop.
_cancelled_runs: set = set()


@app.post("/chat", response_model=ChatResponse)
async def chat(req: ChatRequest, user_id: str = Depends(current_user_id)) -> Any:
    """Non-streaming fallback — kept for compatibility. Prefer /chat/stream."""
    target = req.domain.strip()
    run_id = req.run_id or uuid.uuid4().hex

    target_check = validate_target_enhanced(target)
    if not target_check.valid:
        return ChatResponse(
            ai_message=f"Invalid target: {target_check.errors[0]}",
            error=target_check.errors[0],
            run_id=run_id,
        )

    tools = _resolve_tools(req)

    async def _run_one(tool_name: str):
        input_err = precheck_tool_input(tool_name, {})
        if input_err:
            return tool_name, "", input_err, -1, 0.0
        denial = await asyncio.to_thread(check_tool_access, user_id, tool_name, target)
        if denial:
            return tool_name, "", denial_text(denial), -1, 0.0
        args, run_target = _resolve_chat_invocation(tool_name, target, req.tool_args)
        try:
            result = await run_tool(
                tool_name=tool_name, args=args, target=run_target,
                settings=settings, run_id=run_id,
            )
            return (tool_name, result.raw_output[:settings.TOOL_OUTPUT_MAX_CHARS],
                    None, result.exit_code, result.execution_time)
        except Exception as exc:
            return tool_name, "", str(exc), -1, 0.0

    results = await asyncio.gather(*[_run_one(t) for t in tools])

    combined_raw = ""
    tools_used: List[str] = []
    tool_errors: List[str] = []
    tool_results: List[Dict[str, Any]] = []
    for tool_name, raw, err, exit_code, duration in results:
        tools_used.append(tool_name)
        tool_results.append({
            "tool": tool_name, "raw_output": raw, "error": err,
            "exit_code": exit_code, "duration": duration,
        })
        if err:
            tool_errors.append(f"{tool_name}: {err}")
            combined_raw += f"\n=== {tool_name.upper()} ERROR ===\n{err}\n"
        else:
            combined_raw += f"\n=== {tool_name.upper()} ===\n{raw}\n"

    baron = get_baron(settings)
    interpret_result: Dict[str, Any] = {}
    # interpret_output does deterministic parsing first and lazy-loads Baron
    # only if that finds nothing — no is_loaded gate needed.
    if combined_raw.strip():
        try:
            interpret_result = await asyncio.to_thread(
                baron.interpret_output, ", ".join(tools_used), combined_raw[:60000], target,
            )
        except Exception as llm_err:
            logger.warning(f"interpret_output failed: {llm_err}")

    summary = interpret_result.get("summary", "")
    suggestion = interpret_result.get("suggestion", "")
    next_tool = interpret_result.get("next_tool")

    llm_analysis = summary
    if suggestion:
        llm_analysis = f"{llm_analysis}\n\nNext step: {suggestion}" if llm_analysis else suggestion

    if not llm_analysis:
        lines = combined_raw.count('\n') + 1
        llm_analysis = (
            f"Ran {', '.join(t.upper() for t in tools_used)} against {target}. "
            f"{lines} lines of output captured."
            + (f"\nErrors: {'; '.join(tool_errors)}" if tool_errors else "")
        )

    report = build_report(
        run_id=run_id, target=target, prompt=req.prompt,
        tool_results=tool_results, analysis=llm_analysis,
        alerts=extract_alerts(tool_results),
    )
    await asyncio.to_thread(save_report, settings.LOG_DIR, run_id, report)

    return ChatResponse(
        ai_message=llm_analysis,
        tool_used=", ".join(tools_used),
        raw_output=combined_raw.strip(),
        run_id=run_id,
        report_url=f"/report/{run_id}",
        next_tool=next_tool,
        suggestion=suggestion,
    )


@app.post("/chat/stream")
async def chat_stream(req: ChatRequest, user_id: str = Depends(current_user_id)):
    """
    SSE streaming endpoint.
    Events:
      data: {"type": "run_start", "run_id": "<id>", "tools": [...]}
      data: {"type": "tool_start", "tool": "<name>"}
      data: {"type": "tool_line", "tool": "<name>", "line": "<text>"}
      data: {"type": "tool_done", "tool": "<name>", "exit_code": <int>}
      data: {"type": "analysis", "content": "<ai text>", "tool_used": "<name,name>"}
      data: {"type": "report", "run_id": "<id>", "report_url": "/report/<id>"}
      data: {"type": "cancelled"}
      data: {"type": "error", "message": "<text>"}
      data: {"type": "done"}
    """
    from fastapi.responses import StreamingResponse
    import asyncio

    target = req.domain.strip()
    run_id = req.run_id or uuid.uuid4().hex
    _cancelled_runs.discard(run_id)

    target_check = validate_target_enhanced(target)
    if not target_check.valid:
        err_msg = target_check.errors[0]
        async def _err():
            yield f'data: {json.dumps({"type": "error", "message": err_msg})}\n\n'
            yield f'data: {json.dumps({"type": "done"})}\n\n'
        return StreamingResponse(_err(), media_type="text/event-stream")

    tools = _resolve_tools(req)

    async def _event_generator():
        combined_raw = ""
        tools_used: List[str] = []
        tool_errors: List[str] = []
        tool_results: List[Dict[str, Any]] = []
        cancelled = False

        yield f'data: {json.dumps({"type": "run_start", "run_id": run_id, "tools": tools})}\n\n'

        for tool_name in tools:
            if run_id in _cancelled_runs:
                cancelled = True
                break

            raw_output = ""
            exit_code = 0
            duration = 0.0

            input_err = precheck_tool_input(tool_name, {})
            if input_err:
                yield f'data: {json.dumps({"type": "tool_start", "tool": tool_name})}\n\n'
                tool_errors.append(f"{tool_name}: {input_err}")
                tools_used.append(tool_name)
                tool_results.append({
                    "tool": tool_name, "raw_output": "", "error": input_err,
                    "exit_code": -1, "duration": 0.0,
                })
                combined_raw += f"\n=== {tool_name.upper()} ERROR ===\n{input_err}\n"
                yield f'data: {json.dumps({"type": "tool_line", "tool": tool_name, "line": f"[ERROR] {input_err}"})}\n\n'
                yield f'data: {json.dumps({"type": "tool_done", "tool": tool_name, "exit_code": -1})}\n\n'
                continue

            # Ownership gate: Tier-2 tools need a verified domain (Tier 1 passes).
            denial = await asyncio.to_thread(check_tool_access, user_id, tool_name, target)
            if denial:
                denial_msg = denial_text(denial)
                yield f'data: {json.dumps({"type": "tool_start", "tool": tool_name})}\n\n'
                tool_errors.append(f"{tool_name}: {denial_msg}")
                tools_used.append(tool_name)
                tool_results.append({
                    "tool": tool_name, "raw_output": "", "error": denial_msg,
                    "exit_code": -1, "duration": 0.0,
                })
                combined_raw += f"\n=== {tool_name.upper()} ERROR ===\n{denial_msg}\n"
                yield f'data: {json.dumps({"type": "tool_line", "tool": tool_name, "line": f"[OWNERSHIP] {denial_msg}"})}\n\n'
                yield f'data: {json.dumps({"type": "tool_done", "tool": tool_name, "exit_code": -1})}\n\n'
                continue

            # Validate + normalize target against tool capability registry
            target_valid, normalized_target, target_err = validate_target_for_tool(target, tool_name)
            if not target_valid:
                yield f'data: {json.dumps({"type": "tool_start", "tool": tool_name})}\n\n'
                tool_errors.append(f"{tool_name}: {target_err}")
                tools_used.append(tool_name)
                tool_results.append({
                    "tool": tool_name, "raw_output": "", "error": target_err,
                    "exit_code": -1, "duration": 0.0,
                })
                combined_raw += f"\n=== {tool_name.upper()} TARGET ERROR ===\n{target_err}\n"
                yield f'data: {json.dumps({"type": "tool_line", "tool": tool_name, "line": f"[TARGET ERROR] {target_err}"})}\n\n'
                yield f'data: {json.dumps({"type": "tool_done", "tool": tool_name, "exit_code": -1})}\n\n'
                continue

            # Use normalized target (e.g. URL → domain when tool needs domain)
            effective_target = normalized_target if normalized_target != target else target

            # Resolve args before announcing tool_start so we can include them in the event
            sem_cmd = semantic_router.select_command(tool_name, req.prompt)
            if sem_cmd and sem_cmd.get("args") and not (req.tool_args and tool_name in req.tool_args):
                logger.info(f"Semantic command for {tool_name}: '{sem_cmd['label']}' (args={sem_cmd['args']!r})")

            args, run_target = _resolve_chat_invocation(tool_name, effective_target, req.tool_args)

            # Announce tool start WITH resolved args so the frontend can display the full command
            yield f'data: {json.dumps({"type": "tool_start", "tool": tool_name, "args": args, "target": run_target})}\n\n'
            try:
                # Run the tool and stream its output line-by-line as it
                # appears — the consumer sees progress in real time.
                line_q: asyncio.Queue = asyncio.Queue()
                run_task = asyncio.create_task(run_tool_streaming(
                    tool_name=tool_name, args=args, target=run_target,
                    settings=settings, run_id=run_id, line_queue=line_q,
                ))

                while True:
                    try:
                        item = await asyncio.wait_for(line_q.get(), timeout=1.0)
                    except asyncio.TimeoutError:
                        # No output yet — keep the connection alive and
                        # honour cancellation requests.
                        if run_id in _cancelled_runs:
                            await asyncio.to_thread(cancel_run, run_id)
                        yield f'data: {json.dumps({"type": "heartbeat"})}\n\n'
                        continue
                    if item is None:
                        break  # sentinel — tool finished
                    yield f'data: {json.dumps({"type": "tool_line", "tool": tool_name, "line": item})}\n\n'

                result = await run_task  # raises if the run task failed
                raw_output = result.raw_output[:settings.TOOL_OUTPUT_MAX_CHARS]
                exit_code = result.exit_code
                duration = result.execution_time

                tools_used.append(tool_name)
                tool_results.append({
                    "tool": tool_name, "raw_output": raw_output, "error": None,
                    "exit_code": exit_code, "duration": duration,
                })
                combined_raw += f"\n=== {tool_name.upper()} ===\n{raw_output}\n"

            except Exception as exc:
                err = str(exc)
                tool_errors.append(f"{tool_name}: {err}")
                tools_used.append(tool_name)
                tool_results.append({
                    "tool": tool_name, "raw_output": "", "error": err,
                    "exit_code": -1, "duration": 0.0,
                })
                combined_raw += f"\n=== {tool_name.upper()} ERROR ===\n{err}\n"
                yield f'data: {json.dumps({"type": "tool_line", "tool": tool_name, "line": f"[ERROR] {err}"})}\n\n'

            yield f'data: {json.dumps({"type": "tool_done", "tool": tool_name, "exit_code": exit_code})}\n\n'

            if run_id in _cancelled_runs:
                cancelled = True
                break

        # LLM analysis after all tools finish. interpret_output parses
        # deterministically first and lazy-loads Baron only when needed —
        # no is_loaded gate. Timeout is generous to absorb a cold start
        # (first summary may start llama-server, ~30-60s).
        baron = get_baron(settings)
        interpret_result: Dict[str, Any] = {}
        if combined_raw.strip():
            yield f'data: {json.dumps({"type": "analyzing"})}\n\n'
            try:
                interpret_result = await asyncio.wait_for(
                    asyncio.to_thread(
                        baron.interpret_output,
                        ", ".join(tools_used), combined_raw[:60000], target,
                    ),
                    timeout=120,
                )
            except asyncio.TimeoutError:
                logger.warning("interpret_output timed out — using plain summary")
            except Exception as llm_err:
                logger.warning(f"interpret_output failed: {llm_err}")

        summary = interpret_result.get("summary", "")
        suggestion = interpret_result.get("suggestion", "")
        next_tool = interpret_result.get("next_tool")

        llm_analysis = summary
        if suggestion:
            llm_analysis = f"{llm_analysis}\n\nNext step: {suggestion}" if llm_analysis else suggestion

        if not llm_analysis:
            lines = combined_raw.count('\n') + 1
            ran = ", ".join(t.upper() for t in tools_used) or "no tools"
            llm_analysis = (
                f"Ran {ran} against {target}. {lines} lines of output captured."
                + (f"\nErrors: {'; '.join(tool_errors)}" if tool_errors else "")
            )
        if cancelled:
            llm_analysis = "[Scan cancelled by user]\n" + llm_analysis

        yield f'data: {json.dumps({"type": "analysis", "content": llm_analysis, "tool_used": ", ".join(tools_used), "next_tool": next_tool, "suggestion": suggestion})}\n\n'

        # Extract vulnerability alerts from the collected output
        alerts = extract_alerts(tool_results)
        yield f'data: {json.dumps({"type": "alerts", "alerts": alerts, "counts": severity_counts(alerts)})}\n\n'

        # Persist the report and tell the client where to find it
        if tool_results:
            report = build_report(
                run_id=run_id, target=target, prompt=req.prompt,
                tool_results=tool_results, analysis=llm_analysis, alerts=alerts,
            )
            try:
                await asyncio.to_thread(save_report, settings.LOG_DIR, run_id, report)
                yield f'data: {json.dumps({"type": "report", "run_id": run_id, "report_url": f"/report/{run_id}"})}\n\n'
            except Exception as rep_err:
                logger.warning(f"save_report failed: {rep_err}")

        if cancelled:
            yield f'data: {json.dumps({"type": "cancelled"})}\n\n'
        _cancelled_runs.discard(run_id)
        yield f'data: {json.dumps({"type": "done"})}\n\n'

    return StreamingResponse(
        _event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )


@app.post("/chat/cancel")
async def chat_cancel(req: CancelRequest) -> Any:
    """Cancel an in-flight scan: kill its containers and stop the chain."""
    _cancelled_runs.add(req.run_id)
    killed = await asyncio.to_thread(cancel_run, req.run_id)
    logger.info(f"Cancel requested for run {req.run_id} — killed {killed} container(s)")
    return {"run_id": req.run_id, "cancelled": True, "containers_killed": killed}


@app.get("/tools")
async def list_tools() -> Any:
    """List every available tool with a short capability description."""
    from llm_client import TOOL_DESCRIPTIONS
    return {
        "tools": [
            {"name": name, "description": TOOL_DESCRIPTIONS.get(name, "")}
            for name in SUPPORTED_TOOLS
        ],
        "total": len(SUPPORTED_TOOLS),
    }


@app.get("/report/{run_id}")
async def get_report(run_id: str) -> Any:
    """Serve the rendered HTML scan report (viewable in a browser tab)."""
    from fastapi.responses import HTMLResponse

    safe_id = re.sub(r"[^A-Za-z0-9_-]", "", run_id)[:64]
    html_doc = load_report_html(settings.LOG_DIR, safe_id)
    if not html_doc:
        raise HTTPException(status_code=404, detail="Report not found")
    return HTMLResponse(content=html_doc)


@app.get("/report/{run_id}/download")
async def download_report(run_id: str) -> Any:
    """Download the HTML scan report as a file attachment."""
    from fastapi.responses import HTMLResponse

    safe_id = re.sub(r"[^A-Za-z0-9_-]", "", run_id)[:64]
    html_doc = load_report_html(settings.LOG_DIR, safe_id)
    if not html_doc:
        raise HTTPException(status_code=404, detail="Report not found")
    return HTMLResponse(
        content=html_doc,
        headers={
            "Content-Disposition": f'attachment; filename="alphaweb-report-{safe_id}.html"',
        },
    )


@app.get("/report/{run_id}/pdf")
async def download_report_pdf(run_id: str) -> Any:
    """Download a single scan report as a PDF attachment."""
    from fastapi.responses import Response

    safe_id = re.sub(r"[^A-Za-z0-9_-]", "", run_id)[:64]
    report = load_report(settings.LOG_DIR, safe_id)
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    pdf_bytes = await asyncio.to_thread(render_reports_pdf, [report])
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="alphaweb-report-{safe_id}.pdf"',
        },
    )


@app.get("/reports/pdf")
async def download_all_reports_pdf(
    run_ids: Optional[str] = Query(None, description="Comma-separated run ids; defaults to all"),
) -> Any:
    """Bundle every scan report (or a given subset) into one combined PDF.

    This is the 'Generate' action: after running tools the client requests
    this to get a single PDF of all scan reports.
    """
    from fastapi.responses import Response

    if run_ids:
        ids = [re.sub(r"[^A-Za-z0-9_-]", "", x)[:64] for x in run_ids.split(",") if x.strip()]
        reports = [r for r in (load_report(settings.LOG_DIR, i) for i in ids) if r]
    else:
        reports = await asyncio.to_thread(load_all_reports, settings.LOG_DIR)

    if not reports:
        raise HTTPException(status_code=404, detail="No reports available to generate")

    pdf_bytes = await asyncio.to_thread(render_reports_pdf, reports)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="alphaweb-reports-{stamp}.pdf"',
        },
    )


# --- Database management ---

class DatabaseResetResponse(BaseModel):
    reset: bool
    deleted: Dict[str, int]
    reports_deleted: int


@app.post("/database/reset", response_model=DatabaseResetResponse)
async def reset_database() -> Any:
    """Wipe all user scan data, keeping seeded tool definitions intact.

    User-initiated. Clears scan_jobs, execution_logs, workflow_steps,
    anomalies and every persisted report. tool_definitions are preserved.
    """
    deleted: Dict[str, int] = {}
    db = SessionLocal()
    try:
        # Delete children before parents to satisfy FK constraints.
        deleted["anomalies"] = db.query(Anomaly).delete(synchronize_session=False)
        deleted["execution_logs"] = db.query(ExecutionLog).delete(synchronize_session=False)
        deleted["workflow_steps"] = db.query(WorkflowStep).delete(synchronize_session=False)
        deleted["scan_jobs"] = db.query(ScanJob).delete(synchronize_session=False)
        db.commit()
    except Exception as e:
        db.rollback()
        logger.exception("Database reset failed")
        raise HTTPException(status_code=500, detail=f"Reset failed: {e}") from e
    finally:
        db.close()

    reports_deleted = await asyncio.to_thread(delete_all_reports, settings.LOG_DIR)
    logger.info(f"Database reset by user — deleted {deleted}, {reports_deleted} report files")
    return DatabaseResetResponse(reset=True, deleted=deleted, reports_deleted=reports_deleted)


# --- Legacy endpoint ---

@app.post("/execute", response_model=ExecuteResponse)
async def execute(req: ExecuteRequest, user_id: str = Depends(current_user_id)) -> Any:
    start = time.time()
    request_id = os.urandom(8).hex()

    try:
        validated = parse_and_validate_execute_request(req)

        denial = await asyncio.to_thread(check_tool_access, user_id, validated.tool, validated.target)
        if denial:
            raise HTTPException(status_code=403, detail=denial)

        # Sanitise the optional run_id so a cancel request can target it.
        safe_run_id = re.sub(r"[^A-Za-z0-9_-]", "", req.run_id or "")[:64] or None

        # Coerce the target into the form this tool expects.
        norm_target = _normalize_target(validated.tool, validated.target)

        run_result = await run_tool(
            tool_name=validated.tool,
            args=validated.args,
            target=norm_target,
            settings=settings,
            run_id=safe_run_id,
        )

        elapsed_ms = int((time.time() - start) * 1000)
        logger.info(
            json.dumps(
                {
                    "request_id": request_id,
                    "tool_used": validated.tool,
                    "target": validated.target,
                    "elapsed_ms": elapsed_ms,
                },
                ensure_ascii=False,
            )
        )

        return ExecuteResponse(
            tool_used=validated.tool,
            raw_output=run_result.raw_output[: settings.TOOL_OUTPUT_MAX_CHARS],
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.exception("Execution failed")
        raise HTTPException(status_code=500, detail=str(e)) from e


# --- Fallback tool selection (when BaronLLM is not loaded) ---

# Old/alternate tool names that map to the current registry name. Lets a user
# who types a legacy name (e.g. "sublist3r") still hit the right tool.
TOOL_ALIASES = {
    "sublist3r": "subfinder",
}

KEYWORD_TOOL_MAP = {
    "port": "nmap",
    "scan port": "nmap",
    "service": "nmap",
    "nmap": "nmap",
    "mass scan": "masscan",
    "masscan": "masscan",
    "fast scan": "masscan",
    "vulnerability": "nikto",
    "vuln": "nikto",
    "web server": "nikto",
    "web scan": "nikto",
    "website scan": "nikto",
    "web server scan": "nikto",
    "http scan": "nikto",
    "site scan": "nikto",
    "web check": "nikto",
    "nikto": "nikto",
    "sql injection": "sqlmap",
    "sqli": "sqlmap",
    "sqlmap": "sqlmap",
    "database": "sqlmap",
    "fuzz": "ffuf",
    "endpoint": "ffuf",
    "ffuf": "ffuf",
    "directory": "gobuster",
    "dns": "gobuster",
    "gobuster": "gobuster",
    "brute": "hydra",
    "credential": "hydra",
    "password": "hydra",
    "hydra": "hydra",
    "hash": "john",
    "crack": "john",
    "john": "john",
    "curl": "curl",
    "api": "curl",
    "http request": "curl",
    "packet": "tcpdump",
    "capture": "tcpdump",
    "tcpdump": "tcpdump",
    "traffic": "tcpdump",
    "nuclei": "nuclei",
    "template": "nuclei",
    "cve": "nuclei",
    "hashcat": "hashcat",
    "gpu": "hashcat",
    "gitleaks": "gitleaks",
    "secret": "gitleaks",
    "leak": "gitleaks",
    "git": "gitleaks",
    "theharvester": "theharvester",
    "harvester": "theharvester",
    "osint": "theharvester",
    "email harvest": "theharvester",
    "subfinder": "subfinder",
    "sublist3r": "subfinder",
    "subdomain enum": "subfinder",
    "subdomain": "subfinder",
    "find subdomains": "subfinder",
    "enumerate subdomains": "subfinder",
    "testssl": "testssl",
    "tls": "testssl",
    "ssl": "testssl",
    "cipher": "testssl",
    "certificate": "testssl",
    "wapiti": "wapiti",
    "web vuln": "wapiti",
    "xss": "wapiti",
    "wpscan": "wpscan",
    "wordpress": "wpscan",
    "wp scan": "wpscan",
    "cewl": "cewl",
    "wordlist": "cewl",
    "trivy": "trivy",
    "container": "trivy",
    "image scan": "trivy",
    "amass": "amass",
    "asset discovery": "amass",
    "attack surface": "amass",
    "commix": "commix",
    "command injection": "commix",
    "cmdi": "commix",
    "searchsploit": "searchsploit",
    "exploit": "searchsploit",
    "exploitdb": "searchsploit",
    "subdominator": "subdominator",
    "subdomain takeover": "subdominator",
    "takeover": "subdominator",
    "httpx": "httpx",
    "probe": "httpx",
    "fingerprint": "httpx",
    "web probe": "httpx",
}


def _detect_tools_strict(request_text: str) -> List[str]:
    """Deterministic tool detection WITHOUT the nmap default.

    Returns the tools the prompt explicitly asks for — by tool name or by a
    curated capability keyword — or [] when the prompt expresses no clear
    intent. Word-boundary matching so substrings never select a tool.
    """
    text = request_text.lower()
    cap = settings.MAX_TOOLS_PER_SCAN

    # 1. Explicit tool names (and aliases) — exclusive.
    named: List[str] = []
    for tool in SUPPORTED_TOOLS:
        if re.search(rf"\b{re.escape(tool)}\b", text):
            named.append(tool)
    for alias, tool in TOOL_ALIASES.items():
        if tool not in named and re.search(rf"\b{re.escape(alias)}\b", text):
            named.append(tool)
    if named:
        return named[:cap]

    # 2. Capability keywords — word-boundary on both sides (optional plural 's').
    found: List[str] = []
    seen: set = set()
    for keyword, tool in KEYWORD_TOOL_MAP.items():
        if tool in seen:
            continue
        if re.search(rf"\b{re.escape(keyword)}s?\b", text):
            found.append(tool)
            seen.add(tool)
            if len(found) == cap:
                break
    return found


def _detect_all_tools(request_text: str) -> List[str]:
    """Strict detection, but defaulting to a single nmap port scan when the
    prompt matches nothing."""
    found = _detect_tools_strict(request_text)
    return found if found else ["nmap"]


def _select_tool_for_scan(request_text: str, target: str) -> Dict[str, Any]:
    """Pick a single tool for /api/scan. Gemma first, keyword fallback.

    Returns the legacy analysis dict shape used by create_scan(). The tool
    name is always either a registry-valid Gemma pick or a keyword match —
    never a hallucinated name.
    """
    if settings.GEMMA_ENABLED:
        try:
            from gemma_client import get_gemma
            gemma = get_gemma(settings)
            if gemma.is_available():
                sel = gemma.select_tools(request_text, target)
                if sel and sel.get("tools"):
                    if not sel.get("safe", True):
                        return {
                            "tool_selected": None, "confidence": sel.get("confidence", 0.0),
                            "parameters": {}, "rationale": "Request flagged unsafe by router",
                            "safety_checks_passed": False,
                            "warnings": ["Gemma flagged request as unsafe"],
                        }
                    if sel.get("confidence", 0.0) >= settings.GEMMA_CONFIDENCE_THRESHOLD:
                        first = sel["tools"][0]
                        return {
                            "tool_selected": first["tool"],
                            "confidence": sel["confidence"],
                            "parameters": first.get("parameters", {}),
                            "rationale": first.get("rationale", f"Gemma selected {first['tool']}"),
                            "safety_checks_passed": True,
                            "warnings": [],
                        }
        except Exception as e:
            logger.warning(f"Gemma scan selection failed: {e}")

    return _fallback_tool_selection(request_text)


def _fallback_tool_selection(request_text: str) -> Dict[str, Any]:
    text = request_text.lower()
    selected = None
    for tool in SUPPORTED_TOOLS:
        if re.search(rf"\b{re.escape(tool)}\b", text):
            selected = tool
            break
    if not selected:
        for keyword, tool in KEYWORD_TOOL_MAP.items():
            if re.search(rf"\b{re.escape(keyword)}", text):
                selected = tool
                break

    if selected:
        return {
            "tool_selected": selected,
            "confidence": 0.75,
            "parameters": {},
            "rationale": f"Keyword-based fallback selected {selected}",
            "safety_checks_passed": True,
            "warnings": ["BaronLLM unavailable - using keyword fallback"],
        }

    return {
        "tool_selected": None,
        "confidence": 0.3,
        "parameters": {},
        "rationale": "Could not determine appropriate tool from request",
        "safety_checks_passed": False,
        "warnings": ["BaronLLM unavailable", "No matching tool found"],
    }


def _fallback_code_analysis(code: str, filename: Optional[str] = None) -> List[Any]:
    """Basic pattern-based code vulnerability detection when BaronLLM is unavailable."""
    import re as _re
    vulns = []
    lines = code.splitlines()

    patterns = [
        (_re.compile(r"""(api[_-]?key|secret|password|token)\s*[=:]\s*["'][^"']+["']""", _re.IGNORECASE),
         "critical", "hardcoded_secret", "Hardcoded secret or credential detected",
         "Use environment variables or a secrets manager"),
        (_re.compile(r"eval\s*\(", _re.IGNORECASE),
         "high", "code_injection", "Use of eval() — potential code injection",
         "Replace eval() with safer alternatives like JSON.parse() or ast.literal_eval()"),
        (_re.compile(r"(exec|system|popen|subprocess\.call)\s*\(", _re.IGNORECASE),
         "high", "command_injection", "Command execution — potential injection risk",
         "Use subprocess with shell=False and parameterized arguments"),
        (_re.compile(r"(SELECT|INSERT|UPDATE|DELETE)\s+.*\+.*['\"]", _re.IGNORECASE),
         "high", "sql_injection", "Possible SQL injection via string concatenation",
         "Use parameterized queries or ORM"),
        (_re.compile(r"innerHTML\s*=", _re.IGNORECASE),
         "medium", "xss", "innerHTML assignment — potential XSS",
         "Use textContent or a sanitization library like DOMPurify"),
        (_re.compile(r"(MD5|SHA1)\s*\(", _re.IGNORECASE),
         "medium", "weak_crypto", "Weak hashing algorithm detected",
         "Use SHA-256 or bcrypt for hashing"),
        (_re.compile(r"verify\s*=\s*False", _re.IGNORECASE),
         "high", "ssl_bypass", "SSL verification disabled",
         "Enable SSL verification; use verify=True"),
        (_re.compile(r"chmod\s+777", _re.IGNORECASE),
         "medium", "insecure_permissions", "Overly permissive file permissions",
         "Use minimal permissions (e.g., chmod 644 or 755)"),
    ]

    for line_num, line in enumerate(lines, 1):
        for pattern, severity, vuln_type, issue, fix in patterns:
            if pattern.search(line):
                vulns.append({
                    "type": vuln_type,
                    "severity": severity,
                    "line": line_num,
                    "code_snippet": line.strip()[:120],
                    "issue": issue,
                    "fix": fix,
                    "file": filename,
                })

    return vulns


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "app:app",
        host=settings.ORCHESTRATOR_HOST,
        port=settings.ORCHESTRATOR_PORT,
        reload=False,
    )
