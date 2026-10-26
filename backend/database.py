from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
    create_engine,
    text,
)
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from config import Settings
from tool_tiers import TOOL_TIERS


class Base(DeclarativeBase):
    pass


DEFAULT_USER_ID = "default-user"


class User(Base):
    __tablename__ = "users"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    email = Column(String(255), unique=True)
    # sha256 of the API token; the token itself is shown once at creation.
    token_hash = Column(String(64), unique=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))


class VerifiedDomain(Base):
    __tablename__ = "verified_domains"
    __table_args__ = (UniqueConstraint("user_id", "domain", name="uq_verified_domains_user_domain"),)

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String(36), ForeignKey("users.id"), nullable=False)
    domain = Column(String(255), nullable=False)  # registrable domain (or IP)
    method = Column(String(20))  # dns_txt | html_file | meta_tag (last method tried)
    token = Column(String(80), nullable=False)
    status = Column(String(20), nullable=False, default="pending")  # pending|verified|failed|revoked
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    verified_at = Column(DateTime)
    last_checked_at = Column(DateTime)


class ScanJob(Base):
    __tablename__ = "scan_jobs"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String(36), ForeignKey("users.id", name="fk_scan_jobs_user"), nullable=False)
    target = Column(String(255), nullable=False)
    tool_name = Column(String(50), nullable=False)
    status = Column(String(20), nullable=False, default="pending")
    parameters = Column(Text, default="{}")
    findings = Column(Text, default="{}")
    raw_output = Column(Text)
    execution_time = Column(Float)
    cpu_usage = Column(Float)
    memory_usage = Column(Float)
    network_sent = Column(Integer)
    network_received = Column(Integer)
    exit_code = Column(Integer)
    error_message = Column(Text)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    started_at = Column(DateTime)
    completed_at = Column(DateTime)


class ToolDefinition(Base):
    __tablename__ = "tool_definitions"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name = Column(String(50), unique=True, nullable=False)
    docker_image = Column(String(255), nullable=False)
    timeout = Column(Integer, default=300)
    allowed_parameters = Column(Text)
    dangerous_flags = Column(Text)
    description = Column(Text)
    use_cases = Column(Text)
    # 1 = no ownership needed, 2 = verified domain ownership required.
    # Source of truth is tool_tiers.TOOL_TIERS; the seed syncs this column.
    tier = Column(Integer, nullable=False, default=2, server_default="2")
    enabled = Column(Boolean, default=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime)


class ExecutionLog(Base):
    __tablename__ = "execution_logs"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_id = Column(String(36), ForeignKey("scan_jobs.id"), nullable=False)
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    log_level = Column(String(10))
    message = Column(Text)


class WorkflowStep(Base):
    __tablename__ = "workflow_steps"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_id = Column(String(36), ForeignKey("scan_jobs.id"), nullable=False)
    parent_step_id = Column(String(36), ForeignKey("workflow_steps.id"), nullable=True)
    execution_order = Column(Integer, nullable=False, default=0)
    tool_name = Column(String(50), nullable=False)
    confidence = Column(Float, default=0.0)
    parameters = Column(Text, default="{}")
    findings = Column(Text, default="[]")
    raw_output = Column(Text)
    execution_time = Column(Float)
    cpu_usage = Column(Float)
    memory_usage = Column(Float)
    exit_code = Column(Integer)
    status = Column(String(20), nullable=False, default="pending")
    error_message = Column(Text)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    completed_at = Column(DateTime)


class Anomaly(Base):
    __tablename__ = "anomalies"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_id = Column(String(36), ForeignKey("scan_jobs.id"), nullable=False)
    step_id = Column(String(36), ForeignKey("workflow_steps.id"), nullable=True)
    anomaly_type = Column(String(50), nullable=False)
    severity = Column(String(20), nullable=False)
    confidence = Column(Float, default=0.0)
    details = Column(Text, default="{}")
    suggestion = Column(Text)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))


# Engine and session factory
engine = create_engine(Settings.DATABASE_URL, echo=False)
SessionLocal = sessionmaker(bind=engine)


def init_db() -> None:
    Base.metadata.create_all(bind=engine)
    # create_all does not add columns to an existing table (no Alembic here).
    with engine.begin() as conn:
        conn.execute(text(
            "ALTER TABLE tool_definitions "
            "ADD COLUMN IF NOT EXISTS tier INTEGER NOT NULL DEFAULT 2"
        ))
    _ensure_users()
    _seed_tool_definitions()


def _ensure_users() -> None:
    """Seed the default user, backfill users for existing scans, add the scan FK."""
    with engine.begin() as conn:
        conn.execute(
            text("INSERT INTO users (id, created_at) VALUES (:id, now()) ON CONFLICT (id) DO NOTHING"),
            {"id": DEFAULT_USER_ID},
        )
        # Scans created before the users table existed carry bare user_id strings.
        conn.execute(text(
            "INSERT INTO users (id, created_at) "
            "SELECT DISTINCT user_id, now() FROM scan_jobs ON CONFLICT (id) DO NOTHING"
        ))
        # create_all does not alter an existing scan_jobs table; add the FK once.
        conn.execute(text(
            "DO $$ BEGIN "
            "IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'fk_scan_jobs_user') THEN "
            "ALTER TABLE scan_jobs ADD CONSTRAINT fk_scan_jobs_user "
            "FOREIGN KEY (user_id) REFERENCES users(id); "
            "END IF; END $$"
        ))


def get_db() -> Session:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


TOOL_SEED_DATA = [
    {"name": "nmap", "docker_image": "nmap", "description": "Port scanning, service discovery", "use_cases": '["port scanning", "service detection", "OS fingerprinting"]', "dangerous_flags": '["-T5", "-T4", "--script=exploit"]', "timeout": 300},
    {"name": "masscan", "docker_image": "masscan", "description": "Fast mass port scanning", "use_cases": '["mass scanning", "large network enumeration"]', "dangerous_flags": '["--rate=10000"]', "timeout": 300},
    {"name": "nikto", "docker_image": "nikto", "description": "Web server vulnerability scanning", "use_cases": '["web vulnerability scanning", "server misconfiguration"]', "dangerous_flags": '[]', "timeout": 600},
    {"name": "sqlmap", "docker_image": "sqlmap", "description": "SQL injection testing", "use_cases": '["SQL injection", "database enumeration"]', "dangerous_flags": '["--os-shell", "--os-pwn"]', "timeout": 600},
    {"name": "ffuf", "docker_image": "ffuf", "description": "Web fuzzing, endpoint discovery", "use_cases": '["fuzzing", "endpoint discovery", "parameter brute-forcing"]', "dangerous_flags": '[]', "timeout": 300},
    {"name": "gobuster", "docker_image": "gobuster", "description": "Directory and DNS enumeration", "use_cases": '["directory brute-forcing", "DNS enumeration", "vhost discovery"]', "dangerous_flags": '[]', "timeout": 300},
    {"name": "hydra", "docker_image": "hydra", "description": "Credential brute-forcing", "use_cases": '["password brute-forcing", "credential testing"]', "dangerous_flags": '[]', "timeout": 600},
    {"name": "john", "docker_image": "john", "description": "Password hash cracking", "use_cases": '["hash cracking", "password recovery"]', "dangerous_flags": '[]', "timeout": 600},
    {"name": "curl", "docker_image": "curl", "description": "Web requests, API testing", "use_cases": '["HTTP requests", "API testing", "header inspection"]', "dangerous_flags": '[]', "timeout": 120},
    {"name": "tcpdump", "docker_image": "tcpdump", "description": "Packet capture and analysis", "use_cases": '["packet capture", "traffic analysis"]', "dangerous_flags": '[]', "timeout": 300},
    {"name": "nuclei", "docker_image": "nuclei", "description": "Template-based vulnerability scanning", "use_cases": '["vulnerability scanning", "CVE detection", "template-based scanning"]', "dangerous_flags": '[]', "timeout": 600},
    {"name": "hashcat", "docker_image": "hashcat", "description": "Advanced password hash cracking", "use_cases": '["hash cracking", "password recovery", "GPU-accelerated cracking"]', "dangerous_flags": '[]', "timeout": 3600},
    {"name": "gitleaks", "docker_image": "gitleaks", "description": "Git repository secret scanning", "use_cases": '["secret detection", "API key scanning", "credential leak detection"]', "dangerous_flags": '[]', "timeout": 300},
    {"name": "theharvester", "docker_image": "theharvester", "description": "OSINT email, subdomain and host harvesting", "use_cases": '["OSINT", "email harvesting", "subdomain discovery"]', "dangerous_flags": '[]', "timeout": 300},
    {"name": "subfinder", "docker_image": "subfinder", "description": "Passive subdomain enumeration", "use_cases": '["subdomain enumeration", "passive recon"]', "dangerous_flags": '[]', "timeout": 300},
    {"name": "testssl", "docker_image": "testssl", "description": "TLS/SSL configuration and cipher testing", "use_cases": '["TLS audit", "cipher suite testing", "certificate checks"]', "dangerous_flags": '[]', "timeout": 300},
    {"name": "wapiti", "docker_image": "wapiti", "description": "Web application vulnerability scanner", "use_cases": '["SQLi", "XSS", "SSRF", "LFI detection"]', "dangerous_flags": '[]', "timeout": 900},
    {"name": "wpscan", "docker_image": "wpscan", "description": "WordPress vulnerability scanner", "use_cases": '["WordPress plugin/theme vulnerabilities", "user enumeration"]', "dangerous_flags": '[]', "timeout": 600},
    {"name": "cewl", "docker_image": "cewl", "description": "Custom wordlist generator via site spidering", "use_cases": '["wordlist generation", "password list building"]', "dangerous_flags": '[]', "timeout": 300},
    {"name": "trivy", "docker_image": "trivy", "description": "Container image and filesystem vulnerability scanner", "use_cases": '["container scanning", "dependency vulnerabilities", "misconfiguration detection"]', "dangerous_flags": '[]', "timeout": 300},
    {"name": "amass", "docker_image": "amass", "description": "DNS enumeration and attack surface mapping", "use_cases": '["DNS enumeration", "asset discovery", "attack surface mapping"]', "dangerous_flags": '[]', "timeout": 600},
    {"name": "commix", "docker_image": "commix", "description": "Command injection detection", "use_cases": '["command injection testing"]', "dangerous_flags": '["--os-shell", "--os-pwn"]', "timeout": 900},
    {"name": "searchsploit", "docker_image": "searchsploit", "description": "Offline exploit database search", "use_cases": '["CVE lookup", "exploit search"]', "dangerous_flags": '[]', "timeout": 60},
    {"name": "subdominator", "docker_image": "subdominator", "description": "Passive subdomain takeover detection", "use_cases": '["subdomain takeover detection"]', "dangerous_flags": '[]', "timeout": 300},
    {"name": "httpx", "docker_image": "httpx", "description": "HTTP probing and web fingerprinting", "use_cases": '["HTTP probing", "tech detection", "status code checks"]', "dangerous_flags": '[]', "timeout": 120},
]

# Fail at import if the seed catalog and the allow-list ever diverge again.
_seed_names = {t["name"] for t in TOOL_SEED_DATA}
if _seed_names != set(TOOL_TIERS) or len(_seed_names) != len(TOOL_SEED_DATA):
    raise RuntimeError(
        "TOOL_SEED_DATA out of sync with tool_tiers.TOOL_TIERS: "
        f"missing={sorted(set(TOOL_TIERS) - _seed_names)} "
        f"extra={sorted(_seed_names - set(TOOL_TIERS))}"
    )


def _seed_tool_definitions() -> None:
    """Insert missing tools and sync `tier` from TOOL_TIERS (idempotent).

    Existing rows keep their other (possibly admin-edited) fields; only
    the tier is authoritative from code.
    """
    db = SessionLocal()
    try:
        existing = {t.name: t for t in db.query(ToolDefinition).all()}
        for tool_data in TOOL_SEED_DATA:
            tier = TOOL_TIERS[tool_data["name"]]
            row = existing.get(tool_data["name"])
            if row is None:
                db.add(ToolDefinition(**tool_data, tier=tier))
            elif row.tier != tier:
                row.tier = tier
        db.commit()
    finally:
        db.close()
