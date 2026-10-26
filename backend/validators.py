from __future__ import annotations

import ipaddress
import re
import socket
from collections import defaultdict
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

from pydantic import BaseModel, ConfigDict, Field

from tool_tiers import TOOL_TIERS


# Derived from tool_tiers.TOOL_TIERS (single source of truth for the catalog).
SUPPORTED_TOOLS = list(TOOL_TIERS)

# --- Pydantic models for the legacy /execute endpoint ---

class ExecuteRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tool: str
    args: str = ""
    target: str = Field(min_length=1, max_length=4096)
    run_id: Optional[str] = Field(default=None, max_length=64)


class ExecuteResponse(BaseModel):
    tool_used: str
    raw_output: str


# --- Pydantic models for Phase 1 endpoints ---

class ScanRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    target: str = Field(min_length=1, max_length=255)
    request: str = Field(min_length=1, max_length=2048)


class ValidateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    target: str = Field(min_length=1, max_length=255)
    request: str = Field(min_length=1, max_length=2048)


class ValidationResult(BaseModel):
    valid: bool
    errors: List[str] = []


# --- Forbidden patterns ---

_FORBIDDEN_IN_TARGET = re.compile(r"[;\|&`$<>\"\']")
_FORBIDDEN_IN_ARGS = re.compile(r"[;\|&`$<>\"\r\n]")

# Private/reserved IP ranges
BLOCKED_IP_RANGES = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]

BLOCKED_HOSTNAMES = {"localhost", "localhost.localdomain", "ip6-localhost", "ip6-loopback"}

# Dangerous flags per tool
DANGEROUS_FLAGS: Dict[str, List[str]] = {
    "nmap": ["-T5", "-T4", "--script=exploit", "-aggressive", "--destructive"],
    "masscan": ["--rate=10000", "-aggressive", "--destructive"],
    "nikto": ["-aggressive", "--destructive"],
    "sqlmap": ["--os-shell", "--os-pwn", "-aggressive", "--destructive", "-X"],
    "ffuf": ["-aggressive", "--destructive", "-X"],
    "gobuster": ["-aggressive", "--destructive", "-X"],
    "hydra": ["-aggressive", "--destructive", "-X"],
    "john": ["-aggressive", "--destructive"],
    "curl": ["-aggressive", "--destructive", "-X"],
    "tcpdump": ["-aggressive", "--destructive"],
    "nuclei": ["-aggressive", "--destructive"],
    "hashcat": ["-aggressive", "--destructive"],
    "gitleaks": ["-aggressive", "--destructive"],
    "theharvester": ["-aggressive", "--destructive"],
    "subfinder": ["-aggressive", "--destructive"],
    "testssl": ["-aggressive", "--destructive"],
    "wapiti": ["-aggressive", "--destructive"],
    "wpscan": ["--aggressive", "--destructive"],
    "cewl": ["-aggressive", "--destructive"],
    "trivy": ["-aggressive", "--destructive"],
    "amass": ["-aggressive", "--destructive"],
    "commix": ["--os-shell", "--os-pwn", "-aggressive", "--destructive"],
    "searchsploit": ["-aggressive", "--destructive"],
    "subdominator": ["-aggressive", "--destructive"],
    "httpx": ["-aggressive", "--destructive"],
}

# --- Rate limiting state ---

_user_scan_counts: Dict[str, List[datetime]] = defaultdict(list)
_user_active_scans: Dict[str, int] = defaultdict(int)


# --- Target validation ---

def _is_private_ip(ip_str: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip_str)
        for network in BLOCKED_IP_RANGES:
            if addr in network:
                return True
        return False
    except ValueError:
        return False


def _resolve_and_check(hostname: str) -> Tuple[bool, Optional[str]]:
    if hostname.lower() in BLOCKED_HOSTNAMES:
        return True, "Target resolves to blocked hostname"
    try:
        results = socket.getaddrinfo(hostname, None)
        for _family, _type, _proto, _canonname, sockaddr in results:
            ip = sockaddr[0]
            if _is_private_ip(ip):
                return True, f"Target resolves to private IP: {ip}"
    except socket.gaierror:
        pass
    return False, None


def validate_target_enhanced(target: str) -> ValidationResult:
    errors = []

    if not target or not target.strip():
        return ValidationResult(valid=False, errors=["Target is empty"])

    target = target.strip()

    # Check for shell metacharacters
    if _FORBIDDEN_IN_TARGET.search(target):
        errors.append("Target contains forbidden characters")
        return ValidationResult(valid=False, errors=errors)

    # Extract hostname from URL if needed
    hostname = target
    if "://" in target:
        try:
            from urllib.parse import urlparse
            parsed = urlparse(target)
            hostname = parsed.hostname or target
        except Exception:
            pass

    # Check direct IP
    if _is_private_ip(hostname):
        errors.append("Target is a private/reserved IP address")
        return ValidationResult(valid=False, errors=errors)

    # Check blocked hostnames
    if hostname.lower() in BLOCKED_HOSTNAMES:
        errors.append("Target resolves to localhost")
        return ValidationResult(valid=False, errors=errors)

    # DNS resolution check
    is_blocked, reason = _resolve_and_check(hostname)
    if is_blocked:
        errors.append(reason)
        return ValidationResult(valid=False, errors=errors)

    return ValidationResult(valid=True)


def validate_parameters(tool_name: str, parameters: Dict) -> ValidationResult:
    errors = []

    # Check for dangerous flags
    dangerous = DANGEROUS_FLAGS.get(tool_name, [])
    params_str = str(parameters)
    for flag in dangerous:
        if flag in params_str:
            errors.append(f"Dangerous flag detected: {flag}")

    # Validate port ranges if present
    ports = parameters.get("ports", "")
    if ports:
        if not _validate_port_range(str(ports)):
            errors.append("Parameter 'ports' must be valid port numbers (1-65535)")

    # Validate timeout if present
    timeout = parameters.get("timeout")
    if timeout is not None:
        try:
            t = int(timeout)
            if t < 30:
                errors.append("Timeout must be at least 30 seconds")
            elif t > 600:
                errors.append("Timeout must not exceed 600 seconds")
        except (ValueError, TypeError):
            errors.append("Timeout must be a numeric value")

    if errors:
        return ValidationResult(valid=False, errors=errors)
    return ValidationResult(valid=True)


def _validate_port_range(ports_str: str) -> bool:
    parts = ports_str.replace(" ", "").split(",")
    for part in parts:
        if "-" in part:
            bounds = part.split("-", 1)
            if len(bounds) != 2:
                return False
            try:
                low, high = int(bounds[0]), int(bounds[1])
                if not (1 <= low <= 65535 and 1 <= high <= 65535 and low <= high):
                    return False
            except ValueError:
                return False
        else:
            try:
                port = int(part)
                if not (1 <= port <= 65535):
                    return False
            except ValueError:
                return False
    return True


# --- Rate limiting ---

def check_rate_limit(user_id: str, max_concurrent: int, max_per_hour: int) -> ValidationResult:
    now = datetime.now(timezone.utc)

    # Check concurrent scans
    active = _user_active_scans.get(user_id, 0)
    if active >= max_concurrent:
        return ValidationResult(
            valid=False,
            errors=[f"Maximum {max_concurrent} concurrent scans exceeded"]
        )

    # Check hourly limit - prune old entries
    hour_ago = now.timestamp() - 3600
    _user_scan_counts[user_id] = [
        t for t in _user_scan_counts[user_id]
        if t.timestamp() > hour_ago
    ]

    if len(_user_scan_counts[user_id]) >= max_per_hour:
        return ValidationResult(
            valid=False,
            errors=[f"Maximum {max_per_hour} scans per hour exceeded"]
        )

    return ValidationResult(valid=True)


def record_scan_start(user_id: str) -> None:
    _user_active_scans[user_id] = _user_active_scans.get(user_id, 0) + 1
    _user_scan_counts[user_id].append(datetime.now(timezone.utc))


def record_scan_end(user_id: str) -> None:
    _user_active_scans[user_id] = max(0, _user_active_scans.get(user_id, 0) - 1)


# --- Legacy validation (kept for /execute endpoint compatibility) ---

def validate_tool_name(tool: str) -> str:
    tool = (tool or "").strip()
    if tool not in SUPPORTED_TOOLS:
        raise ValueError(f"Unsupported tool: {tool!r}")
    return tool


def _validate_no_whitespace(s: str, field_name: str) -> None:
    if any(ch.isspace() for ch in s):
        raise ValueError(f"{field_name} must not contain whitespace.")


def validate_target(target: str, tool: str, *, john_filename_only: bool = False) -> str:
    target = (target or "").strip()
    if not target:
        raise ValueError("target is empty.")

    if _FORBIDDEN_IN_TARGET.search(target):
        raise ValueError("target contains forbidden characters.")

    _validate_no_whitespace(target, "target")

    if tool == "john":
        basename = target
        if john_filename_only:
            if "/" in basename or "\\" in basename:
                raise ValueError("john target must be a simple filename.")
        if not re.match(r"^[A-Za-z0-9_.-]{1,255}$", basename):
            raise ValueError("john target must be a safe filename.")
        return basename

    if tool == "tcpdump":
        if not re.match(r"^[A-Za-z0-9_.:-]{1,64}$", target):
            raise ValueError("tcpdump target must look like an interface name.")
        return target

    if len(target) > 2048:
        raise ValueError("target is too long.")

    # subdominator enumerates subdomains *under* the given name, so it needs
    # a bare root domain. Strip any scheme, path and leading "www." prefix.
    if tool == "subdominator":
        host = target
        if "://" in host:
            from urllib.parse import urlparse
            host = urlparse(host).hostname or host
        host = host.split("/")[0].split(":")[0]
        if host.lower().startswith("www."):
            host = host[4:]
        if not re.match(r"^[A-Za-z0-9.-]{1,253}$", host):
            raise ValueError("subdominator target must be a valid domain.")
        return host

    if "://" in target:
        m = re.match(r"^https?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]+$", target)
        if not m:
            raise ValueError("target URL contains invalid characters.")
        return target

    m = re.match(
        r"^[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]+$",
        target,
    )
    if not m:
        raise ValueError("target contains invalid characters.")
    return target


def validate_args_string(args: Optional[str]) -> str:
    args = (args or "").strip()
    if not args:
        return ""

    if len(args) > 8192:
        raise ValueError("args is too long.")

    if _FORBIDDEN_IN_ARGS.search(args):
        raise ValueError("args contains forbidden characters.")

    if "\n" in args or "\r" in args:
        raise ValueError("args must not contain newlines.")

    return args


def parse_and_validate_execute_request(req: ExecuteRequest) -> ExecuteRequest:
    tool = validate_tool_name(req.tool)
    args = validate_args_string(req.args)
    target = validate_target(
        req.target,
        tool,
        john_filename_only=True,
    )

    return ExecuteRequest(tool=tool, args=args, target=target)
