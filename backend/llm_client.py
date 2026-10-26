from __future__ import annotations

import json
import logging
import os
import subprocess
import threading
import time
import urllib.request
import urllib.error
from typing import Any, Dict, List, Optional

from config import Settings

logger = logging.getLogger("orchestrator")

TOOL_DESCRIPTIONS = {
    "nmap": "port scanning, service discovery, OS fingerprinting",
    "masscan": "fast mass port scanning across large networks",
    "nikto": "web server vulnerability scanning",
    "sqlmap": "SQL injection testing and database enumeration",
    "ffuf": "web fuzzing, endpoint and parameter discovery",
    "gobuster": "directory brute-forcing, DNS enumeration",
    "hydra": "credential brute-forcing against network services",
    "john": "password hash cracking",
    "curl": "HTTP requests, API testing, header inspection",
    "tcpdump": "network packet capture and traffic analysis",
    "nuclei": "template-based vulnerability scanning and CVE detection",
    "hashcat": "advanced GPU-accelerated password hash cracking",
    "gitleaks": "git repository secret scanning and credential leak detection",
    "theharvester": "OSINT email, subdomain, host, and employee harvesting from public sources",
    "subfinder": "passive subdomain enumeration across many DNS sources",
    "testssl": "TLS/SSL configuration testing, cipher suite auditing, and certificate checks",
    "wapiti": "web application vulnerability scanner (SQLi, XSS, SSRF, LFI, etc.)",
    "wpscan": "WordPress vulnerability scanner — plugins, themes, users, CVEs",
    "cewl": "custom wordlist generator by spidering a target website",
    "trivy": "container image and filesystem vulnerability and misconfiguration scanner",
    "amass": "in-depth DNS enumeration, asset discovery, and attack surface mapping",
    "commix": "automated command injection detection and exploitation",
    "searchsploit": "offline exploit database search for CVEs and known vulnerabilities",
    "subdominator": "fast passive subdomain takeover detection",
    "httpx": "fast HTTP probing, status codes, tech detection, and web fingerprinting",
}

AVAILABLE_TOOLS = list(TOOL_DESCRIPTIONS.keys())

# Grammar-enforced schema for tool selection. tool_selected is an ENUM of the
# real tool names (+ null), so the decoder cannot hallucinate a tool.
TOOL_SELECTION_SCHEMA: Dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "tool_selected": {"enum": AVAILABLE_TOOLS + [None]},
        "confidence":    {"type": "number", "minimum": 0.0, "maximum": 1.0},
        "parameters":    {"type": "object"},
        "rationale":     {"type": "string"},
        "safety_checks_passed": {"type": "boolean"},
        "warnings":      {"type": "array", "items": {"type": "string"}},
    },
    "required": ["tool_selected", "confidence", "parameters",
                 "rationale", "safety_checks_passed", "warnings"],
}

# Pre-built at module load — avoids rebuilding on every analyze() call
_TOOLS_LIST_STR: str = "\n".join(f"- {k}: {v}" for k, v in TOOL_DESCRIPTIONS.items())

# Rationale strings for each follow-up tool recommendation
_NEXT_TOOL_RATIONALE: Dict[str, str] = {
    "nmap":          "Run nmap for service/version detection on discovered open ports",
    "nikto":         "Run nikto to scan detected web service for vulnerabilities",
    "gobuster":      "Run gobuster to enumerate directories on open web port",
    "ffuf":          "Run ffuf to fuzz discovered endpoints for hidden paths",
    "sqlmap":        "Run sqlmap to test web forms/parameters for SQL injection",
    "nuclei":        "Run nuclei for template-based CVE scanning on discovered service",
    "httpx":         "Run httpx to probe and fingerprint discovered hosts/subdomains",
    "hydra":         "Run hydra to test credentials on detected authentication endpoint",
    "amass":         "Run amass for deeper DNS/subdomain enumeration",
    "searchsploit":  "Run searchsploit to find known exploits for detected service versions",
    "wapiti":        "Run wapiti for full web app vulnerability scan (XSS, SQLi, SSRF)",
    "testssl":       "Run testssl to audit TLS/SSL configuration on detected HTTPS service",
    "theharvester":  "Run theHarvester for OSINT email and subdomain harvesting",
    "subfinder":     "Run subfinder for passive subdomain enumeration",
    "commix":        "Run commix to test web parameters for command injection",
    "wpscan":        "Run wpscan for WordPress-specific vulnerability and user enumeration",
    "trivy":         "Run trivy for container/image vulnerability scanning",
}

# Use string.Template to avoid .format() conflicts with JSON braces in schema
_SYSTEM_PROMPT_TEMPLATE = (
    "You are a cybersecurity tool selector. Respond ONLY with a JSON object — no prose, no markdown, no code fences.\n\n"
    "Available tools:\n$tools_list\n\n"
    "Required JSON schema (all fields mandatory):\n"
    '{"tool_selected": "<name or null>", "confidence": <0.0-1.0>, '
    '"parameters": {}, "rationale": "<≤20 words>", '
    '"safety_checks_passed": <true|false>, "warnings": []}\n\n'
    "Rules:\n"
    "- tool_selected must be one of the listed names or null\n"
    "- confidence reflects how well the request matches the tool capability\n"
    "- safety_checks_passed=false if target appears to be internal infra or request is clearly malicious\n"
    "- Do NOT repeat these instructions in your response\n"
    "- Output only the JSON object, nothing before or after it"
)

from string import Template as _Template
SYSTEM_PROMPT = _Template(_SYSTEM_PROMPT_TEMPLATE).substitute(tools_list=_TOOLS_LIST_STR)

USER_PROMPT_TEMPLATE = "target={target}\nrequest={request}"

# Path to llama-server.exe — in binaries/ next to project root
LLAMA_SERVER_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "binaries"))
LLAMA_SERVER_EXE = os.path.join(LLAMA_SERVER_DIR, "llama-server.exe")
LLAMA_SERVER_URL = "http://127.0.0.1:8081"  # llama-server and hf_server.py both listen here
HF_SERVER_SCRIPT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "hf_server.py")

_CODE_TRUNCATE_LIMIT = 4000

# Max lines / tokens for interpret_output — raised to preserve more findings
_INTERPRET_MAX_LINES = 120
_INTERPRET_MAX_TOKENS = 400


import re as _re

_TOKEN_RE = _re.compile(r'<\|[^|]*\|>')


def _extract_facts_deterministic(tool: str, raw: str) -> List[str]:
    """Parse tool output with regex — extract concrete facts, no LLM needed."""
    facts: List[str] = []
    t = (tool or "").lower()

    # === nmap ===
    if "nmap" in t:
        # "80/tcp open  http  nginx 1.18.0"
        for m in _re.finditer(r'^(\d+)/(tcp|udp)\s+(\w+)\s+(\S+)(?:\s+(.+))?$', raw, _re.M):
            port, proto, state, svc, ver = m.group(1), m.group(2), m.group(3), m.group(4), m.group(5)
            if state == "open":
                ver_str = f" ({ver.strip()})" if ver else ""
                facts.append(f"Port {port}/{proto} open: {svc}{ver_str}")
        for m in _re.finditer(r'OS details:\s*(.+)', raw):
            facts.append(f"OS detected: {m.group(1).strip()}")
        for m in _re.finditer(r'(\d+)\s+(?:filtered|closed)\s+(?:tcp\s+)?ports?', raw):
            facts.append(f"{m.group(1)} ports filtered/closed")

    # === httpx ===
    elif "httpx" in t:
        # "https://x [200] [Title] [Tech]"
        for line in raw.splitlines():
            m = _re.search(r'(https?://\S+)\s+\[(\d+)\](?:\s+\[([^\]]+)\])?(?:\s+\[([^\]]+)\])?', line)
            if m:
                url, code, title, tech = m.group(1), m.group(2), m.group(3), m.group(4)
                facts.append(f"{url} returned HTTP {code}")
                if title:
                    facts.append(f"Page title: {title}")
                if tech:
                    facts.append(f"Tech stack: {tech}")

    # === curl ===
    elif "curl" in t:
        for m in _re.finditer(r'^HTTP/[\d.]+\s+(\d+)\s*(.*)$', raw, _re.M | _re.I):
            facts.append(f"HTTP response: {m.group(1)} {m.group(2).strip()}")
        for hdr in ("Server", "X-Powered-By", "Content-Type", "Strict-Transport-Security"):
            m = _re.search(rf'^{hdr}:\s*(.+)$', raw, _re.M | _re.I)
            if m:
                facts.append(f"{hdr}: {m.group(1).strip()[:60]}")

    # === testssl ===
    elif "testssl" in t:
        for m in _re.finditer(r'(TLSv?\d\.\d|SSLv?\d)\s+(?:offered|not offered|supported|deprecated)', raw):
            facts.append(f"Protocol: {m.group(0)}")
        if _re.search(r'Heartbleed.*not vulnerable', raw, _re.I):
            facts.append("Heartbleed: not vulnerable")
        if _re.search(r'BREACH.*VULNERABLE', raw):
            facts.append("BREACH: vulnerable")

    # === sqlmap ===
    elif "sqlmap" in t:
        for m in _re.finditer(r"available databases \[\d+\]:\s*([^\n]+)", raw):
            facts.append(f"Databases: {m.group(1).strip()[:80]}")
        if _re.search(r"is vulnerable", raw, _re.I):
            facts.append("Target appears vulnerable to SQL injection")
        for m in _re.finditer(r'web (?:application|server) technology:\s*(.+)', raw, _re.I):
            facts.append(f"Web tech: {m.group(1).strip()[:60]}")

    # === nikto ===
    elif "nikto" in t:
        for line in raw.splitlines():
            if line.startswith("+ ") and len(line) > 5 and "Target" not in line and "Start Time" not in line:
                facts.append(line[2:].strip()[:120])

    # === nuclei ===
    elif "nuclei" in t:
        # "[template-id] [type] [severity] url"
        for m in _re.finditer(r'\[([^\]]+)\]\s+\[([^\]]+)\]\s+\[([^\]]+)\]\s+(\S+)', raw):
            tpl, typ, sev, url = m.groups()
            facts.append(f"{sev.upper()}: {tpl} ({typ}) on {url}")

    # === gobuster / ffuf ===
    elif t in ("gobuster", "ffuf"):
        for m in _re.finditer(r'^(/\S+)\s+\(?Status:?\s*(\d+)\)?', raw, _re.M):
            facts.append(f"Found path {m.group(1)} (status {m.group(2)})")
        for m in _re.finditer(r'^([\w._-]+)\s+\[Status:\s*(\d+),', raw, _re.M):
            facts.append(f"Found {m.group(1)} (status {m.group(2)})")

    # === subfinder / amass / subdominator ===
    elif t in ("subfinder", "amass", "subdominator"):
        subs = set()
        for line in raw.splitlines():
            line = _re.sub(r'\x1b\[[0-9;]*m', '', line).strip()  # strip ANSI
            m = _re.match(r'^([\w-]+(?:\.[\w-]+)+)$', line)
            if m and len(m.group(1)) < 80:
                subs.add(m.group(1))
        if subs:
            sub_list = sorted(subs)[:10]
            facts.append(f"Found {len(subs)} subdomain(s): {', '.join(sub_list[:5])}" + ("..." if len(subs) > 5 else ""))

    # === wpscan ===
    elif "wpscan" in t:
        if "WordPress" in raw and "not detected" in raw.lower():
            facts.append("WordPress not detected on target")
        for m in _re.finditer(r'WordPress version\s+([\d.]+)', raw):
            facts.append(f"WordPress version: {m.group(1)}")

    # === gitleaks ===
    elif "gitleaks" in t:
        m = _re.search(r'(\d+)\s+leaks? found', raw, _re.I)
        if m:
            facts.append(f"{m.group(1)} secret leak(s) found")
        elif "no leaks found" in raw.lower():
            facts.append("No secret leaks found")

    # === searchsploit ===
    elif "searchsploit" in t:
        if "No Results" in raw:
            facts.append("No matching exploits found in database")
        else:
            count = len([l for l in raw.splitlines() if "|" in l and "----" not in l])
            if count > 1:
                facts.append(f"Found ~{count - 1} matching exploit(s) in database")

    # === theharvester ===
    elif "theharvester" in t:
        if "No emails found" in raw:
            facts.append("No emails harvested")
        if "No hosts found" in raw:
            facts.append("No hosts harvested")
        emails = _re.findall(r'[\w.+-]+@[\w-]+\.[\w.-]+', raw)
        if emails:
            facts.append(f"Found {len(set(emails))} email(s)")

    # === cewl ===  (wordlist generator — count words, don't "interpret" them)
    elif "cewl" in t:
        words = []
        for line in raw.splitlines():
            w = line.strip()
            # skip banner / blank / non-word lines
            if not w or w.startswith("CeWL") or "Robin Wood" in w or w.startswith(("http", "[", "-")):
                continue
            if _re.fullmatch(r"[A-Za-z][A-Za-z0-9'-]*", w):
                words.append(w)
        if words:
            uniq = len(set(w.lower() for w in words))
            sample = ", ".join(words[:8])
            facts.append(f"Generated {len(words)} words ({uniq} unique) from target")
            facts.append(f"Sample: {sample}")
        else:
            facts.append("No words generated from target")

    # === masscan ===
    elif "masscan" in t:
        for m in _re.finditer(r'Discovered open port (\d+)/(tcp|udp) on (\S+)', raw):
            facts.append(f"Open port {m.group(1)}/{m.group(2)} on {m.group(3)}")

    # === hydra ===  (credential brute-force)
    elif "hydra" in t:
        creds = _re.findall(r'\[\d+\]\[[^\]]+\]\s+host:\s*(\S+)\s+login:\s*(\S+)\s+password:\s*(\S+)', raw)
        for host, login, pw in creds:
            facts.append(f"Valid credential: {login}:{pw} on {host}")
        if not creds:
            m = _re.search(r'(\d+)\s+valid passwords? found', raw, _re.I)
            if m:
                facts.append(f"{m.group(1)} valid credential(s) found")
            elif _re.search(r'0 valid passwords? found|could not connect', raw, _re.I):
                facts.append("No valid credentials found")

    # === hashcat ===  (hash cracking)
    elif "hashcat" in t:
        if _re.search(r'Status\.+:\s*Cracked', raw, _re.I) or _re.search(r':\s*\w+\s*$', raw, _re.M):
            cracked = _re.findall(r'^([0-9a-fA-F]{16,}):(.+)$', raw, _re.M)
            for h, plain in cracked[:5]:
                facts.append(f"Cracked hash -> {plain.strip()}")
            if not cracked:
                facts.append("Hash cracked (see output)")
        elif _re.search(r'Status\.+:\s*Exhausted', raw, _re.I):
            facts.append("Wordlist exhausted — hash not cracked")
        m = _re.search(r'Recovered\.+:\s*(\d+)/(\d+)', raw)
        if m:
            facts.append(f"Recovered {m.group(1)}/{m.group(2)} hashes")

    # === john ===  (hash cracking)
    elif t == "john" or "john the ripper" in t:
        # "password         (user)"  cracked lines
        cracked = _re.findall(r'^(\S+)\s+\(([^)]+)\)\s*$', raw, _re.M)
        for pw, user in cracked[:8]:
            if pw.lower() not in ("loaded", "using", "press"):
                facts.append(f"Cracked: {user} -> {pw}")
        if not cracked:
            if "No password hashes loaded" in raw:
                facts.append("No valid hashes loaded from file")
            elif _re.search(r'\b0g\b|0 password hashes cracked', raw):
                facts.append("No hashes cracked")
        m = _re.search(r'(\d+)g\s+\d+:', raw)
        if m and int(m.group(1)) > 0:
            facts.append(f"{m.group(1)} hash(es) cracked")

    # === trivy ===  (container/fs vuln scan)
    elif "trivy" in t:
        sev_counts: Dict[str, int] = {}
        for m in _re.finditer(r'\b(CRITICAL|HIGH|MEDIUM|LOW|UNKNOWN)\b', raw):
            sev_counts[m.group(1)] = sev_counts.get(m.group(1), 0) + 1
        # Trivy summary line: "Total: 12 (HIGH: 4, CRITICAL: 1)"
        m = _re.search(r'Total:\s*(\d+)\s*\(([^)]*)\)', raw)
        if m:
            facts.append(f"Total {m.group(1)} vulnerabilities ({m.group(2).strip()})")
        elif sev_counts:
            parts = ", ".join(f"{k}: {v}" for k, v in sev_counts.items())
            facts.append(f"Vulnerabilities by severity — {parts}")
        for m in _re.finditer(r'(CVE-\d{4}-\d+)', raw):
            facts.append(f"CVE found: {m.group(1)}")
            if len([f for f in facts if f.startswith("CVE found")]) >= 5:
                break

    # === commix ===  (command injection)
    elif "commix" in t:
        if _re.search(r"(is vulnerable|appears to be injectable|injection point)", raw, _re.I):
            facts.append("Target appears vulnerable to command injection")
        for m in _re.finditer(r'Parameter:\s*(\S+)', raw):
            facts.append(f"Injectable parameter: {m.group(1)}")
        if _re.search(r"all tested parameters.*not injectable|does not seem to be injectable", raw, _re.I):
            facts.append("No command injection found")

    # === wapiti ===  (web app vuln scanner)
    elif "wapiti" in t:
        for m in _re.finditer(r'(?:Found|Detected)\s+(\d+)\s+([A-Za-z ]+?)(?: vulnerabilit)', raw, _re.I):
            facts.append(f"{m.group(1)} {m.group(2).strip()} vulnerability(ies)")
        for vuln in ("SQL Injection", "Cross Site Scripting", "XSS", "SSRF",
                     "Path Traversal", "Command execution", "CRLF"):
            if _re.search(rf'\b{_re.escape(vuln)}\b', raw, _re.I):
                facts.append(f"Found: {vuln}")
        # de-dupe handled by _format_facts later

    # === tcpdump ===  (packet capture)
    elif "tcpdump" in t:
        m = _re.search(r'(\d+)\s+packets? captured', raw)
        if m:
            facts.append(f"{m.group(1)} packets captured")
        protos: Dict[str, int] = {}
        for pm in _re.finditer(r'\b(TCP|UDP|ICMP|ARP|HTTP|DNS|TLS)\b', raw):
            protos[pm.group(1)] = protos.get(pm.group(1), 0) + 1
        if protos:
            top = ", ".join(f"{k}: {v}" for k, v in sorted(protos.items(), key=lambda x: -x[1])[:4])
            facts.append(f"Protocols seen — {top}")

    # === Generic fallback: count exit status ===
    if not facts:
        if "0 hosts up" in raw or "Host seems down" in raw:
            facts.append("Target appears to be down or filtered")

    return facts


def _clean_llm_output(raw: str) -> str:
    """Last-resort cleaner for LLM output. Used only when deterministic parser finds nothing."""
    for stop_pat in ('<|im_start|>', '<|im_end|>', '<|input_expected|>', 'tool=', '==OUTPUT==', 'FINDINGS', 'RISK'):
        idx = raw.find(stop_pat)
        if idx > 50:  # keep some content if stop tag appears late
            raw = raw[:idx]
        elif idx == 0:
            raw = raw[len(stop_pat):]

    text = _TOKEN_RE.sub('', raw).strip()
    sentences: List[str] = []
    for chunk in text.splitlines():
        chunk = chunk.strip()
        if not chunk:
            continue
        chunk = _re.sub(r'^[•\*\-]\s+', '', chunk)
        chunk = _re.sub(r'^\d+[.)]\s+', '', chunk)
        for s in _re.split(r'\.\s+(?=[A-Z])', chunk):
            s = s.strip().rstrip('.')
            if 10 <= len(s) <= 140:
                sentences.append(s)

    seen: set = set()
    out: List[str] = []
    for s in sentences:
        key = _re.sub(r'\s+', ' ', s.lower())
        if key in seen:
            continue
        seen.add(key)
        out.append(f"{len(out)+1}. {s}.")
        if len(out) >= 6:
            break

    return "\n".join(out) if out else "1. No significant findings."


def _format_facts(facts: List[str]) -> str:
    """Format extracted facts as numbered list."""
    if not facts:
        return "1. No significant findings."
    out = []
    seen: set = set()
    for f in facts[:8]:
        f = f.strip().rstrip('.')
        key = f.lower()
        if key in seen:
            continue
        seen.add(key)
        out.append(f"{len(out)+1}. {f}.")
    return "\n".join(out)


def _infer_next_tool(tool_name: str, facts: List[str], raw_output: str) -> Optional[str]:
    """Deterministic next-tool recommendation from current tool output. No LLM needed."""
    import re as _r
    # Handle multi-tool names like "nmap, httpx" — use last tool run
    t = tool_name.lower().split(",")[-1].strip()
    raw_lower = raw_output.lower()

    if "masscan" in t:
        if _r.search(r"(discovered open port|open port \d+)", raw_lower):
            return "nmap"

    if "nmap" in t:
        if _r.search(r"(http|https|apache|nginx|iis|tomcat|lighttpd|jetty)", raw_lower):
            return "nikto"
        if _r.search(r"\d+/(tcp|udp)\s+open", raw_lower):
            return "gobuster"

    if "nikto" in t:
        if _r.search(r"(osvdb|cve-|sql|injection|xss|form|parameter)", raw_lower):
            return "sqlmap"
        if _r.search(r"(login|auth|signin|admin|password)", raw_lower):
            return "hydra"
        return "nuclei"

    if t in ("gobuster", "ffuf"):
        if _r.search(r"(status.*200|status.*301|status.*302|\(status: 200\))", raw_lower):
            return "nuclei"

    if t in ("subfinder", "amass", "subdominator", "theharvester"):
        # only chain if something hostname-like actually came back
        if _r.search(r"(?:[a-z0-9-]+\.)+[a-z]{2,}", raw_lower):
            return "httpx"

    if "httpx" in t:
        if _r.search(r"\[(?:200|301|302|401|403)\]|(?:200|301|302)", raw_lower):
            return "nikto"

    if "ffuf" in t:
        if _r.search(r"(status.*200|status.*301|status.*302)", raw_lower):
            return "nuclei"

    if "nuclei" in t:
        if _r.search(r"(cve-|critical|high|medium)", raw_lower):
            return "searchsploit"

    if "wapiti" in t:
        if _r.search(r"(sql|injection|xss|vulnerab)", raw_lower):
            return "sqlmap"

    if "testssl" in t:
        if _r.search(r"(vulnerable|heartbleed|breach|sweet32|poodle)", raw_lower):
            return "nuclei"

    if "wpscan" in t:
        if _r.search(r"(username|user found|plugin|vulnerability|cve-)", raw_lower):
            return "searchsploit"

    return None


class LLMError(Exception):
    """Typed error from BaronLLM HTTP calls."""


class BaronLLM:
    """AlphaLLM client — talks to llama-server.exe via HTTP API."""

    def __init__(self, settings: Settings):
        self._settings = settings
        self._loaded = False
        self._server_proc: Optional[subprocess.Popen] = None
        self._load_lock = threading.Lock()
        # llama-server `usage` dict from the most recent _chat call (eval cost metric).
        self.last_usage: Optional[Dict[str, Any]] = None

    def ensure_loaded(self) -> bool:
        """Lazy-load the model on first use. Thread-safe; idempotent.

        BaronLLM sleeps until a summary is actually requested, then starts
        llama-server here. Subsequent calls return immediately.
        """
        if self._loaded:
            return True
        with self._load_lock:
            if self._loaded:
                return True
            return self.load()

    def can_load(self) -> bool:
        """True if the model file and llama-server binary are present.

        Cheap check — does not start the server. Used by /health so a sleeping
        (not-yet-loaded) Baron still reports healthy.
        """
        if self._settings.LLM_HF_MODEL:
            return os.path.isfile(self._settings.LLM_HF_PYTHON) and os.path.isfile(HF_SERVER_SCRIPT)
        model_path = os.path.abspath(self._settings.BARONLLM_MODEL_PATH)
        return os.path.isfile(model_path) and os.path.isfile(LLAMA_SERVER_EXE)

    def load(self) -> bool:
        use_hf = bool(self._settings.LLM_HF_MODEL)
        if use_hf:
            if not (os.path.isfile(self._settings.LLM_HF_PYTHON) and os.path.isfile(HF_SERVER_SCRIPT)):
                logger.error(f"HF model server unavailable: need {self._settings.LLM_HF_PYTHON} "
                             f"(virtualenv with torch/transformers/bitsandbytes) and {HF_SERVER_SCRIPT}")
                return False
        else:
            model_path = os.path.abspath(self._settings.BARONLLM_MODEL_PATH)
            if not os.path.isfile(model_path):
                logger.error(f"AlphaLLM model file not found: {model_path}")
                return False

            if not os.path.isfile(LLAMA_SERVER_EXE):
                logger.error(f"llama-server.exe not found: {LLAMA_SERVER_EXE}")
                return False

        if self._is_server_healthy():
            logger.info("AlphaLLM server already running")
            self._loaded = True
            return True

        try:
            if use_hf:
                cmd = [self._settings.LLM_HF_PYTHON, HF_SERVER_SCRIPT,
                       "--model", self._settings.LLM_HF_MODEL, "--port", "8081"]
                # Log to a file: a full stderr pipe would stall the server mid-load.
                os.makedirs(self._settings.LOG_DIR, exist_ok=True)
                server_log = open(os.path.join(self._settings.LOG_DIR, "hf_server.log"), "ab")
                popen_kwargs: Dict[str, Any] = {"stdout": server_log, "stderr": server_log,
                                                "cwd": os.path.dirname(HF_SERVER_SCRIPT)}
                budget = 300.0  # first start loads multi-GB weights and initialises CUDA
            else:
                cmd = [
                    LLAMA_SERVER_EXE,
                    "-m", model_path,
                    "--host", "127.0.0.1",
                    "--port", "8081",
                    "-ngl", str(self._settings.BARONLLM_N_GPU_LAYERS or 35),
                    "-c", str(self._settings.BARONLLM_N_CTX),
                ]
                popen_kwargs = {"stdout": subprocess.PIPE, "stderr": subprocess.PIPE, "cwd": LLAMA_SERVER_DIR}
                budget = 60.0
            logger.info(f"Starting AlphaLLM server: {' '.join(cmd)}")

            self._server_proc = subprocess.Popen(cmd, **popen_kwargs)

            # Exponential backoff: 1s, 2s, 4s, 8s... capped at 16s
            delay = 1.0
            elapsed = 0.0
            while elapsed < budget:
                time.sleep(delay)
                elapsed += delay
                if self._is_server_healthy():
                    self._loaded = True
                    logger.info(f"AlphaLLM server started and healthy (waited {elapsed:.0f}s)")
                    return True
                if self._server_proc.poll() is not None:
                    if self._server_proc.stderr is not None:
                        stderr = self._server_proc.stderr.read().decode(errors="replace")
                        logger.error(f"AlphaLLM server exited: {stderr[:500]}")
                    else:
                        logger.error("AlphaLLM server exited; see hf_server.log in the log dir")
                    return False
                delay = min(delay * 2, 16.0)

            logger.error(f"AlphaLLM server did not become healthy within {budget:.0f}s")
            return False

        except Exception as e:
            logger.error(f"Failed to start AlphaLLM server: {e}")
            self._loaded = False
            return False

    def _is_server_healthy(self) -> bool:
        try:
            req = urllib.request.Request(f"{LLAMA_SERVER_URL}/health")
            with urllib.request.urlopen(req, timeout=2) as resp:
                data = json.loads(resp.read())
                return data.get("status") == "ok"
        except Exception:
            return False

    def _chat(self, messages: List[Dict], temperature: float = 0.1, max_tokens: int = 512, json_mode: bool = True,
              schema: Optional[Dict[str, Any]] = None, seed: Optional[int] = None) -> str:
        """Send chat completion request to llama-server. Raises LLMError on failure.

        If `schema` is given, the decoder is grammar-constrained to it.
        """
        payload_dict: Dict[str, Any] = {
            "messages": messages,
            "temperature": temperature,
            "n_predict": max_tokens,
            "repeat_penalty": 1.3,
            "repeat_last_n": 64,
        }
        if schema is not None:
            # Constrain the decoder to this schema (grammar-enforced).
            payload_dict["response_format"] = {
                "type": "json_schema",
                "json_schema": {"name": "schema", "schema": schema, "strict": True},
            }
        elif json_mode:
            payload_dict["response_format"] = {"type": "json_object"}
        if seed is not None:
            payload_dict["seed"] = seed
        payload = json.dumps(payload_dict).encode()

        req = urllib.request.Request(
            f"{LLAMA_SERVER_URL}/v1/chat/completions",
            data=payload,
            headers={"Content-Type": "application/json"},
        )

        try:
            with urllib.request.urlopen(req, timeout=120) as resp:
                data = json.loads(resp.read())
                self.last_usage = data.get("usage")
                return data["choices"][0]["message"]["content"]
        except urllib.error.URLError as e:
            raise LLMError(f"HTTP request to llama-server failed: {e}") from e
        except (KeyError, json.JSONDecodeError) as e:
            raise LLMError(f"Unexpected llama-server response format: {e}") from e

    @property
    def is_loaded(self) -> bool:
        return self._loaded

    def _extract_json(self, text: str) -> str:
        """Extract outermost JSON object from text."""
        start = text.find("{")
        end = text.rfind("}") + 1
        if start >= 0 and end > start:
            return text[start:end]
        return text

    def _parse_response(self, raw_text: str) -> Dict[str, Any]:
        text = self._extract_json(raw_text.strip())

        try:
            parsed = json.loads(text)
        except json.JSONDecodeError:
            return self._error_response("Failed to parse model output as JSON")

        required = ["tool_selected", "confidence", "parameters", "rationale", "safety_checks_passed", "warnings"]
        for field in required:
            if field not in parsed:
                return self._error_response(f"Missing field in model output: {field}")

        if parsed["tool_selected"] is not None and parsed["tool_selected"] not in AVAILABLE_TOOLS:
            return self._error_response(f"Unknown tool: {parsed['tool_selected']}")

        parsed["confidence"] = float(parsed.get("confidence", 0.0))
        parsed["safety_checks_passed"] = bool(parsed.get("safety_checks_passed", False))
        if not isinstance(parsed.get("warnings"), list):
            parsed["warnings"] = []
        if not isinstance(parsed.get("parameters"), dict):
            parsed["parameters"] = {}

        return parsed

    def _error_response(self, reason: str) -> Dict[str, Any]:
        return {
            "tool_selected": None,
            "confidence": 0.3,
            "parameters": {},
            "rationale": reason,
            "safety_checks_passed": False,
            "warnings": [reason],
        }

    def analyze(self, user_request: str, target: str, constrained: bool = True,
                seed: Optional[int] = None) -> Dict[str, Any]:
        """Pick a tool. `constrained=False` skips the schema grammar (json_object
        mode only) so the eval can ablate constrained vs free-text decoding."""
        if not self._loaded:
            return self._error_response("AlphaLLM model is not loaded")

        user_msg = USER_PROMPT_TEMPLATE.format(target=target, request=user_request)

        try:
            raw_text = self._chat(
                messages=[
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": user_msg},
                ],
                temperature=self._settings.BARONLLM_TEMPERATURE,
                max_tokens=512,
                schema=TOOL_SELECTION_SCHEMA if constrained else None,
                seed=seed,
            )

            result = self._parse_response(raw_text)

            if result["confidence"] < self._settings.BARONLLM_CONFIDENCE_THRESHOLD:
                result["safety_checks_passed"] = False
                if "Low confidence in tool selection" not in result.get("warnings", []):
                    result.setdefault("warnings", []).append("Low confidence in tool selection")

            return result

        except Exception as e:
            logger.error(f"AlphaLLM inference failed: {e}")
            return self._error_response(f"Model inference error: {str(e)}")

    def interpret_output(self, tool_name: str, raw_output: str, target: str) -> Dict[str, Any]:
        """Extract facts from tool output and suggest next tool.

        Returns dict: {summary: str, suggestion: str, next_tool: Optional[str]}
        Uses deterministic regex parsing first; LLM only as fallback for summary.
        next_tool is always determined deterministically — no LLM hallucination.
        """
        # Strip ANSI color codes from raw output first
        clean_raw = _re.sub(r'\x1b\[[0-9;]*[a-zA-Z]', '', raw_output)

        # PRIMARY: deterministic regex parsing (per-tool)
        # Multiple tools may be in raw output (chat endpoint runs many)
        all_facts: List[str] = []
        tool_blocks = _re.split(r'={3,}\s+(\w+)\s+={3,}', clean_raw)
        if len(tool_blocks) > 1:
            # Alternating (toolname, content) pairs after preamble
            for i in range(1, len(tool_blocks) - 1, 2):
                tname = tool_blocks[i].lower()
                content = tool_blocks[i + 1]
                all_facts.extend(_extract_facts_deterministic(tname, content))
        else:
            all_facts.extend(_extract_facts_deterministic(tool_name, clean_raw))

        # Always determine next_tool deterministically (no LLM, no hallucination)
        next_tool = _infer_next_tool(tool_name, all_facts, clean_raw)
        suggestion = _NEXT_TOOL_RATIONALE.get(next_tool, "") if next_tool else ""

        if all_facts:
            return {
                "summary": _format_facts(all_facts),
                "suggestion": suggestion,
                "next_tool": next_tool,
            }

        # FALLBACK: LLM only for summary when deterministic parser finds nothing.
        # Lazy-load BaronLLM here — this is the first point a summary truly needs it.
        if not self.ensure_loaded():
            return {"summary": "1. No significant findings.", "suggestion": suggestion, "next_tool": next_tool}

        system = (
            "Extract only concrete facts from the scan output. "
            "Numbered list. Max 6 items. Max 12 words each. "
            "State ONLY what is in the data. No speculation. No prose. No headers. "
            "If nothing found, output exactly: 1. No significant findings."
        )

        # Pre-filter junk lines before sending to LLM
        filtered: List[str] = []
        hex_re = _re.compile(r'\b[0-9a-fA-F]{16,}\b')
        for line in clean_raw.splitlines():
            s = line.strip()
            if not s or _TOKEN_RE.search(s):
                continue
            if hex_re.search(s) and len(s) < 80:
                continue
            if any(s.startswith(p) for p in ("Starting ", "Nmap scan report", "Host is up",
                                              "NSE:", "DEBUG", "Read data files")):
                continue
            if len(s) > 180:
                continue
            filtered.append(s)

        filtered_text = "\n".join(filtered[:_INTERPRET_MAX_LINES])

        try:
            raw = self._chat(
                messages=[
                    {"role": "system", "content": system},
                    {"role": "user", "content": f"tool={tool_name}\ntarget={target}\n---\n{filtered_text}"},
                ],
                temperature=0.05,
                max_tokens=_INTERPRET_MAX_TOKENS,
                json_mode=False,
            ).strip()
            summary = _clean_llm_output(raw)
        except Exception as e:
            logger.error(f"interpret_output failed: {e}")
            summary = "1. No significant findings."

        return {"summary": summary, "suggestion": suggestion, "next_tool": next_tool}

    def analyze_code(self, code: str, language: str = "unknown", filename: Optional[str] = None) -> Dict[str, Any]:
        if not self._loaded:
            return {"vulnerabilities": [], "summary": "AlphaLLM not loaded"}

        if len(code) > _CODE_TRUNCATE_LIMIT:
            logger.warning(
                f"analyze_code: code truncated from {len(code)} to {_CODE_TRUNCATE_LIMIT} chars "
                f"(file={filename or 'unknown'}) — results may be partial"
            )

        system = """You are a security code reviewer. Analyze the provided code for security vulnerabilities.
Return your response as valid JSON:
{
  "vulnerabilities": [
    {"type": "vuln_type", "severity": "critical|high|medium|low", "line": <int or null>, "code_snippet": "<the vulnerable line>", "issue": "<description>", "fix": "<suggested fix>"}
  ],
  "summary": "<one-line summary>"
}"""

        user_msg = f"Language: {language}\n"
        if filename:
            user_msg += f"File: {filename}\n"
        user_msg += f"\nCode:\n```\n{code[:_CODE_TRUNCATE_LIMIT]}\n```\n\nFind all security vulnerabilities."

        try:
            raw_text = self._chat(
                messages=[
                    {"role": "system", "content": system},
                    {"role": "user", "content": user_msg},
                ],
                temperature=0.1,
                max_tokens=1024,
            )

            text = self._extract_json(raw_text.strip())
            parsed = json.loads(text)
            return {
                "vulnerabilities": parsed.get("vulnerabilities", []),
                "summary": parsed.get("summary", ""),
            }

        except Exception as e:
            logger.error(f"Code analysis failed: {e}")
            return {"vulnerabilities": [], "summary": f"Analysis error: {str(e)}"}

    def shutdown(self):
        if self._server_proc and self._server_proc.poll() is None:
            logger.info("Shutting down AlphaLLM server")
            self._server_proc.terminate()
            try:
                self._server_proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self._server_proc.kill()


# Thread-safe singleton
_baron_instance: Optional[BaronLLM] = None
_baron_lock = threading.Lock()


def get_baron(settings: Settings) -> BaronLLM:
    global _baron_instance
    if _baron_instance is None:
        with _baron_lock:
            if _baron_instance is None:
                _baron_instance = BaronLLM(settings)
    return _baron_instance
