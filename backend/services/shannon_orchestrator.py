"""Shannon-inspired orchestrator: multi-step tool chaining.

Flow:
  User Request → BaronLLM picks first tool → run tool_runner
  → tool_decision_engine selects next tool → repeat
  → anomaly_detector runs after workflow
  → DB stores workflow + anomalies
"""
from __future__ import annotations

import asyncio
import json
import logging
import re
from typing import Any, Dict, List, Optional

from config import Settings
from tool_runner import ToolRunResult, run_tool

from services.anomaly_detector import detect_anomalies
from services.execution_graph import ExecutionGraph
from services.ownership import check_tool_access, denial_text
from services.tool_decision_engine import decide_next_tools
from services.workflow_engine import WorkflowEngine

logger = logging.getLogger("orchestrator")


class ShannonOrchestrator:
    """Orchestrates multi-step tool execution for a scan."""

    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    async def run_workflow(
        self,
        scan_id: str,
        target: str,
        initial_tool: str,
        initial_params: Dict[str, Any],
        initial_confidence: float,
        user_id: str,
    ) -> Dict[str, Any]:
        """Execute the full orchestration workflow.

        Returns a summary dict with all findings, workflow steps, and anomalies.
        """
        graph = ExecutionGraph(
            max_depth=self.settings.WORKFLOW_MAX_DEPTH,
            max_tools=self.settings.WORKFLOW_MAX_TOOLS,
        )
        workflow = WorkflowEngine(scan_id)

        all_findings: List[Dict] = []
        all_raw_outputs: List[str] = []

        # Execute the chain starting with the initial tool
        await self._execute_chain(
            graph=graph,
            workflow=workflow,
            target=target,
            user_id=user_id,
            tool_name=initial_tool,
            parameters=initial_params,
            confidence=initial_confidence,
            parent_step_id=None,
            all_findings=all_findings,
            all_raw_outputs=all_raw_outputs,
        )

        # Run anomaly detection across all steps
        summary = workflow.get_workflow_summary()
        anomalies = detect_anomalies(summary["steps"])
        workflow.save_anomalies(anomalies)

        # Refresh summary to include anomalies
        summary = workflow.get_workflow_summary()
        summary["all_findings"] = all_findings

        return summary

    async def _execute_chain(
        self,
        graph: ExecutionGraph,
        workflow: WorkflowEngine,
        target: str,
        user_id: str,
        tool_name: str,
        parameters: Dict[str, Any],
        confidence: float,
        parent_step_id: Optional[str],
        all_findings: List[Dict],
        all_raw_outputs: List[str],
    ) -> None:
        """Recursively execute tools following chain decisions."""
        # Check if we can add this tool
        can_add, reason = graph.can_add(tool_name, parameters, parent_step_id)
        if not can_add:
            logger.info(f"Chain stopped: {reason}")
            return

        # Create workflow step
        step_id = workflow.create_step(
            tool_name=tool_name,
            confidence=confidence,
            parameters=parameters,
            parent_step_id=parent_step_id,
        )

        # Register in execution graph
        graph.add_node(
            step_id=step_id,
            tool_name=tool_name,
            parameters=parameters,
            parent_id=parent_step_id,
        )

        logger.info(
            f"[Workflow {workflow.scan_id}] Step {graph.total_tools_run}: "
            f"{tool_name} (confidence={confidence:.2f})"
        )

        # Tools needing file/credential input cannot run against a bare domain
        input_err = precheck_tool_input(tool_name, parameters)
        if input_err:
            logger.info(f"Tool {tool_name} skipped: {input_err}")
            workflow.fail_step(step_id, input_err)
            return

        # Ownership gate: a chain can move from a Tier-1 tool to a Tier-2 one.
        denial = await asyncio.to_thread(check_tool_access, user_id, tool_name, target)
        if denial:
            logger.info(f"Tool {tool_name} blocked: {denial['error']}")
            workflow.fail_step(step_id, denial_text(denial))
            return

        # Build args string from parameters
        args_str = _params_to_args(tool_name, parameters, target)
        run_target = _normalize_target(tool_name, target)

        # Execute the tool
        try:
            result: ToolRunResult = await run_tool(
                tool_name=tool_name,
                args=args_str,
                target=run_target,
                settings=self.settings,
            )

            # Parse findings
            findings = parse_findings(tool_name, result.raw_output)

            workflow.complete_step(
                step_id=step_id,
                findings=findings,
                raw_output=result.raw_output,
                execution_time=result.execution_time,
                exit_code=result.exit_code,
                cpu_usage=result.cpu_usage,
                memory_usage=result.memory_usage,
                status=result.status,
                error_message=result.errors[0] if result.errors else None,
            )

            all_findings.extend(findings)
            all_raw_outputs.append(result.raw_output)

            if not result.success:
                logger.warning(f"Tool {tool_name} failed: {result.errors}")
                return

        except Exception as e:
            logger.exception(f"Tool execution failed: {tool_name}")
            workflow.fail_step(step_id, str(e))
            return

        # Decide follow-up tools
        next_tools = decide_next_tools(
            tool_name=tool_name,
            findings=findings,
            raw_output=result.raw_output,
            confidence=confidence,
            confidence_threshold=self.settings.ORCHESTRATION_CONFIDENCE_THRESHOLD,
        )

        for next_tool_info in next_tools:
            await self._execute_chain(
                graph=graph,
                workflow=workflow,
                target=target,
                user_id=user_id,
                tool_name=next_tool_info["tool"],
                parameters=next_tool_info.get("parameters", {}),
                confidence=confidence * 0.95,  # slight decay per chain depth
                parent_step_id=step_id,
                all_findings=all_findings,
                all_raw_outputs=all_raw_outputs,
            )

    async def run_single_tool(
        self,
        scan_id: str,
        target: str,
        tool_name: str,
        params: Dict[str, Any],
        confidence: float,
        user_id: str,
    ) -> Dict[str, Any]:
        """Fallback: run a single tool without chaining (Phase 1 behavior)."""
        workflow = WorkflowEngine(scan_id)
        step_id = workflow.create_step(
            tool_name=tool_name,
            confidence=confidence,
            parameters=params,
        )

        input_err = precheck_tool_input(tool_name, params)
        if input_err:
            workflow.fail_step(step_id, input_err)
            return {
                "findings": [],
                "raw_output": input_err,
                "execution_time": 0.0,
                "exit_code": -1,
                "status": "failed",
            }

        denial = await asyncio.to_thread(check_tool_access, user_id, tool_name, target)
        if denial:
            msg = denial_text(denial)
            workflow.fail_step(step_id, msg)
            return {
                "findings": [],
                "raw_output": msg,
                "execution_time": 0.0,
                "exit_code": -1,
                "status": "failed",
            }

        args_str = _params_to_args(tool_name, params, target)
        run_target = _normalize_target(tool_name, target)

        try:
            result = await run_tool(
                tool_name=tool_name,
                args=args_str,
                target=run_target,
                settings=self.settings,
            )

            findings = parse_findings(tool_name, result.raw_output)
            workflow.complete_step(
                step_id=step_id,
                findings=findings,
                raw_output=result.raw_output,
                execution_time=result.execution_time,
                exit_code=result.exit_code,
                status=result.status,
                error_message=result.errors[0] if result.errors else None,
            )

            return {
                "findings": findings,
                "raw_output": result.raw_output,
                "execution_time": result.execution_time,
                "exit_code": result.exit_code,
                "status": result.status,
            }

        except Exception as e:
            workflow.fail_step(step_id, str(e))
            raise


# Default flags per tool — emitted before the positional target.
# Most tools require a flag (e.g. -h, -u, --url) ahead of the target
# or they exit with an error.
_TOOL_DEFAULT_ARGS: Dict[str, str] = {
    "nikto":        "-h",
    "sqlmap":       "--batch --dbs -u",
    "wapiti":       "-u",
    "wpscan":       "--url",
    "commix":       "--batch --url",
    "nuclei":       "-u",
    "gobuster":     "dir -w /wordlists/common.txt -u",
    "amass":        "enum -passive -d",
    "subfinder":    "-d",
    "subdominator": "-d",
    "trivy":        "image",
    "theharvester": "-b all -l 100 -d",
    "httpx":        "-silent -status-code -title -tech-detect -u",
    "masscan":      "-p1-1000 --rate=500",
    "curl":         "-sv",
    "testssl":      "",
    "cewl":         "",
    "searchsploit": "",
    "tcpdump":      "-c 20",
}

# Tools that require an http(s):// URL as the target.
_NEEDS_URL_SCHEME = {
    "curl", "sqlmap", "nuclei", "httpx", "gobuster",
    "ffuf", "wapiti", "wpscan", "commix", "cewl",
}

# Tools that take a bare host/domain — any scheme, path or port must be
# stripped or the tool errors (e.g. nmap can't parse "https://x/").
_NEEDS_BARE_HOST = {
    "nmap", "masscan", "subfinder", "amass", "subdominator",
    "theharvester", "testssl", "hydra",
}


def _host_only(target: str) -> str:
    """Reduce a target to a bare hostname/IP — drop scheme, path and port."""
    t = (target or "").strip()
    if "://" in t:
        from urllib.parse import urlparse
        parsed = urlparse(t)
        host = parsed.hostname or t
        return host
    # No scheme: drop any path component, then a trailing :port
    t = t.split("/", 1)[0]
    if t.count(":") == 1:  # host:port (skip bare IPv6, which has many colons)
        t = t.split(":", 1)[0]
    return t


# Two-label public suffixes — so "x.example.co.uk" reduces to "example.co.uk",
# not "co.uk". Extend as needed.
_MULTI_TLDS = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "co.in", "co.jp", "com.au",
    "com.br", "co.za", "com.sg", "co.kr", "com.mx", "co.nz",
}


def _root_domain(host: str) -> str:
    """Reduce a hostname to its registrable root domain.

    s3.hackprix.tech -> hackprix.tech ; www.foo.co.uk -> foo.co.uk
    Subdomain-enumeration tools must run against the ROOT, otherwise they look
    for children of a leaf (e.g. s3.hackprix.tech) and find nothing.
    """
    host = (host or "").strip().lower().rstrip(".")
    # An IP address has no "root domain" — return as-is.
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host):
        return host
    labels = host.split(".")
    if len(labels) <= 2:
        return host
    last2 = ".".join(labels[-2:])
    last3 = ".".join(labels[-3:])
    if last2 in _MULTI_TLDS:
        return last3
    return last2


def _normalize_target(tool_name: str, target: str) -> str:
    """Coerce the target into the form the given tool expects."""
    # masscan cannot resolve hostnames — it needs a literal IP address.
    if tool_name == "masscan":
        host = _host_only(target)
        try:
            import socket
            return socket.gethostbyname(host)
        except Exception:
            return host
    # Subdomain-enumeration tools must target the registrable ROOT domain.
    if tool_name in ("subfinder", "amass", "subdominator", "theharvester"):
        return _root_domain(_host_only(target))
    if tool_name in _NEEDS_BARE_HOST:
        return _host_only(target)
    if tool_name in _NEEDS_URL_SCHEME:
        return _ensure_url(target)
    return target

# Tools that cannot run against a bare domain — they need file/credential
# input (wordlists, hashes, a local git repo) that the scan/chat flow
# does not supply. Invoking them here returns a helpful error.
_NEEDS_EXTRA_INPUT: Dict[str, str] = {
    "hydra": (
        "hydra needs a login/password list and a service module — "
        "e.g. -l <user> -P <wordlist> <service>://<target>. "
        "Use the /execute endpoint with explicit args."
    ),
    "hashcat": (
        "hashcat needs a hash mode (-m), a hash file, and a wordlist. "
        "Use the /execute endpoint with explicit args."
    ),
    "gitleaks": (
        "gitleaks scans a local git repository path, not a domain. "
        "Use the /execute endpoint pointing at a cloned repo."
    ),
}


def precheck_tool_input(tool_name: str, parameters: Dict[str, Any]) -> Optional[str]:
    """Return an error message if the tool cannot run without extra input."""
    msg = _NEEDS_EXTRA_INPUT.get(tool_name)
    if msg and not parameters:
        return msg
    return None


def _ensure_url(target: str) -> str:
    """Prefix http:// if the target has no scheme."""
    if "://" in target:
        return target
    return f"http://{target}"


def _params_to_args(tool_name: str, parameters: Dict[str, Any], target: str = "") -> str:
    """Convert parameter dict to CLI args string (placed before the target)."""
    parts: List[str] = []

    if tool_name == "nmap":
        # Use fast scan (-F) by default to avoid timeouts on full 65k port scans
        if not parameters.get("ports"):
            parts.append("-F")
        parts.append("-sV")
        if parameters.get("ports"):
            parts.append(f"-p {parameters['ports']}")
        return " ".join(parts)

    # ffuf needs the FUZZ keyword embedded in the URL + a wordlist;
    # the bare target is appended by the runner, so we pass the full -u here.
    if tool_name == "ffuf":
        url = _ensure_url(target).rstrip("/")
        return f"-w /wordlists/common.txt -u {url}/FUZZ"

    base = _TOOL_DEFAULT_ARGS.get(tool_name, "")
    if base:
        parts.append(base)

    if parameters.get("ports"):
        parts.append(f"-p {parameters['ports']}")
    if parameters.get("port") and tool_name in ("nikto",):
        parts.append(f"-p {parameters['port']}")

    return " ".join(parts)


def parse_findings(tool_name: str, raw_output: str) -> List[Dict[str, Any]]:
    """Parse tool-specific output into structured findings."""
    if tool_name == "nmap":
        return _parse_nmap(raw_output)
    elif tool_name == "masscan":
        return _parse_masscan(raw_output)
    elif tool_name in ("nikto", "nuclei"):
        return _parse_line_findings(raw_output)
    elif tool_name in ("gobuster", "ffuf"):
        return _parse_directory_findings(raw_output)
    elif tool_name == "sqlmap":
        return _parse_line_findings(raw_output)
    elif tool_name == "gitleaks":
        return _parse_gitleaks(raw_output)
    elif tool_name in ("subdominator", "subfinder", "amass"):
        return _parse_subdomains(raw_output)
    else:
        return _parse_generic(raw_output)


# A valid subdomain line: dotted hostname, letters/digits/hyphens only.
_SUBDOMAIN_RE = re.compile(r"^(?:[a-zA-Z0-9_-]+\.)+[a-zA-Z]{2,}$")


def _parse_subdomains(raw: str) -> List[Dict]:
    """Extract unique subdomain hostnames, dropping banner/log/wildcard lines."""
    seen = set()
    findings = []
    for line in raw.splitlines():
        host = line.strip().lower()
        if not host or host in seen:
            continue
        # Skip log lines, banners, wildcard/redacted entries.
        if host.startswith(("[", "#", "-")) or "*" in host or " " in host:
            continue
        if not _SUBDOMAIN_RE.match(host):
            continue
        seen.add(host)
        findings.append({"type": "subdomain", "host": host, "detail": host})
    return findings


def _parse_nmap(raw: str) -> List[Dict]:
    findings = []
    for line in raw.splitlines():
        match = re.match(
            r"(\d+)/(tcp|udp)\s+(open|closed|filtered)\s+(\S+)\s*(.*)", line
        )
        if match:
            findings.append({
                "port": int(match.group(1)),
                "protocol": match.group(2),
                "state": match.group(3),
                "service": match.group(4),
                "version": match.group(5).strip() or None,
            })
    return findings


def _parse_masscan(raw: str) -> List[Dict]:
    findings = []
    for line in raw.splitlines():
        match = re.match(r"Discovered open port (\d+)/(tcp|udp) on (.+)", line)
        if match:
            findings.append({
                "port": int(match.group(1)),
                "protocol": match.group(2),
                "state": "open",
                "host": match.group(3).strip(),
            })
    return findings


def _parse_directory_findings(raw: str) -> List[Dict]:
    findings = []
    for line in raw.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        # gobuster/ffuf output: /path (Status: 200) [Size: 1234]
        match = re.match(r"(/\S+)\s+.*Status:\s*(\d+)", line)
        if match:
            findings.append({
                "path": match.group(1),
                "status_code": int(match.group(2)),
                "detail": line,
            })
        elif line.startswith("/"):
            findings.append({"path": line.split()[0], "detail": line})
    return findings


def _parse_gitleaks(raw: str) -> List[Dict]:
    findings = []
    try:
        data = json.loads(raw)
        if isinstance(data, list):
            for item in data:
                findings.append({
                    "type": "secret",
                    "rule": item.get("RuleID", ""),
                    "file": item.get("File", ""),
                    "line": item.get("StartLine", 0),
                    "detail": item.get("Match", ""),
                })
    except (json.JSONDecodeError, TypeError):
        return _parse_generic(raw)
    return findings


def _parse_line_findings(raw: str) -> List[Dict]:
    findings = []
    for line in raw.splitlines():
        line = line.strip()
        if line and not line.startswith("#") and not line.startswith("-"):
            findings.append({"detail": line})
    return findings


def _parse_generic(raw: str) -> List[Dict]:
    findings = []
    for line in raw.splitlines():
        line = line.strip()
        if line and not line.startswith("#") and not line.startswith("-"):
            findings.append({"detail": line})
    return findings
