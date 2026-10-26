"""Single source of truth for the tool catalog: which tools exist and their tier.

Tier 1: passive / public-source / offline, or operates on an artifact the user
        supplied (code, hashes, a repo, an image). No domain ownership needed.
Tier 2: sends active traffic to a live target. Requires verified domain
        ownership. Borderline live-target tools (curl, httpx, testssl, cewl)
        default to Tier 2.

validators.SUPPORTED_TOOLS and the database tool catalog are both derived from
this table, so the allow-list and the DB cannot drift apart.
"""
from __future__ import annotations

from typing import Dict

TIER_PASSIVE = 1
TIER_ACTIVE = 2

TOOL_TIERS: Dict[str, int] = {
    "nmap": TIER_ACTIVE,
    "masscan": TIER_ACTIVE,
    "nikto": TIER_ACTIVE,
    "sqlmap": TIER_ACTIVE,
    "ffuf": TIER_ACTIVE,
    "gobuster": TIER_ACTIVE,
    "john": TIER_PASSIVE,
    "hydra": TIER_ACTIVE,
    "curl": TIER_ACTIVE,
    "tcpdump": TIER_ACTIVE,
    "nuclei": TIER_ACTIVE,
    "hashcat": TIER_PASSIVE,
    "gitleaks": TIER_PASSIVE,
    "theharvester": TIER_PASSIVE,
    "subfinder": TIER_PASSIVE,
    "testssl": TIER_ACTIVE,
    "wapiti": TIER_ACTIVE,
    "wpscan": TIER_ACTIVE,
    "cewl": TIER_ACTIVE,
    "trivy": TIER_PASSIVE,
    "amass": TIER_PASSIVE,  # passive mode only; active enumeration would be Tier 2
    "commix": TIER_ACTIVE,
    "searchsploit": TIER_PASSIVE,
    "subdominator": TIER_PASSIVE,
    "httpx": TIER_ACTIVE,
}


def tool_tier(tool_name: str) -> int:
    """Tier of a tool. Unknown tools are treated as Tier 2 (fail closed)."""
    return TOOL_TIERS.get(tool_name, TIER_ACTIVE)
