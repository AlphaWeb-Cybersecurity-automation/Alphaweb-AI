"""Identity + domain-ownership gate for Tier-2 (active) tools.

Tier-2 tools only run against a registrable domain the requesting user has
proven they control (DNS TXT, a file under /.well-known/, or a <meta> tag).
Tier-1 tools skip the check. This is authorization; the SSRF/private-range
guard in validators.py is a separate layer and still applies on top.
"""
from __future__ import annotations

import hashlib
import hmac
import ipaddress
import logging
import re
import secrets
import socket
import urllib.error
import urllib.request
from datetime import datetime, timezone
from typing import Any, Dict, Optional
from urllib.parse import urlparse

import dns.exception
import dns.resolver
import tldextract

from config import Settings
from database import DEFAULT_USER_ID, SessionLocal, User, VerifiedDomain
from tool_tiers import TIER_PASSIVE, tool_tier
from validators import _is_private_ip

logger = logging.getLogger("orchestrator")

METHODS = ("dns_txt", "html_file", "meta_tag")
DNS_LABEL = "_alphaweb"
WELL_KNOWN_PATH = "/.well-known/alphaweb-verify.txt"
META_NAME = "alphaweb-verify"
_TOKEN_PREFIX = "alphaweb-verify="
_FETCH_TIMEOUT = 5
_MAX_BODY = 256 * 1024

# Bundled public-suffix snapshot only: no network fetch at runtime.
_tld = tldextract.TLDExtract(suffix_list_urls=())


# --- Identity ---------------------------------------------------------------

def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def create_user(email: Optional[str] = None) -> Dict[str, str]:
    """Create a user and return {id, token}. The token is only returned here."""
    token = secrets.token_urlsafe(32)
    db = SessionLocal()
    try:
        user = User(email=email or None, token_hash=_hash_token(token))
        db.add(user)
        db.commit()
        return {"id": user.id, "token": token}
    finally:
        db.close()


def resolve_user_id(token: Optional[str], auth_required: bool) -> Optional[str]:
    """Map an API token to a user id. None means the token is missing/invalid."""
    if not token:
        return None if auth_required else DEFAULT_USER_ID
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.token_hash == _hash_token(token)).first()
        return user.id if user else None
    finally:
        db.close()


# --- Target -> registrable domain -------------------------------------------

def registrable_domain(target: str) -> Optional[str]:
    """Registrable domain of a target (eTLD+1), or the IP itself for IP targets.

    Returns None when no single owner-verifiable name can be derived (CIDR
    ranges, bare TLDs, unknown suffixes). Callers must treat None as a denial.
    """
    t = (target or "").strip()
    if not t:
        return None
    if "://" not in t and "/" in t:
        try:  # bare CIDR range: many hosts, no single owner to verify
            ipaddress.ip_network(t, strict=False)
            return None
        except ValueError:
            pass
    # urlparse strips scheme, userinfo, port and IPv6 brackets for us.
    host = urlparse(t if "://" in t else "//" + t).hostname
    if not host:
        return None
    host = host.rstrip(".")
    if _is_ip(host):
        return host
    reg = _tld(host).registered_domain
    return reg.lower() if reg else None


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


# --- Challenges -------------------------------------------------------------

def _challenge_payload(row: VerifiedDomain) -> Dict[str, Any]:
    domain = row.domain
    is_ip = _is_ip(domain)
    methods: Dict[str, Any] = {
        "html_file": {
            "instruction": f"Serve exactly this text at http(s)://{domain}{WELL_KNOWN_PATH}",
            "content": row.token,
        },
        "meta_tag": {
            "instruction": f"Add this tag to the <head> of http(s)://{domain}/",
            "content": f'<meta name="{META_NAME}" content="{row.token}">',
        },
    }
    if not is_ip:
        methods["dns_txt"] = {
            "instruction": f"Add a TXT record at {DNS_LABEL}.{domain}",
            "content": row.token,
        }
    return {
        "domain": domain,
        "status": row.status,
        "token": row.token,
        "methods": methods,
        "verify_endpoint": "POST /api/domains/verify",
    }


def get_or_create_challenge(user_id: str, domain: str) -> Dict[str, Any]:
    db = SessionLocal()
    try:
        row = (
            db.query(VerifiedDomain)
            .filter(VerifiedDomain.user_id == user_id, VerifiedDomain.domain == domain)
            .first()
        )
        if row is None:
            row = VerifiedDomain(
                user_id=user_id,
                domain=domain,
                token=_TOKEN_PREFIX + secrets.token_hex(16),
                status="pending",
            )
            db.add(row)
            db.commit()
            db.refresh(row)
        return _challenge_payload(row)
    finally:
        db.close()


def list_domains(user_id: str) -> list[Dict[str, Any]]:
    db = SessionLocal()
    try:
        rows = db.query(VerifiedDomain).filter(VerifiedDomain.user_id == user_id).order_by(VerifiedDomain.created_at).all()
        return [
            {
                "domain": r.domain,
                "status": r.status,
                "method": r.method,
                "verified_at": r.verified_at.isoformat() if r.verified_at else None,
                "last_checked_at": r.last_checked_at.isoformat() if r.last_checked_at else None,
            }
            for r in rows
        ]
    finally:
        db.close()


def revoke_domain(user_id: str, domain: str) -> bool:
    db = SessionLocal()
    try:
        row = (
            db.query(VerifiedDomain)
            .filter(VerifiedDomain.user_id == user_id, VerifiedDomain.domain == domain)
            .first()
        )
        if row is None:
            return False
        row.status = "revoked"
        db.commit()
        return True
    finally:
        db.close()


# --- Proof checks (each returns True only on an exact token match) ----------

def _tokens_equal(found: str, expected: str) -> bool:
    return hmac.compare_digest(found.strip().encode(), expected.encode())


def _check_dns_txt(domain: str, token: str) -> bool:
    try:
        resolver = dns.resolver.Resolver()
        resolver.lifetime = _FETCH_TIMEOUT
        answers = resolver.resolve(f"{DNS_LABEL}.{domain}", "TXT")
    except (dns.exception.DNSException, OSError):
        return False
    for rdata in answers:
        txt = b"".join(rdata.strings).decode("utf-8", "ignore")
        if _tokens_equal(txt, token):
            return True
    return False


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args: Any, **kwargs: Any) -> None:
        return None


_opener = urllib.request.build_opener(_NoRedirect)


def _fetch(domain: str, path: str) -> Optional[str]:
    """GET http(s)://domain/path. No redirects; refuses private/loopback hosts."""
    try:
        infos = socket.getaddrinfo(domain, None)
    except OSError:
        return None
    if not infos or any(_is_private_ip(i[4][0]) for i in infos):
        return None
    for scheme in ("https", "http"):
        try:
            req = urllib.request.Request(f"{scheme}://{domain}{path}", headers={"User-Agent": "alphaweb-verify"})
            with _opener.open(req, timeout=_FETCH_TIMEOUT) as resp:
                if resp.status == 200:
                    return resp.read(_MAX_BODY).decode("utf-8", "ignore")
        except (urllib.error.URLError, OSError, ValueError):
            continue
    return None


def _check_html_file(domain: str, token: str) -> bool:
    body = _fetch(domain, WELL_KNOWN_PATH)
    return body is not None and _tokens_equal(body, token)


_META_RE = re.compile(r"<meta\b[^>]*>", re.I)
_ATTR_RE = re.compile(r'([a-zA-Z-]+)\s*=\s*["\']([^"\']*)["\']')


def _check_meta_tag(domain: str, token: str) -> bool:
    body = _fetch(domain, "/")
    if body is None:
        return False
    for tag in _META_RE.findall(body):
        attrs = {k.lower(): v for k, v in _ATTR_RE.findall(tag)}
        if attrs.get("name", "").lower() == META_NAME and _tokens_equal(attrs.get("content", ""), token):
            return True
    return False


_CHECKS = {"dns_txt": _check_dns_txt, "html_file": _check_html_file, "meta_tag": _check_meta_tag}


def check_verification(user_id: str, domain: str, method: str) -> Dict[str, Any]:
    """Run the chosen proof check server-side and record the outcome."""
    if method not in _CHECKS:
        raise ValueError(f"Unknown method {method!r}; use one of {METHODS}")
    if method == "dns_txt" and _is_ip(domain):
        raise ValueError("dns_txt cannot verify an IP address")
    db = SessionLocal()
    try:
        row = (
            db.query(VerifiedDomain)
            .filter(VerifiedDomain.user_id == user_id, VerifiedDomain.domain == domain)
            .first()
        )
        if row is None:
            raise LookupError("No challenge for this domain; request one first")
        ok = _CHECKS[method](domain, row.token)
        now = datetime.now(timezone.utc)
        row.method = method
        row.last_checked_at = now
        row.status = "verified" if ok else "failed"
        if ok:
            row.verified_at = now
        db.commit()
        return {"domain": domain, "status": row.status, "method": method}
    finally:
        db.close()


# --- The gate ---------------------------------------------------------------

def check_tool_access(user_id: str, tool: str, target: str) -> Optional[Dict[str, Any]]:
    """None if the user may run `tool` against `target`; else a denial payload."""
    if Settings.OWNERSHIP_ENFORCEMENT == "off" or tool_tier(tool) == TIER_PASSIVE:
        return None

    domain = registrable_domain(target)
    if domain is None:
        return {
            "error": "ownership_unverifiable",
            "tool": tool,
            "target": target,
            "message": (
                f"'{tool}' is a Tier 2 (active) tool and needs verified ownership, but a single "
                f"owner-verifiable domain or IP could not be derived from '{target}'."
            ),
        }

    db = SessionLocal()
    try:
        verified = (
            db.query(VerifiedDomain.id)
            .filter(
                VerifiedDomain.user_id == user_id,
                VerifiedDomain.domain == domain,
                VerifiedDomain.status == "verified",
            )
            .first()
        )
    finally:
        db.close()
    if verified:
        return None

    return {
        "error": "domain_not_verified",
        "tool": tool,
        "tier": 2,
        "message": (
            f"'{tool}' is a Tier 2 (active) tool. Verify ownership of {domain} first "
            f"(POST /api/domains, then POST /api/domains/verify)."
        ),
        "challenge": get_or_create_challenge(user_id, domain),
    }


def denial_text(denial: Dict[str, Any]) -> str:
    """One-line form of a denial for chat/stream/step error messages."""
    ch = denial.get("challenge")
    if not ch:
        return denial["message"]
    return f"{denial['message']} Token: {ch['token']}"
