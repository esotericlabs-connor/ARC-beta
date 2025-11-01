"""Authentication helpers for SPF, DKIM, and DMARC."""
from __future__ import annotations

import importlib
import importlib.util
from email.message import EmailMessage
from typing import Dict, Optional

from .models import VerificationResult


def _load_optional_module(name: str):
    """Attempt to load an optional dependency without raising ImportError."""

    if importlib.util.find_spec(name) is None:
        return None
    return importlib.import_module(name)


def _authentication_results_lookup(headers: Dict[str, str], token: str) -> Optional[str]:
    header = headers.get("Authentication-Results")
    if not header:
        return None
    token = token.lower()
    for segment in header.split(";"):
        segment = segment.strip()
        if segment.lower().startswith(token):
            return segment
    return None


def verify_spf(metadata: Dict[str, Optional[str]]) -> VerificationResult:
    """Run SPF verification using pyspf when available."""

    protocol = "SPF"
    ip_address = metadata.get("source_ip")
    mail_from = metadata.get("mail_from") or metadata.get("from")
    helo = metadata.get("helo") or metadata.get("helo_domain")

    spf_module = _load_optional_module("spf")
    if spf_module is None:
        header_fragment = _authentication_results_lookup(metadata.get("headers", {}), "spf=")
        result = "unknown"
        details = "pyspf library unavailable"
        if header_fragment:
            result = header_fragment
            details = "inferred from Authentication-Results header"
        return VerificationResult(protocol=protocol, passed=None, result=result, details=details)

    if not (ip_address and mail_from and helo):
        return VerificationResult(
            protocol=protocol,
            passed=None,
            result="unknown",
            details="insufficient metadata for SPF evaluation",
        )

    spf_result = spf_module.query(ip_address, mail_from, helo)
    result_code = spf_result[0]
    explanation = spf_result[2]
    passed = result_code == "pass"
    return VerificationResult(protocol=protocol, passed=passed, result=result_code, details=explanation)


def verify_dkim(metadata: Dict[str, Optional[str]]) -> VerificationResult:
    """Run DKIM verification using the dkim package when available."""

    protocol = "DKIM"
    dkim_module = _load_optional_module("dkim")
    raw_source = metadata.get("raw_source")
    if dkim_module is None or raw_source is None:
        header_fragment = _authentication_results_lookup(metadata.get("headers", {}), "dkim=")
        result = "unknown"
        details = "dkim library unavailable" if dkim_module is None else "raw message unavailable"
        if header_fragment:
            result = header_fragment
            details = "inferred from Authentication-Results header"
        return VerificationResult(protocol=protocol, passed=None, result=result, details=details)

    if isinstance(raw_source, str):
        raw_bytes = raw_source.encode("utf-8", errors="ignore")
    else:
        raw_bytes = raw_source

    try:
        passed = bool(dkim_module.verify(raw_bytes))
        result = "pass" if passed else "fail"
        details = "signature validation {}".format("succeeded" if passed else "failed")
    except dkim_module.DKIMException as exc:  # type: ignore[attr-defined]
        passed = False
        result = "temperror"
        details = str(exc)
    return VerificationResult(protocol=protocol, passed=passed, result=result, details=details)


def verify_dmarc(metadata: Dict[str, Optional[str]], message: Optional[EmailMessage] = None) -> VerificationResult:
    """Run DMARC verification leveraging optional parsers and headers."""

    protocol = "DMARC"
    dmarc_module = _load_optional_module("dmarc")
    headers = metadata.get("headers", {})
    header_fragment = _authentication_results_lookup(headers, "dmarc=")

    if dmarc_module is None:
        result = header_fragment or "unknown"
        details = "dmarc parser unavailable"
        if header_fragment:
            details = "inferred from Authentication-Results header"
        return VerificationResult(protocol=protocol, passed=None, result=result, details=details)

    domain = None
    if message:
        from_header = message.get("From", "")
        domain = from_header.split("@")[-1].strip("<>") if "@" in from_header else None
    if not domain:
        domain = metadata.get("from_domain")

    if not domain:
        return VerificationResult(
            protocol=protocol,
            passed=None,
            result="unknown",
            details="unable to determine domain for DMARC lookup",
        )

    try:
        policy = dmarc_module.get_record(domain)
    except Exception as exc:  # noqa: BLE001 - library-specific exceptions vary
        result = header_fragment or "temperror"
        return VerificationResult(protocol=protocol, passed=None, result=result, details=str(exc))

    policy_result = header_fragment or "unknown"
    passed = None
    if policy:
        alignment = policy.get("p") or policy.get("policy")
        policy_result = f"policy={alignment}" if alignment else "policy=unknown"
        if alignment == "reject":
            passed = False
        elif alignment in {"none", "quarantine"}:
            passed = alignment == "none"

    return VerificationResult(protocol=protocol, passed=passed, result=policy_result, details="policy evaluation")