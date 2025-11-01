"""Core analysis pipeline for the Adaptive Email Threat Analysis (AETA) engine."""
from __future__ import annotations

import base64
import binascii
import ipaddress
import re
from email import policy
from email.header import decode_header, make_header
from email.message import EmailMessage
from email.parser import BytesParser, Parser
from email.utils import getaddresses, parseaddr
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, MutableMapping, Optional, Sequence, Tuple

from .authentication import verify_dkim, verify_dmarc, verify_spf
from .heuristics import (
    analyze_attachments,
    analyze_ip_geolocation,
    analyze_predictive_signals,
    analyze_sender_behavior,
    analyze_url_reputation,
    analyze_whois,
)
from .heuristics.sandbox import analyze_with_sandbox
from .models import SentryReport, SignalContribution, VerificationResult
from .utils.community_intel import get_community_hub
from .utils.predictive_analytics import get_predictive_model


DEFAULT_THRESHOLDS = {"danger": 30.0, "review": 60.0}
TEXT_MEDIA_TYPES = {
    "text/plain",
    "text/html",
    "text/markdown",
    "text/x-markdown",
    "application/json",
}


def analyze_email(message: Any, *, thresholds: Optional[Dict[str, float]] = None) -> SentryReport:
    """Analyze an email message and return a :class:`SentryReport`."""

    metadata, email_obj = _prepare_inputs(message)
    resolved_thresholds = dict(DEFAULT_THRESHOLDS)
    custom_thresholds = thresholds or metadata.get("thresholds")
    if isinstance(custom_thresholds, dict):
        resolved_thresholds.update(custom_thresholds)

    body_texts, attachments = _extract_contents(email_obj)
    authentication_results = _run_authentication_checks(metadata, email_obj)
    attachment_count = len(attachments)

    if _all_authentication_failed(authentication_results):
        risk_score = 100.0
        score = _risk_to_confidence(risk_score)
        verdict = "malicious"
        return SentryReport(
            score=score,
            risk_score=risk_score,
            verdict=verdict,
            contributions=[],
            authentication=authentication_results,
            metadata=_public_metadata(metadata, attachment_count),
@@ -53,123 +67,451 @@ def analyze_email(message: Any, *, thresholds: Optional[Dict[str, float]] = None
    contributions = _gather_contributions(
        metadata=metadata,
        body_texts=body_texts,
        attachments=attachments,
    )

    risk_score = _combine_risk_scores(contributions)
    score = _risk_to_confidence(risk_score)
    verdict = _score_to_verdict(score, resolved_thresholds)

    report = SentryReport(
        score=score,
        risk_score=risk_score,
        verdict=verdict,
        contributions=contributions,
        authentication=authentication_results,
        metadata=_public_metadata(metadata, attachment_count),
    )

    _record_observation(metadata, contributions, verdict, risk_score)

    return report


def _prepare_inputs(message: Any) -> Tuple[Dict[str, Any], EmailMessage]:
    metadata: Dict[str, Any] = {}
    raw_source: Optional[bytes] = None

    if isinstance(message, EmailMessage):
        email_obj = message
        raw_source = message.as_bytes()
    elif isinstance(message, (bytes, bytearray)):
        raw_source = bytes(message)
        email_obj = BytesParser(policy=policy.default).parsebytes(raw_source)
    elif isinstance(message, str):
        raw_source = message.encode("utf-8")
        email_obj = Parser(policy=policy.default).parsestr(message)
    elif isinstance(message, dict):
        metadata = dict(message)
        metadata = _flatten_metadata(metadata)
        raw_source = _extract_raw_source(metadata)
        if raw_source is not None:
            email_obj = BytesParser(policy=policy.default).parsebytes(raw_source)
        else:
            fallback = metadata.get("body") or metadata.get("email")
            if isinstance(fallback, bytes):
                raw_source = bytes(fallback)
                email_obj = BytesParser(policy=policy.default).parsebytes(raw_source)
            elif isinstance(fallback, str):
                raw_source = fallback.encode("utf-8")
                email_obj = Parser(policy=policy.default).parsestr(fallback)
            else:
                raise ValueError(
                    "Dictionary input must include 'raw_source' or textual 'body'/'email' content"
                )
    else:
        raise TypeError(f"Unsupported message type: {type(message)!r}")

    extracted_metadata = _metadata_from_message(email_obj, raw_source)
    merged_metadata = _merge_metadata(extracted_metadata, metadata)
    if raw_source is not None:
        merged_metadata["raw_source"] = raw_source

    return merged_metadata, email_obj


def _flatten_metadata(metadata: Dict[str, Any]) -> Dict[str, Any]:
    if "metadata" in metadata and isinstance(metadata["metadata"], Mapping):
        nested = dict(metadata.pop("metadata"))
        nested.update(metadata)
        return nested
    return metadata


def _extract_raw_source(metadata: MutableMapping[str, Any]) -> Optional[bytes]:
    raw_candidates = [
        "raw_source",
        "raw_message",
        "raw_email",
        "raw",
        "source",
        "eml",
    ]
    for key in raw_candidates:
        if key not in metadata:
            continue
        value = metadata.pop(key)
        if isinstance(value, bytes):
            return value
        if isinstance(value, str) and value.strip():
            return value.encode("utf-8", errors="ignore")

    for key in ("raw_source_b64", "raw_source_base64", "raw_email_b64", "raw_email_base64"):
        value = metadata.pop(key, None)
        if isinstance(value, str) and value.strip():
            try:
                return base64.b64decode(value, validate=True)
            except (binascii.Error, ValueError):
                continue

    path_value = metadata.pop("raw_source_path", None)
    if isinstance(path_value, (str, Path)):
        try:
            return Path(path_value).expanduser().read_bytes()
        except OSError:
            return None

    return None


def _merge_metadata(base: Dict[str, Any], overrides: Mapping[str, Any]) -> Dict[str, Any]:
    if not overrides:
        return base

    merged = dict(base)
    for key, value in overrides.items():
        if key == "headers" and isinstance(value, Mapping):
            headers = dict(base.get("headers", {}))
            for header_key, header_value in value.items():
                headers[str(header_key)] = str(header_value)
            merged["headers"] = headers
            continue
        if key == "raw_source":
            if isinstance(value, bytes):
                merged[key] = value
            elif isinstance(value, str):
                merged[key] = value.encode("utf-8", errors="ignore")
            continue
        merged[key] = value
    return merged


def _metadata_from_message(message: EmailMessage, raw_source: Optional[bytes]) -> Dict[str, Any]:
    metadata: Dict[str, Any] = {}

    headers = _headers_dict(message)
    if headers:
        metadata["headers"] = headers
    if raw_source is not None:
        metadata["raw_source"] = raw_source

    metadata["message_id"] = (message.get("Message-ID") or message.get("Message-Id") or "").strip() or None
    metadata["subject"] = _decode_header_value(message.get("Subject")) or None
    metadata["date"] = message.get("Date") or None
    metadata["mime_version"] = message.get("MIME-Version") or None

    from_header = _decode_header_value(message.get("From"))
    metadata["from"] = from_header or None
    name, addr = parseaddr(from_header or "")
    if name:
        metadata["from_display_name"] = name
    if addr:
        metadata["mail_from"] = addr
        metadata["from_address"] = addr
        if "@" in addr:
            metadata["from_domain"] = addr.split("@")[-1].lower()

    reply_to_header = _decode_header_value(message.get("Reply-To"))
    if reply_to_header:
        metadata["reply_to"] = reply_to_header
        _, reply_addr = parseaddr(reply_to_header)
        if reply_addr:
            metadata["reply_to_address"] = reply_addr

    to_values = [_decode_header_value(value) for value in message.get_all("To", [])]
    cc_values = [_decode_header_value(value) for value in message.get_all("Cc", [])]
    if to_values:
        metadata["to"] = ", ".join(filter(None, to_values)) or None
    if cc_values:
        metadata["cc"] = ", ".join(filter(None, cc_values)) or None

    to_addresses = [addr for _, addr in getaddresses(message.get_all("To", [])) if addr]
    if to_addresses:
        metadata["to_addresses"] = to_addresses

    cc_addresses = [addr for _, addr in getaddresses(message.get_all("Cc", [])) if addr]
    if cc_addresses:
        metadata["cc_addresses"] = cc_addresses

    return_path = message.get("Return-Path")
    if return_path:
        metadata["return_path"] = return_path.strip("<>")

    auth_results = message.get_all("Authentication-Results", [])
    if auth_results:
        metadata["authentication_results"] = auth_results

    received_headers = message.get_all("Received", [])
    if received_headers:
        metadata["received"] = received_headers
        metadata.update(_infer_network_metadata(received_headers))

    return metadata


def _headers_dict(message: EmailMessage) -> Dict[str, str]:
    headers: Dict[str, str] = {}
    for key in dict.fromkeys(message.keys()):
        values = message.get_all(key, [])
        if not values:
            continue
        decoded = [_decode_header_value(value) for value in values]
        headers[key] = ", ".join(value for value in decoded if value)
    return headers


def _decode_header_value(value: Optional[str]) -> str:
    if not value:
        return ""
    try:
        return str(make_header(decode_header(value)))
    except Exception:
        return value


def _infer_network_metadata(received_headers: Sequence[str]) -> Dict[str, Any]:
    metadata: Dict[str, Any] = {}
    for header in reversed(received_headers):
        header_text = str(header)
        ip_candidate = _extract_ip(header_text)
        if ip_candidate and "source_ip" not in metadata:
            metadata["source_ip"] = ip_candidate
            metadata["source_ip_prefix"] = _truncate_ip_prefix(ip_candidate)
        hostname = _extract_hostname(header_text)
        if hostname and "source_ip_hostname" not in metadata:
            metadata["source_ip_hostname"] = hostname
        helo = _extract_helo(header_text)
        if helo and "helo" not in metadata:
            metadata["helo"] = helo
        if metadata.get("source_ip") and metadata.get("source_ip_hostname"):
            break
    return metadata


def _extract_ip(header: str) -> Optional[str]:
    tokens = re.findall(r"[0-9A-Fa-f:\.]+", header)
    for token in tokens:
        candidate = token.strip("[]();")
        if not candidate:
            continue
        try:
            address = ipaddress.ip_address(candidate)
        except ValueError:
            continue
        return str(address)
    return None


def _truncate_ip_prefix(value: str) -> Optional[str]:
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return None
    network = ipaddress.ip_network(
        f"{address}/24" if address.version == 4 else f"{address}/48", strict=False
    )
    return str(network)


def _extract_hostname(header: str) -> Optional[str]:
    match = re.search(r"from\s+([^\s(;]+)", header, flags=re.IGNORECASE)
    if match:
        return match.group(1).strip("[]<>()")
    match = re.search(r"\(([^)]+)\)", header)
    if match:
        parts = match.group(1).split()
        for part in parts:
            if part.startswith("[") or part.startswith("("):
                continue
            if "." in part and not part.replace(".", "").isdigit():
                return part.strip("[]<>()")
    return None


def _extract_helo(header: str) -> Optional[str]:
    match = re.search(r"helo(?:=|\s)([^;\s]+)", header, flags=re.IGNORECASE)
    if match:
        return match.group(1).strip("[]<>()")
    return None


def _extract_contents(message: EmailMessage) -> Tuple[List[str], List[Dict[str, Any]]]:
    body_texts: List[str] = []
    attachments: List[Dict[str, Any]] = []

    if message.is_multipart():
        for part in message.walk():
            if part.is_multipart():
                continue
            _categorise_part(part, body_texts, attachments)
    else:
        _categorise_part(message, body_texts, attachments)

    return body_texts, attachments


def _categorise_part(part: EmailMessage, body_texts: List[str], attachments: List[Dict[str, Any]]) -> None:
    content_disposition = part.get_content_disposition()
    content_type = part.get_content_type()
    filename = part.get_filename()

    if content_disposition == "attachment" or (content_disposition == "inline" and filename):
        payload_bytes = part.get_payload(decode=True) or b""
        attachments.append(
            {
                "filename": filename or "attachment",
                "content_type": content_type,
                "payload": payload_bytes,
                "size": len(payload_bytes),
            }
        )
        return

    if content_type in TEXT_MEDIA_TYPES or content_type.startswith("text/"):
        try:
            content = part.get_content()
            if isinstance(content, str):
                body_texts.append(content)
                return
        except LookupError:
            pass
        payload_bytes = part.get_payload(decode=True) or b""
        charset = part.get_content_charset() or "utf-8"
        body_texts.append(_decode_bytes(payload_bytes, charset))
        return

    payload_bytes = part.get_payload(decode=True) or b""
    if payload_bytes:
        attachments.append(
            {
                "filename": filename or content_type,
                "content_type": content_type,
                "payload": payload_bytes,
                "size": len(payload_bytes),
                "disposition": content_disposition or "inline",
            }
        )


def _decode_bytes(payload: bytes, charset: str) -> str:
    attempts = [charset, "utf-8", "latin-1"]
    for encoding in attempts:
        try:
            return payload.decode(encoding, errors="replace")
        except LookupError:
            continue
    return payload.decode("utf-8", errors="replace") if payload else ""


def _run_authentication_checks(metadata: Mapping[str, Any], message: EmailMessage) -> List[VerificationResult]:
    enriched_metadata = dict(metadata)
    if "headers" not in enriched_metadata:
        enriched_metadata["headers"] = _headers_dict(message)
    if "raw_source" not in enriched_metadata:
        enriched_metadata["raw_source"] = message.as_bytes()

    return [
        verify_spf(enriched_metadata),
        verify_dkim(enriched_metadata),
        verify_dmarc(enriched_metadata, message=message),
    ]


def _all_authentication_failed(results: Iterable[VerificationResult]) -> bool:
    results_list = list(results)
    failures = [result for result in results_list if result.passed is False]
    return len(failures) == 3 and len(results_list) == 3


def _gather_contributions(
    *,
    metadata: Dict[str, Any],
    body_texts: Iterable[str],
    attachments: Iterable[Dict[str, Any]],
) -> List[SignalContribution]:
    base_contributions = [
        analyze_url_reputation(body_texts),
        analyze_attachments(attachments),
        analyze_sender_behavior(metadata),
        analyze_ip_geolocation(metadata),
        analyze_whois(metadata),
        analyze_with_sandbox(metadata),
    ]
    predictive = analyze_predictive_signals(metadata, base_contributions)
    return base_contributions + [predictive]


def _combine_risk_scores(contributions: Iterable[SignalContribution]) -> float:
    contributions = list(contributions)
    total_weight = sum(
        contribution.weight for contribution in contributions if contribution.weight > 0
    )
    if total_weight == 0:
        return 0.0
    total_score = sum(contribution.weighted_score() for contribution in contributions)
    return round(min(total_score / total_weight, 100.0), 2)


def _score_to_verdict(score: float, thresholds: Dict[str, float]) -> str:
    danger = thresholds.get("danger", DEFAULT_THRESHOLDS["danger"])
    review = thresholds.get("review", DEFAULT_THRESHOLDS["review"])
    danger, review = sorted((danger, review))

    if score <= danger:
        return "malicious"
    if score <= review:
        return "review"
    return "benign"


def _risk_to_confidence(risk_score: float) -> float:
    """Convert an aggregated risk score into a 0-100 confidence rating."""

    return round(max(0.0, min(100.0, 100.0 - risk_score)), 2)


def _public_metadata(metadata: Dict[str, Any], attachment_count: int) -> Dict[str, Any]:
    summary = {
        key: metadata.get(key)
        for key in ["message_id", "subject", "from", "to", "reply_to", "from_domain", "source_ip"]
        if metadata.get(key) is not None
    }
    summary["attachment_count"] = attachment_count
    return summary


def _record_observation(
    metadata: Mapping[str, Any],
    contributions: Sequence[SignalContribution],
    verdict: str,
    risk_score: float,
) -> None:
    """Persist predictive and community telemetry, ignoring runtime hiccups."""

    try:
        predictive_model = get_predictive_model()
        predictive_model.record(metadata, contributions, verdict=verdict, risk_score=risk_score)
    except Exception:
        pass

    try:
        community_hub = get_community_hub()
        community_hub.record_observation(
            metadata, contributions, verdict=verdict, risk_score=risk_score
        )
    except Exception:
        pass


__all__ = ["analyze_email"]