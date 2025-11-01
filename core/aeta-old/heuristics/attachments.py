"""Attachment risk heuristics."""
from __future__ import annotations

import hashlib
from typing import Dict, Iterable, List

from ..models import SignalContribution
from ..utils.containerization import mark_analysis_container

SUSPICIOUS_EXTENSIONS = {".exe", ".scr", ".js", ".vbs", ".bat", ".cmd", ".com", ".msi", ".ps1"}
ARCHIVE_EXTENSIONS = {".zip", ".rar", ".7z", ".gz", ".tar"}


def _extension(filename: str) -> str:
    if not filename or "." not in filename:
        return ""
    return filename.lower()[filename.rfind(".") :]


def _attachment_hash(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def analyze_attachments(attachments: Iterable[Dict[str, object]]) -> SignalContribution:
    """Score attachment risk based on simple heuristics."""

    details: List[Dict[str, object]] = []
    containers: List[Dict[str, object]] = []
    score = 0.0
    weight = 1.5

    for attachment in attachments:
        filename = str(attachment.get("filename") or "")
        content_type = str(attachment.get("content_type") or "")
        payload = attachment.get("payload")
        payload_bytes = b""
        if isinstance(payload, bytes):
            payload_bytes = payload
        extension = _extension(filename)
        attachment_details: Dict[str, object] = {
            "filename": filename,
            "content_type": content_type,
            "extension": extension,
        }
        if payload_bytes:
            attachment_details["sha256"] = _attachment_hash(payload_bytes)

        if extension in SUSPICIOUS_EXTENSIONS:
            score += 35
            attachment_details["flag"] = "dangerous_extension"
        elif extension in ARCHIVE_EXTENSIONS:
            score += 15
            attachment_details["flag"] = "archive"
        elif not extension:
            score += 10
            attachment_details["flag"] = "no_extension"

        if payload_bytes and len(payload_bytes) > 10_000_000:
            score += 5
            attachment_details["size_flag"] = "large_attachment"

        container = mark_analysis_container(
            attachment_details,
            "file",
            attachment_details.get("sha256") or filename or content_type,
            metadata={"filename": filename, "content_type": content_type, "extension": extension},
            confidence=0.85,
        )
        containers.append(container)

        details.append(attachment_details)

    if details and score == 0:
        score = 5

    score = min(score, 100.0)
    return SignalContribution(
        name="attachments",
        score=score,
        weight=weight,
        details={"attachments": details, "containers": containers},
    )
