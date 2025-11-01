"""Heuristic self-auditing utilities."""
from __future__ import annotations

import threading
from collections import deque
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Deque, Dict, Iterable, List, Optional


@dataclass
class AuditRecord:
    """Represents a single heuristic execution summary."""

    heuristic: str
    score: float
    triggers: List[str]
    timestamp: datetime


class HeuristicAuditLogger:
    """Tracks heuristic scoring behaviour and emits diagnostics."""

    def __init__(self, max_records: int = 500) -> None:
        self._records: Deque[AuditRecord] = deque(maxlen=max_records)
        self._lock = threading.RLock()

    def record(self, heuristic: str, score: float, triggers: Iterable[str]) -> AuditRecord:
        with self._lock:
            record = AuditRecord(
                heuristic=heuristic,
                score=score,
                triggers=list(triggers),
                timestamp=datetime.now(tz=timezone.utc),
            )
            self._records.append(record)
            return record

    def assess(self, heuristic: str, score: float, triggers: Iterable[str]) -> Dict[str, object]:
        record = self.record(heuristic, score, triggers)
        summary = self.summary(heuristic)
        status = "ok"
        message = "Scoring distribution is within expected bounds."
        high_ratio = summary.get("high_ratio", 0.0)
        low_ratio = summary.get("low_ratio", 0.0)
        if summary.get("count", 0) >= 10:
            if high_ratio >= 0.6 and low_ratio <= 0.2:
                status = "warning"
                message = (
                    "Heuristic is trending aggressive – review thresholding to avoid false positives."
                )
            elif low_ratio >= 0.6 and high_ratio <= 0.2:
                status = "warning"
                message = "Heuristic is trending passive – consider tightening detection criteria."
        return {
            "status": status,
            "message": message,
            "statistics": summary,
            "last_triggers": record.triggers,
        }

    def summary(self, heuristic: str) -> Dict[str, object]:
        with self._lock:
            relevant = [record for record in self._records if record.heuristic == heuristic]
        if not relevant:
            return {"count": 0, "average_score": 0.0, "high_ratio": 0.0, "low_ratio": 0.0}

        count = len(relevant)
        high = sum(1 for record in relevant if record.score >= 70)
        low = sum(1 for record in relevant if record.score <= 10)
        average = sum(record.score for record in relevant) / count
        newest = max(relevant, key=lambda rec: rec.timestamp)
        oldest = min(relevant, key=lambda rec: rec.timestamp)
        return {
            "count": count,
            "average_score": round(average, 2),
            "high_ratio": round(high / count, 3),
            "low_ratio": round(low / count, 3),
            "oldest": oldest.timestamp.isoformat(),
            "newest": newest.timestamp.isoformat(),
        }


_audit_logger: Optional[HeuristicAuditLogger] = None
_audit_lock = threading.Lock()


def get_audit_logger() -> HeuristicAuditLogger:
    global _audit_logger
    with _audit_lock:
        if _audit_logger is None:
            _audit_logger = HeuristicAuditLogger()
        return _audit_logger


def reset_audit_logger() -> None:
    global _audit_logger
    with _audit_lock:
        _audit_logger = None
