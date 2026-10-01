"""Report generation for EverbloomSecurity scan results.

This module provides helpers for converting a list of scan result dictionaries
into CSV, JSON, and plain-text summaries, while optionally filtering the
results by threat level, engine, and date range.
"""

from __future__ import annotations

import csv
import io
import json
from datetime import datetime, timezone

try:
    from datetime import UTC
except ImportError:  # Python < 3.11
    UTC = timezone.utc
from typing import Any, Iterable, Mapping
from .threat_naming import ThreatNameFormat


class ReportGenerator:
    """Generate structured reports for scan results.

    The input is expected to be a list of dictionaries with scan result data,
    such as file path, threat name, engine, score values, and timestamps.
    """

    CSV_COLUMNS: tuple[str, ...] = (
        "File Path",
        "Threat Name",
        "Hash Score",
        "YARA Score",
        "Heuristic Score",
        "AI Score",
        "Action",
    )

    @staticmethod
    def _coerce_datetime(value: Any) -> datetime | None:
        """Return a parsed datetime or ``None`` when the input is missing."""
        if value in (None, ""):
            return None
        if isinstance(value, datetime):
            return value
        if isinstance(value, (int, float)):
            return datetime.fromtimestamp(value)
        if isinstance(value, str):
            text = value.strip()
            if not text:
                return None
            try:
                return datetime.fromisoformat(text.replace("Z", "+00:00"))
            except ValueError:
                try:
                    return datetime.strptime(text, "%Y-%m-%d %H:%M:%S")
                except ValueError:
                    return None
        return None

    @classmethod
    def _normalize_result(cls, result: Mapping[str, Any]) -> dict[str, Any]:
        """Normalize a scan result dictionary into a stable shape."""
        file_path = (
            result.get("file_path")
            or result.get("filePath")
            or result.get("path")
            or result.get("File Path")
            or ""
        )
        threat_name = (
            result.get("threat_name")
            or result.get("threatName")
            or result.get("threat")
            or result.get("Threat Name")
            or result.get("name")
            or "Unknown"
        )
        threat_name = ThreatNameFormat.normalize_threat_name(str(threat_name))
        threat_level = (
            result.get("threat_level")
            or result.get("threatLevel")
            or result.get("severity")
            or result.get("Threat Level")
            or "unknown"
        )
        engine = (
            result.get("engine")
            or result.get("Engine")
            or result.get("detection_engine")
            or "unknown"
        )
        date_value = (
            result.get("date")
            or result.get("timestamp")
            or result.get("scan_time")
            or result.get("Date")
            or ""
        )
        hash_score = result.get("hash_score") or result.get("hashScore") or result.get("Hash Score") or 0.0
        yara_score = result.get("yara_score") or result.get("yaraScore") or result.get("YARA Score") or 0.0
        heuristic_score = (
            result.get("heuristic_score")
            or result.get("heuristicScore")
            or result.get("Heuristic Score")
            or 0.0
        )
        ai_score = result.get("ai_score") or result.get("aiScore") or result.get("AI Score") or 0.0
        action = result.get("action") or result.get("Action") or "pending"

        return {
            "file_path": str(file_path),
            "threat_name": str(threat_name),
            "threat_level": str(threat_level).lower(),
            "engine": str(engine),
            "date": str(date_value),
            "hash_score": float(hash_score),
            "yara_score": float(yara_score),
            "heuristic_score": float(heuristic_score),
            "ai_score": float(ai_score),
            "action": str(action),
        }

    @classmethod
    def filter_results(
        cls,
        results: Iterable[Mapping[str, Any]],
        *,
        threat_level: str | None = None,
        engine: str | None = None,
        start_date: str | datetime | None = None,
        end_date: str | datetime | None = None,
    ) -> list[dict[str, Any]]:
        """Filter results by threat level, engine, and date range.

        Args:
            results: Iterable of scan result dictionaries.
            threat_level: Optional severity filter such as ``malicious`` or ``suspicious``.
            engine: Optional engine name filter.
            start_date: Optional lower bound for the scan timestamp.
            end_date: Optional upper bound for the scan timestamp.

        Returns:
            A filtered list of normalized result dictionaries.
        """
        normalized = [cls._normalize_result(result) for result in results]

        start_dt = cls._coerce_datetime(start_date)
        end_dt = cls._coerce_datetime(end_date)

        filtered: list[dict[str, Any]] = []
        for item in normalized:
            if threat_level is not None and item["threat_level"] != str(threat_level).lower():
                continue
            if engine is not None and str(engine).lower() not in str(item["engine"]).lower():
                continue

            item_dt = cls._coerce_datetime(item["date"])
            if start_dt is not None and item_dt is not None and item_dt < start_dt:
                continue
            if end_dt is not None and item_dt is not None and item_dt > end_dt:
                continue

            filtered.append(item)

        return filtered

    @classmethod
    def to_csv(
        cls,
        results: Iterable[Mapping[str, Any]],
        *,
        threat_level: str | None = None,
        engine: str | None = None,
        start_date: str | datetime | None = None,
        end_date: str | datetime | None = None,
    ) -> str:
        """Serialize filtered scan results to CSV text."""
        filtered = cls.filter_results(
            results,
            threat_level=threat_level,
            engine=engine,
            start_date=start_date,
            end_date=end_date,
        )

        buffer = io.StringIO()
        writer = csv.DictWriter(buffer, fieldnames=list(cls.CSV_COLUMNS))
        writer.writeheader()
        for item in filtered:
            writer.writerow(
                {
                    "File Path": item["file_path"],
                    "Threat Name": item["threat_name"],
                    "Hash Score": item["hash_score"],
                    "YARA Score": item["yara_score"],
                    "Heuristic Score": item["heuristic_score"],
                    "AI Score": item["ai_score"],
                    "Action": item["action"],
                }
            )
        return buffer.getvalue()

    @classmethod
    def to_json(
        cls,
        results: Iterable[Mapping[str, Any]],
        *,
        metadata: Mapping[str, Any] | None = None,
        threat_level: str | None = None,
        engine: str | None = None,
        start_date: str | datetime | None = None,
        end_date: str | datetime | None = None,
    ) -> str:
        """Serialize filtered scan results to a structured JSON report."""
        filtered = cls.filter_results(
            results,
            threat_level=threat_level,
            engine=engine,
            start_date=start_date,
            end_date=end_date,
        )

        payload = {
            "metadata": {
                "generated_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
                "result_count": len(filtered),
                "filters": {
                    "threat_level": threat_level,
                    "engine": engine,
                    "start_date": start_date.isoformat() if isinstance(start_date, datetime) else start_date,
                    "end_date": end_date.isoformat() if isinstance(end_date, datetime) else end_date,
                },
                **(dict(metadata) if metadata is not None else {}),
            },
            "results": filtered,
        }
        return json.dumps(payload, indent=2, ensure_ascii=False)

    @classmethod
    def to_text_summary(
        cls,
        results: Iterable[Mapping[str, Any]],
        *,
        threat_level: str | None = None,
        engine: str | None = None,
        start_date: str | datetime | None = None,
        end_date: str | datetime | None = None,
    ) -> str:
        """Create a plain-text summary of the filtered scan results."""
        filtered = cls.filter_results(
            results,
            threat_level=threat_level,
            engine=engine,
            start_date=start_date,
            end_date=end_date,
        )

        if not filtered:
            return "No scan results matched the requested filters."

        lines = [
            "EverbloomSecurity Scan Report",
            f"Total results: {len(filtered)}",
            "",
        ]

        for item in filtered:
            lines.append(
                f"- {item['file_path']} | {item['threat_name']} | "
                f"severity={item['threat_level']} | engine={item['engine']} | "
                f"action={item['action']}"
            )

        return "\n".join(lines)


__all__ = ["ReportGenerator"]
