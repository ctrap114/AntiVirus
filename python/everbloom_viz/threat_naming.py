"""Threat naming helpers for EverbloomSecurity.

This module encodes the repository's standardized malware naming convention:

    <Type>.<Platform>/<Family>.<Variant>

The convention is documented in `docs/malware_naming_convention.md`.
"""

from __future__ import annotations

import re

TYPE_PREFIXES = (
    "Trojan",
    "Worm",
    "Virus",
    "Backdoor",
    "Ransom",
    "Spyware",
    "Adware",
    "HackTool",
    "Exploit",
    "PWS",
    "VirTool",
)

_TYPE_CANONICAL = {prefix.lower(): prefix for prefix in TYPE_PREFIXES}

_ALLOWED_VARIANTS = {"generic", "gen", "dam"}

_THREAT_NAME_RE = re.compile(
    rf"^(?P<type>{'|'.join(TYPE_PREFIXES)})\.(?P<platform>[A-Za-z0-9]+)\/"
    rf"(?P<family>[A-Za-z0-9_\-]+)(?:\.(?P<variant>[A-Za-z0-9]+))?$"
    , re.IGNORECASE
)


def _canonicalize_type(type_prefix: str) -> str:
    return _TYPE_CANONICAL.get(type_prefix.strip().lower(), type_prefix.strip())


def _canonicalize_platform(platform: str) -> str:
    normalized = platform.strip()
    if not normalized:
        return normalized
    if normalized.lower().startswith("win") or normalized.lower().startswith("mac"):
        return normalized[0].upper() + normalized[1:]
    return normalized


def _canonicalize_family(family: str) -> str:
    normalized = re.sub(r"\s+", "_", family.strip())
    if normalized.islower():
        return normalized.title()
    return normalized


def _canonicalize_variant(variant: str) -> str:
    normalized = variant.strip()
    if normalized.lower() in _ALLOWED_VARIANTS:
        return normalized.lower()
    return normalized


class ThreatNameFormat:
    """Utilities for EverbloomSecurity standardized threat names."""

    @staticmethod
    def is_valid_threat_name(name: str) -> bool:
        """Return ``True`` when the input follows the standard threat naming format."""
        return bool(_THREAT_NAME_RE.match(name.strip()))

    @staticmethod
    def normalize_threat_name(name: str) -> str:
        """Normalize a threat name to the repository's standard format."""
        normalized = name.strip()
        if not normalized:
            return "Unknown"

        match = _THREAT_NAME_RE.match(normalized)
        if not match:
            return normalized

        type_prefix = _canonicalize_type(match.group("type"))
        platform = _canonicalize_platform(match.group("platform"))
        family = _canonicalize_family(match.group("family"))
        variant = match.group("variant")
        if variant:
            variant = _canonicalize_variant(variant)
            return f"{type_prefix}.{platform}/{family}.{variant}"

        return f"{type_prefix}.{platform}/{family}"

    @staticmethod
    def format_threat_name(
        type_prefix: str,
        platform: str,
        family: str,
        variant: str | None = None,
    ) -> str:
        """Build a standardized threat name from individual components."""
        if not type_prefix or not platform or not family:
            raise ValueError("type_prefix, platform, and family are required")

        formatted_type = _canonicalize_type(type_prefix)
        formatted_platform = _canonicalize_platform(platform)
        formatted_family = _canonicalize_family(family)
        if variant is None or variant.strip() == "":
            return f"{formatted_type}.{formatted_platform}/{formatted_family}"

        formatted_variant = _canonicalize_variant(variant)
        return f"{formatted_type}.{formatted_platform}/{formatted_family}.{formatted_variant}"


__all__ = [
    "ThreatNameFormat",
    "TYPE_PREFIXES",
    "_ALLOWED_VARIANTS",
]
