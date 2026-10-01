"""Preset definitions for EverbloomSecurity engine operating modes.

This module exposes named presets that map to validated
:class:`~everbloom_config.schema.EngineConfig` instances for common scanning
profiles.
"""

from __future__ import annotations

from enum import Enum
from typing import Final

from .schema import EngineConfig


class EnginePreset(str, Enum):
    """Supported engine preset modes."""

    AGGRESSIVE = "aggressive"
    BALANCED = "balanced"
    STEALTHY = "stealthy"


def _build_preset_config(
    *,
    ai_threshold: float,
    sandbox_timeout_sec: int,
    cache_size_mb: int,
    cpu_limit_percent: int,
    ai_enabled: bool,
    heuristic_enabled: bool,
    sandbox_enabled: bool,
    hash_enabled: bool = True,
    yara_enabled: bool = True,
) -> EngineConfig:
    """Create a validated engine config for a preset.

    Args:
        ai_threshold: Confidence threshold used by the AI engine.
        sandbox_timeout_sec: Sandbox timeout in seconds.
        cache_size_mb: Cache size in megabytes.
        cpu_limit_percent: CPU usage limit percentage.
        ai_enabled: Whether AI scanning is enabled.
        heuristic_enabled: Whether heuristic scanning is enabled.
        sandbox_enabled: Whether sandbox execution is enabled.
        hash_enabled: Whether hashing is enabled.
        yara_enabled: Whether YARA scanning is enabled.

    Returns:
        A validated :class:`EngineConfig` instance.
    """
    return EngineConfig(
        hash_enabled=hash_enabled,
        yara_enabled=yara_enabled,
        heuristic_enabled=heuristic_enabled,
        ai_enabled=ai_enabled,
        ai_threshold=ai_threshold,
        sandbox_enabled=sandbox_enabled,
        sandbox_timeout_sec=sandbox_timeout_sec,
        cache_size_mb=cache_size_mb,
        cpu_limit_percent=cpu_limit_percent,
    )


PRESET_CONFIGS: Final[dict[EnginePreset, EngineConfig]] = {
    EnginePreset.AGGRESSIVE: _build_preset_config(
        ai_threshold=0.3,
        sandbox_timeout_sec=60,
        cache_size_mb=512,
        cpu_limit_percent=80,
        ai_enabled=True,
        heuristic_enabled=True,
        sandbox_enabled=True,
    ),
    EnginePreset.BALANCED: _build_preset_config(
        ai_threshold=0.5,
        sandbox_timeout_sec=30,
        cache_size_mb=256,
        cpu_limit_percent=50,
        ai_enabled=True,
        heuristic_enabled=True,
        sandbox_enabled=True,
    ),
    EnginePreset.STEALTHY: _build_preset_config(
        ai_threshold=0.7,
        sandbox_timeout_sec=15,
        cache_size_mb=128,
        cpu_limit_percent=20,
        ai_enabled=False,
        heuristic_enabled=False,
        sandbox_enabled=False,
    ),
}


def get_preset_descriptions() -> dict[str, str]:
    """Return human-readable descriptions for the available presets.

    Returns:
        A mapping of preset names to readable descriptions highlighting the
        main differences between them.
    """
    descriptions: dict[str, str] = {}
    for preset in EnginePreset:
        config = PRESET_CONFIGS[preset]
        if preset is EnginePreset.AGGRESSIVE:
            descriptions[preset.value] = (
                "Aggressive mode: maximum coverage with AI, heuristics, sandbox, "
                f"AI threshold {config.ai_threshold:.1f}, sandbox {config.sandbox_timeout_sec}s, "
                f"cache {config.cache_size_mb}MB, CPU limit {config.cpu_limit_percent}%"
            )
        elif preset is EnginePreset.BALANCED:
            descriptions[preset.value] = (
                "Balanced mode: default protection with AI, heuristics, sandbox, "
                f"AI threshold {config.ai_threshold:.1f}, sandbox {config.sandbox_timeout_sec}s, "
                f"cache {config.cache_size_mb}MB, CPU limit {config.cpu_limit_percent}%"
            )
        else:
            descriptions[preset.value] = (
                "Stealthy mode: reduced footprint with hashing and YARA only, "
                f"AI threshold {config.ai_threshold:.1f}, sandbox {config.sandbox_timeout_sec}s, "
                f"cache {config.cache_size_mb}MB, CPU limit {config.cpu_limit_percent}%"
            )
    return descriptions


__all__ = ["EnginePreset", "PRESET_CONFIGS", "get_preset_descriptions"]
