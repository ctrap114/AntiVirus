"""Pydantic v2 configuration models for EverbloomSecurity engine settings.

This module provides a lightweight schema for serializing engine configuration
through IPC and other JSON-based transports.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field, field_validator


class EngineConfig(BaseModel):
    """Configuration for the EverbloomSecurity engine runtime.

    Attributes:
        hash_enabled: Whether file hashing is enabled.
        yara_enabled: Whether YARA signature scanning is enabled.
        yara_rules_path: Path to the YARA rules directory or file.
        heuristic_enabled: Whether heuristic scanning is enabled.
        ai_enabled: Whether AI-based scanning is enabled.
        ai_model_path: Path to the AI model artifact.
        ai_threshold: Confidence threshold for AI detection.
        sandbox_enabled: Whether sandbox execution is enabled.
        sandbox_timeout_sec: Sandbox execution timeout in seconds.
        cache_size_mb: Engine cache size in megabytes.
        exclude_paths: Paths excluded from scanning.
        cpu_limit_percent: CPU usage limit percentage.
    """

    hash_enabled: bool = Field(default=True)
    yara_enabled: bool = Field(default=True)
    yara_rules_path: str | None = Field(default=None)
    heuristic_enabled: bool = Field(default=True)
    ai_enabled: bool = Field(default=True)
    ai_model_path: str | None = Field(default=None)
    ai_threshold: float = Field(default=0.7, ge=0.0, le=1.0)
    sandbox_enabled: bool = Field(default=False)
    sandbox_timeout_sec: int = Field(default=30, ge=5, le=120)
    cache_size_mb: int = Field(default=256, ge=64, le=1024)
    exclude_paths: list[str] = Field(default_factory=list)
    cpu_limit_percent: int = Field(default=80, ge=10, le=100)

    model_config = {
        "extra": "forbid",
        "str_strip_whitespace": True,
    }

    @field_validator("yara_rules_path", "ai_model_path", mode="before")
    @classmethod
    def _normalize_optional_path(cls, value: Any) -> str | None:
        """Normalize optional file-system paths to strings.

        Args:
            value: The raw input value.

        Returns:
            A normalized string path or ``None``.
        """
        if value in (None, ""):
            return None
        if isinstance(value, Path):
            return str(value)
        if isinstance(value, str):
            return value.strip()
        raise TypeError("path values must be strings or pathlib.Path instances")

    @field_validator("exclude_paths", mode="before")
    @classmethod
    def _normalize_exclude_paths(cls, value: Any) -> list[str]:
        """Normalize exclude paths to a list of non-empty strings.

        Args:
            value: The raw input value.

        Returns:
            A cleaned list of exclude paths.
        """
        if value is None:
            return []
        if isinstance(value, str):
            value = [value]
        if not isinstance(value, (list, tuple, set)):
            raise TypeError("exclude_paths must be a string or an iterable of strings")

        cleaned: list[str] = []
        for item in value:
            if item is None:
                continue
            if not isinstance(item, str):
                raise TypeError("exclude_paths entries must be strings")
            normalized = item.strip()
            if normalized:
                cleaned.append(normalized)
        return cleaned

    def model_dump_json(self, **kwargs: Any) -> str:
        """Serialize the model to a JSON string for IPC use.

        Args:
            **kwargs: Additional keyword arguments forwarded to
                :meth:`pydantic.BaseModel.model_dump_json`.

        Returns:
            A JSON string representation of the model.
        """
        return super().model_dump_json(**kwargs)

    @classmethod
    def model_validate_json(cls, json_data: str | bytes | bytearray, **kwargs: Any) -> "EngineConfig":
        """Deserialize a JSON string or bytes payload into an EngineConfig.

        Args:
            json_data: The serialized JSON payload.
            **kwargs: Additional keyword arguments forwarded to
                :meth:`pydantic.BaseModel.model_validate_json`.

        Returns:
            A validated :class:`EngineConfig` instance.
        """
        return super().model_validate_json(json_data, **kwargs)


__all__ = ["EngineConfig"]
