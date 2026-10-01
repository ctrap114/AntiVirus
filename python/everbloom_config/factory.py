"""Factory helpers for constructing and merging EverbloomSecurity engine configs.

This module provides convenience methods for creating validated
:class:`~everbloom_config.schema.EngineConfig` instances from presets, raw
mapping values, and JSON payloads.
"""

from __future__ import annotations

import json
from typing import Any

from .presets import EnginePreset, PRESET_CONFIGS
from .schema import EngineConfig


class ConfigFactory:
    """Factory for creating and merging engine configuration objects."""

    @staticmethod
    def create_from_preset(preset: EnginePreset) -> EngineConfig:
        """Create an engine config from a named preset.

        Args:
            preset: The preset to instantiate.

        Returns:
            A validated ``EngineConfig`` instance.
        """
        if not isinstance(preset, EnginePreset):
            raise TypeError("preset must be an EnginePreset instance")
        return PRESET_CONFIGS[preset].model_copy(deep=True)

    @staticmethod
    def create_from_dict(data: dict[str, Any]) -> EngineConfig:
        """Create an engine config from a dictionary.

        Args:
            data: Raw configuration values.

        Returns:
            A validated ``EngineConfig`` instance.
        """
        if not isinstance(data, dict):
            raise TypeError("data must be a dictionary")
        return EngineConfig.model_validate(data)

    @staticmethod
    def merge_configs(base_config: EngineConfig, overrides: dict[str, Any]) -> EngineConfig:
        """Apply partial overrides to an existing config.

        Args:
            base_config: The source configuration to modify.
            overrides: Partial configuration overrides.

        Returns:
            A validated ``EngineConfig`` containing the merged values.
        """
        if not isinstance(base_config, EngineConfig):
            raise TypeError("base_config must be an EngineConfig instance")
        if not isinstance(overrides, dict):
            raise TypeError("overrides must be a dictionary")

        merged_data = base_config.model_dump()
        merged_data.update(overrides)
        return EngineConfig.model_validate(merged_data)

    @staticmethod
    def to_json(config: EngineConfig) -> str:
        """Serialize an engine config to JSON for IPC transport.

        Args:
            config: The config to serialize.

        Returns:
            A JSON payload string.
        """
        if not isinstance(config, EngineConfig):
            raise TypeError("config must be an EngineConfig instance")
        return config.model_dump_json()

    @staticmethod
    def from_json(payload: str) -> EngineConfig:
        """Deserialize an engine config from a JSON payload.

        Args:
            payload: The JSON payload string.

        Returns:
            A validated ``EngineConfig`` instance.
        """
        if not isinstance(payload, str) or not payload.strip():
            raise ValueError("payload must be a non-empty JSON string")
        return EngineConfig.model_validate_json(payload)


__all__ = ["ConfigFactory"]
