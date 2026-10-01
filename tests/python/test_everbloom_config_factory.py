import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "python"))

from everbloom_config.factory import ConfigFactory
from everbloom_config.presets import EnginePreset
from everbloom_config.schema import EngineConfig


def test_create_from_preset_returns_valid_config():
    config = ConfigFactory.create_from_preset(EnginePreset.BALANCED)

    assert isinstance(config, EngineConfig)
    assert config.ai_threshold == 0.5
    assert config.cache_size_mb == 256
    assert config.cpu_limit_percent == 50


def test_create_from_dict_validates_and_builds_config():
    data = {
        "hash_enabled": True,
        "yara_enabled": True,
        "heuristic_enabled": True,
        "ai_enabled": True,
        "ai_threshold": 0.4,
        "sandbox_enabled": True,
        "sandbox_timeout_sec": 45,
        "cache_size_mb": 256,
        "exclude_paths": ["C:/tmp", "D:/cache"],
        "cpu_limit_percent": 60,
    }

    config = ConfigFactory.create_from_dict(data)

    assert config.ai_threshold == 0.4
    assert config.exclude_paths == ["C:/tmp", "D:/cache"]


def test_merge_configs_applies_partial_overrides():
    base = ConfigFactory.create_from_preset(EnginePreset.BALANCED)
    overrides = {"ai_threshold": 0.2, "cache_size_mb": 384, "exclude_paths": ["/tmp"]}

    merged = ConfigFactory.merge_configs(base, overrides)

    assert merged.ai_threshold == 0.2
    assert merged.cache_size_mb == 384
    assert merged.exclude_paths == ["/tmp"]
    assert merged.ai_enabled is True


def test_to_json_and_from_json_round_trip():
    config = ConfigFactory.create_from_preset(EnginePreset.AGGRESSIVE)

    payload = ConfigFactory.to_json(config)
    restored = ConfigFactory.from_json(payload)

    assert isinstance(restored, EngineConfig)
    assert restored.ai_threshold == config.ai_threshold
    assert restored.cache_size_mb == config.cache_size_mb


def test_invalid_preset_type_raises():
    with pytest.raises(TypeError):
        ConfigFactory.create_from_preset("balanced")
