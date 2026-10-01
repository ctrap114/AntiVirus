"""Safety and determinism checks for the inert synthetic corpus generator."""

from __future__ import annotations

import json

import numpy as np
import pytest

from everbloom_core.synthetic import (
    FAMILY_BUILDERS,
    SYNTHETIC_MARKER,
    build_pe,
    extract_features_12,
    generate_corpus,
    load_corpus_features,
    validate_output_root,
)


def _build(name: str) -> bytes:
    return build_pe(FAMILY_BUILDERS[name](), seed=42)


@pytest.mark.parametrize("family", sorted(FAMILY_BUILDERS))
def test_generated_samples_are_marked_and_inert(family: str) -> None:
    blob = _build(family)

    assert SYNTHETIC_MARKER in blob, "safety marker missing"
    assert blob[:2] == b"MZ"

    entry_offset = 0x80 + 4 + 20 + 16
    e_lfanew = int(np.frombuffer(blob, dtype="<u4", offset=0x3C)[0])
    opt = e_lfanew + 4 + 20
    entry_rva = int(np.frombuffer(blob, dtype="<u4", offset=opt + 16)[0])
    # Both layouts keep the RET stub at the start of its section payload.
    del entry_offset
    section_table = opt + 240
    stub_found = False
    for index in range(int(np.frombuffer(blob, dtype="<u2", offset=e_lfanew + 6)[0])):
        header = section_table + 40 * index
        virtual_address = int(np.frombuffer(blob, dtype="<u4", offset=header + 12)[0])
        raw_size = int(np.frombuffer(blob, dtype="<u4", offset=header + 16)[0])
        raw_ptr = int(np.frombuffer(blob, dtype="<u4", offset=header + 20)[0])
        if virtual_address <= entry_rva < virtual_address + max(raw_size, 1):
            stub = blob[raw_ptr + (entry_rva - virtual_address)]
            assert stub == 0xC3, "entry point must remain a single RET"
            stub_found = True
            break
    assert stub_found, "entry RVA did not map into any section"


def test_feature_extractor_separates_classes() -> None:
    benign = extract_features_12(_build("benign_like"), now_seconds=1_800_000_000)
    packed = extract_features_12(_build("packed_like"), now_seconds=1_800_000_000)
    stealth = extract_features_12(_build("stealth_like"), now_seconds=1_800_000_000)

    assert benign[3] == 0.0, "benign template must not carry TLS"
    assert packed[3] == 1.0 and stealth[3] == 1.0
    assert stealth[10] > benign[10], "stealth entropy must exceed benign"
    assert packed[4] == 1.0, "zero timestamp must be anomalous"
    assert benign[2] > 0.0, "benign template should parse imports"


def test_generation_is_deterministic(tmp_path) -> None:
    first = build_pe(FAMILY_BUILDERS["packed_like"](), seed=7)
    second = build_pe(FAMILY_BUILDERS["packed_like"](), seed=7)
    other = build_pe(FAMILY_BUILDERS["packed_like"](), seed=8)
    assert first == second
    assert first != other


def test_corpus_writer_emits_manifest_and_summary(tmp_path) -> None:
    summary = generate_corpus(
        tmp_path,
        {"benign_like": 2, "packed_like": 2},
        seed=99,
        force=True,
    )
    assert summary["sample_count"] == 4
    manifest = tmp_path / "manifest.jsonl"
    rows = [json.loads(line) for line in manifest.read_text(encoding="utf-8").splitlines()]
    assert len(rows) == 4
    for row in rows:
        assert (tmp_path / row["path"]).exists()
        assert row["sha256"]
        assert SYNTHETIC_MARKER in (tmp_path / row["path"]).read_bytes()

    features, labels, families, paths = load_corpus_features(manifest)
    assert features.shape == (4, 12)
    assert set(labels.tolist()) == {0.0, 1.0}
    assert set(families) == {"benign_like", "packed_like"}
    assert len(paths) == 4


def test_refuses_to_overwrite_without_force(tmp_path) -> None:
    generate_corpus(tmp_path, {"benign_like": 1}, seed=1)
    with pytest.raises(FileExistsError):
        generate_corpus(tmp_path, {"benign_like": 1}, seed=1)


@pytest.mark.parametrize(
    "root",
    [
        "C:\\Windows\\temp",
        "C:\\Program Files\\x",
        "C:\\",
    ],
)
def test_refuses_protected_output_locations(root: str) -> None:
    with pytest.raises(ValueError):
        validate_output_root(__import__("pathlib").Path(root))
