"""Run repeatable YARA and optional ONNX quality baselines.

The corpus is intentionally synthetic and inert. This tool measures regression
signals, not production malware-detection efficacy.

When ``--gate`` is set the tool exits with a non-zero status if any of the
configured thresholds (``--max-fp-rate``, ``--max-fn-rate``, ``--max-p95-ms``)
is violated, so the script can be wired into CI to fail the build on a
detection or performance regression.
"""

from __future__ import annotations

import argparse
import json
import math
import time
from pathlib import Path
from typing import Any

from everbloom_core.adversarial import normalize_for_rust_runtime


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_MANIFEST = ROOT / "tests" / "corpus" / "manifest.json"
DEFAULT_RULES_DIR = ROOT / "data" / "rules"
DEFAULT_RULES = DEFAULT_RULES_DIR / "everbloom_core.yar"
DEFAULT_MODEL = ROOT / "everbloom_feature_cnn.onnx"
DEFAULT_MODEL_CORPUS = ROOT / "dense_test_features.npy"
DEFAULT_MODEL_LABELS = ROOT / "dense_test_labels.npy"


def _percentile(values: list[float], percentile: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, math.ceil(percentile * len(ordered)) - 1))
    return ordered[index]


def _load_rules_source(rules_path: Path) -> str:
    """Concatenate every ``.yar``/``.yara`` file in ``rules_path``.

    A single file path is loaded as-is; a directory path is loaded by
    concatenating its rules in sorted order so the engine-equivalent corpus
    participates in the baseline.
    """
    if rules_path.is_dir():
        sources = [
            entry
            for entry in sorted(rules_path.iterdir())
            if entry.is_file()
            and entry.suffix.lower() in {".yar", ".yara"}
        ]
        if not sources:
            raise FileNotFoundError(
                f"no .yar/.yara files found under rules directory {rules_path}"
            )
        return "\n".join(source.read_text(encoding="utf-8") for source in sources)
    return rules_path.read_text(encoding="utf-8")


def run_yara(manifest_path: Path, rules_path: Path) -> dict[str, Any]:
    import yara

    rules = yara.compile(source=_load_rules_source(rules_path))
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    durations: list[float] = []
    false_positives: list[str] = []
    false_negatives: list[str] = []
    records: list[dict[str, Any]] = []
    total_bytes = 0

    for sample in manifest["samples"]:
        path = ROOT / "tests" / "corpus" / sample["path"]
        total_bytes += path.stat().st_size
        started = time.perf_counter()
        matches = {match.rule for match in rules.match(str(path))}
        elapsed_ms = (time.perf_counter() - started) * 1000.0
        durations.append(elapsed_ms)
        expected = set(sample.get("expected_rules", []))
        if sample["label"] == 0 and matches:
            false_positives.append(sample["path"])
        if sample["label"] == 1 and not expected.issubset(matches):
            false_negatives.append(sample["path"])
        records.append(
            {
                "path": sample["path"],
                "label": sample["label"],
                "matches": sorted(matches),
                "elapsed_ms": round(elapsed_ms, 4),
            }
        )

    total_ms = sum(durations)
    return {
        "status": "ok",
        "files": len(records),
        "bytes": total_bytes,
        "false_positives": false_positives,
        "false_negatives": false_negatives,
        "false_positive_rate": len(false_positives) / max(1, sum(s["label"] == 0 for s in manifest["samples"])),
        "false_negative_rate": len(false_negatives) / max(1, sum(s["label"] == 1 for s in manifest["samples"])),
        "total_elapsed_ms": round(total_ms, 4),
        "average_elapsed_ms": round(total_ms / max(1, len(records)), 4),
        "p95_elapsed_ms": round(_percentile(durations, 0.95), 4),
        "files_per_second": round(len(records) / max(total_ms / 1000.0, 0.000001), 2),
        "records": records,
    }


def _model_score(output: Any) -> float:
    import numpy as np

    values = np.asarray(output, dtype=np.float32).reshape(-1)
    if values.size == 0:
        return 0.0
    if values.size == 1:
        value = float(values[0])
        return value if 0.0 <= value <= 1.0 else 1.0 / (1.0 + math.exp(-value))
    shifted = values - values.max()
    probabilities = np.exp(shifted) / np.exp(shifted).sum()
    return float(probabilities[-1])


def run_model(model_path: Path, corpus_path: Path, labels_path: Path) -> dict[str, Any]:
    try:
        import numpy as np
        import onnxruntime as ort
    except ImportError as exc:
        return {"status": "skipped", "reason": f"optional dependency unavailable: {exc}"}
    if not model_path.exists():
        return {"status": "skipped", "reason": f"model not found: {model_path}"}

    session = ort.InferenceSession(str(model_path), providers=["CPUExecutionProvider"])
    input_meta = session.get_inputs()[0]
    shape = input_meta.shape
    expected_width = shape[-1] if shape and isinstance(shape[-1], int) else None
    if corpus_path.suffix.lower() == ".npy":
        if expected_width is None or not labels_path.exists():
            return {"status": "skipped", "reason": "raw model corpus requires a fixed input width and labels file"}
        raw_features = np.fromfile(corpus_path, dtype=np.float32)
        raw_labels = np.fromfile(labels_path, dtype=np.uint8)
        if raw_features.size % expected_width != 0:
            return {"status": "skipped", "reason": "raw model feature file is not divisible by the ONNX input width"}
        feature_matrix = raw_features.reshape(-1, expected_width)
        if feature_matrix.shape[0] != raw_labels.size:
            return {"status": "skipped", "reason": "raw model features and labels have different sample counts"}
        feature_map = ROOT / "features.json"
        feature_matrix = normalize_for_rust_runtime(
            feature_matrix,
            feature_map if feature_map.exists() else None,
            "auto",
        )
        rows = [{"label": int(label), "features": vector} for label, vector in zip(raw_labels, feature_matrix)]
    else:
        rows = [
            json.loads(line)
            for line in corpus_path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
    scores: list[float] = []
    labels: list[int] = []
    elapsed: list[float] = []

    for row in rows:
        sparse = row["features"]
        if isinstance(sparse, dict):
            width = expected_width or (max(map(int, sparse), default=-1) + 1)
            vector = np.zeros(width, dtype=np.float32)
            for index, value in sparse.items():
                if int(index) < width:
                    vector[int(index)] = float(value)
        else:
            vector = np.asarray(sparse, dtype=np.float32)
        candidates = []
        if shape and all(isinstance(dimension, int) and dimension > 0 for dimension in shape):
            expected_elements = math.prod(shape)
            if expected_elements == vector.size:
                candidates.append(vector.reshape(tuple(shape)))
            elif shape[-1] == vector.size:
                padded_shape = tuple(1 if not isinstance(dimension, int) else dimension for dimension in shape[:-1])
                candidates.append(vector.reshape(padded_shape + (vector.size,)))
        candidates.extend((vector.reshape(1, -1), vector))
        last_error: Exception | None = None
        started = time.perf_counter()
        for candidate in candidates:
            try:
                output = session.run(None, {input_meta.name: candidate})[0]
                scores.append(_model_score(output))
                labels.append(int(row["label"]))
                elapsed.append((time.perf_counter() - started) * 1000.0)
                break
            except Exception as exc:  # model shapes vary between exported ONNX files
                last_error = exc
        else:
            return {"status": "skipped", "reason": f"model input shape is incompatible: {last_error}"}

    predictions = [int(score >= 0.5) for score in scores]
    tp = sum(pred == label == 1 for pred, label in zip(predictions, labels))
    tn = sum(pred == label == 0 for pred, label in zip(predictions, labels))
    fp = sum(pred == 1 and label == 0 for pred, label in zip(predictions, labels))
    fn = sum(pred == 0 and label == 1 for pred, label in zip(predictions, labels))
    return {
        "status": "ok",
        "samples": len(labels),
        "normalization": "auto" if corpus_path.suffix.lower() == ".npy" else "none",
        "accuracy": (tp + tn) / max(1, len(labels)),
        "precision": tp / max(1, tp + fp),
        "recall": tp / max(1, tp + fn),
        "false_positive_rate": fp / max(1, fp + tn),
        "false_negative_rate": fn / max(1, fn + tp),
        "average_elapsed_ms": sum(elapsed) / max(1, len(elapsed)),
        "p95_elapsed_ms": _percentile(elapsed, 0.95),
        "threshold": 0.5,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument(
        "--rules",
        type=Path,
        default=DEFAULT_RULES,
        help=(
            "Path to a single .yar file or a directory of rule files. When a "
            "directory is provided, every .yar/.yara file inside is compiled "
            "together (mirrors the engine's data/rules layout)."
        ),
    )
    parser.add_argument("--model", type=Path, default=DEFAULT_MODEL)
    parser.add_argument("--model-corpus", type=Path, default=DEFAULT_MODEL_CORPUS)
    parser.add_argument("--model-labels", type=Path, default=DEFAULT_MODEL_LABELS)
    parser.add_argument("--output", type=Path, default=ROOT / "artifacts" / "quality-baseline" / "latest.json")
    parser.add_argument(
        "--gate",
        action="store_true",
        help="Exit non-zero if the configured thresholds are violated.",
    )
    parser.add_argument("--max-fp-rate", type=float, default=0.0, help="Maximum tolerated false-positive rate (0..1).")
    parser.add_argument("--max-fn-rate", type=float, default=0.0, help="Maximum tolerated false-negative rate (0..1).")
    parser.add_argument("--max-p95-ms", type=float, default=5.0, help="Maximum tolerated per-file p95 scan latency (ms).")
    parser.add_argument(
        "--max-model-fp-rate",
        type=float,
        default=0.5,
        help="Maximum tolerated model false-positive rate (0..1).",
    )
    parser.add_argument(
        "--max-model-fn-rate",
        type=float,
        default=0.5,
        help="Maximum tolerated model false-negative rate (0..1).",
    )
    parser.add_argument(
        "--min-model-samples",
        type=int,
        default=20,
        help="Minimum model sample count required for the model gate to apply.",
    )
    args = parser.parse_args()

    rules_for_display = args.rules.resolve()
    result = {
        "schema": 1,
        "generated_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "corpus": str(args.manifest.relative_to(ROOT)),
        "rules_source": str(rules_for_display.relative_to(ROOT)) if rules_for_display.is_relative_to(ROOT) else str(rules_for_display),
        "yara": run_yara(args.manifest, args.rules),
        "model": run_model(args.model, args.model_corpus, args.model_labels),
    }

    gate: dict[str, Any] = {
        "enabled": args.gate,
        "violations": [],
        "passed": True,
        "thresholds": {
            "yara": {
                "false_positive_rate": args.max_fp_rate,
                "false_negative_rate": args.max_fn_rate,
                "p95_elapsed_ms": args.max_p95_ms,
            },
            "model": {
                "false_positive_rate": args.max_model_fp_rate,
                "false_negative_rate": args.max_model_fn_rate,
                "min_samples": args.min_model_samples,
            },
        },
    }
    yara_block = result["yara"]
    if isinstance(yara_block, dict):
        for name, observed, threshold in (
            ("false_positive_rate", yara_block.get("false_positive_rate", 0.0), args.max_fp_rate),
            ("false_negative_rate", yara_block.get("false_negative_rate", 0.0), args.max_fn_rate),
            ("p95_elapsed_ms", yara_block.get("p95_elapsed_ms", 0.0), args.max_p95_ms),
        ):
            if observed is not None and observed > threshold:
                gate["violations"].append(
                    {"metric": name, "observed": observed, "threshold": threshold}
                )
                gate["passed"] = False
    model_block = result["model"]
    if (
        isinstance(model_block, dict)
        and model_block.get("status") == "ok"
        and model_block.get("samples", 0) >= args.min_model_samples
    ):
        for name, observed, threshold in (
            ("false_positive_rate", model_block.get("false_positive_rate", 0.0), args.max_model_fp_rate),
            ("false_negative_rate", model_block.get("false_negative_rate", 0.0), args.max_model_fn_rate),
        ):
            if observed is not None and observed > threshold:
                gate["violations"].append(
                    {"metric": f"model.{name}", "observed": observed, "threshold": threshold}
                )
                gate["passed"] = False
    elif (
        isinstance(model_block, dict)
        and model_block.get("status") == "ok"
        and model_block.get("samples", 0) < args.min_model_samples
    ):
        gate["model_skipped_reason"] = (
            f"model sample count {model_block.get('samples', 0)} below minimum {args.min_model_samples}"
        )
    result["gate"] = gate

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result, ensure_ascii=False, indent=2))
    if args.gate and not gate["passed"]:
        for violation in gate["violations"]:
            print(
                f"quality gate violation: {violation['metric']}={violation['observed']} > {violation['threshold']}",
                file=__import__("sys").stderr,
            )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
