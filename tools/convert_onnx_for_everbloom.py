#!/usr/bin/env python3
"""Normalize a single-input ONNX classifier for EverbloomSecurity's tract backend.

This converter deliberately has a narrow contract. It does not execute a
model, rewrite arbitrary graphs, or claim that unsupported multi-input models
are compatible. It validates the graph, optionally converts the default ONNX
opset to the conservative target used by the bundled models, embeds external
weights, and writes the sidecars consumed by the Rust scanner.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import onnx
from onnx import TensorProto, checker, version_converter


MAX_MODEL_BYTES = 512 * 1024 * 1024
DEFAULT_TARGET_OPSET = 12
CANONICAL_FEATURES = [
    "coverage",
    "section_count",
    "import_count",
    "tls_present",
    "timestamp",
    "section_entropy",
    "printable_ratio",
    "null_ratio",
    "distinct_byte_ratio",
    "mean_byte",
    "entropy_norm",
    "large_flag",
]
NUMERIC_TYPES = {
    TensorProto.FLOAT,
    TensorProto.FLOAT16,
    TensorProto.DOUBLE,
    TensorProto.INT8,
    TensorProto.INT16,
    TensorProto.INT32,
    TensorProto.INT64,
    TensorProto.UINT8,
    TensorProto.UINT16,
    TensorProto.UINT32,
    TensorProto.UINT64,
    TensorProto.BOOL,
}


def _safe_file(path: Path, label: str) -> Path:
    path = path.expanduser().resolve(strict=True)
    if not path.is_file():
        raise ValueError(f"{label} must be a regular file")
    if path.suffix.lower() != ".onnx":
        raise ValueError(f"{label} must use the .onnx extension")
    size = path.stat().st_size
    if size == 0 or size > MAX_MODEL_BYTES:
        raise ValueError(f"{label} must be between 1 byte and 512 MiB")
    return path


def _real_inputs(model: onnx.ModelProto) -> list[onnx.ValueInfoProto]:
    initializers = {item.name for item in model.graph.initializer}
    return [item for item in model.graph.input if item.name not in initializers]


def _input_width(value: onnx.ValueInfoProto) -> int | None:
    tensor = value.type.tensor_type
    if tensor.elem_type not in NUMERIC_TYPES:
        raise ValueError("the model input must be a numeric tensor")
    dims = tensor.shape.dim
    if not dims:
        raise ValueError("the model input must have at least one dimension")
    if all(dim.dim_value > 0 for dim in dims):
        width = 1
        for dim in dims:
            width *= int(dim.dim_value)
        return width
    return None


def _features(path: Path | None, width: int | None) -> list[str]:
    if path is not None:
        payload = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(payload, list) or not all(isinstance(item, str) for item in payload):
            raise ValueError("features.json must be a JSON array of strings")
        names = [item.strip() for item in payload if item.strip()]
    elif width in (None, len(CANONICAL_FEATURES)):
        names = list(CANONICAL_FEATURES)
    else:
        raise ValueError(
            "model input width is not EverbloomSecurity's 12-feature contract; provide --features-json"
        )
    if width is not None and len(names) != width:
        raise ValueError(f"feature map has {len(names)} entries but model input has {width}")
    if len(names) == 0 or len(names) > 4096:
        raise ValueError("feature map must contain between 1 and 4096 entries")
    return names


def _convert_opset(model: onnx.ModelProto, target: int | None) -> tuple[onnx.ModelProto, str | None]:
    if target is None:
        return model, None
    default = next((item for item in model.opset_import if item.domain in ("", "ai.onnx")), None)
    if default is None:
        raise ValueError("model has no default ONNX opset declaration")
    current = int(default.version)
    if current == target:
        return model, None
    try:
        converted = version_converter.convert_version(model, target)
    except Exception as exc:  # version_converter exposes backend-specific errors
        warning = (
            f"opset conversion {current} -> {target} was unavailable; "
            f"kept source opset {current}: {exc}"
        )
        return model, warning
    checker.check_model(converted)
    return converted, None


def convert(
    source: Path,
    destination: Path,
    features_json: Path | None,
    target_opset: int | None,
    output_index: int,
    malicious_index: int,
    output_kind: str,
) -> dict[str, object]:
    source = _safe_file(source, "source model")
    destination = destination.expanduser().resolve()
    if destination.suffix.lower() != ".onnx":
        raise ValueError("destination must use the .onnx extension")
    if destination == source:
        raise ValueError("source and destination must be different; the source is never modified")
    destination.parent.mkdir(parents=True, exist_ok=True)
    if features_json is not None:
        features_json = features_json.expanduser().resolve(strict=True)
        if not features_json.is_file():
            raise ValueError("features.json must be a regular file")

    model = onnx.load(str(source), load_external_data=True)
    checker.check_model(model)
    inputs = _real_inputs(model)
    if len(inputs) != 1:
        raise ValueError(
            f"EverbloomSecurity supplies one feature tensor; model exposes {len(inputs)} real inputs"
        )
    width = _input_width(inputs[0])
    features = _features(features_json, width)
    if not model.graph.output:
        raise ValueError("model has no graph outputs")
    if output_index < 0 or output_index >= len(model.graph.output):
        raise ValueError(f"output index {output_index} is outside output count {len(model.graph.output)}")
    if malicious_index < 0:
        raise ValueError("malicious index must be non-negative")
    if output_kind not in {"auto", "probability", "logit"}:
        raise ValueError("output kind must be auto, probability, or logit")

    model, opset_warning = _convert_opset(model, target_opset)
    model.producer_name = "EverbloomSecurity ONNX converter"
    model.producer_version = "1.0"
    model.doc_string = "Normalized for EverbloomSecurity tract-compatible feature-vector inference."
    model.ClearField("training_info")
    checker.check_model(model)
    onnx.save_model(model, str(destination), save_as_external_data=False)

    destination.parent.joinpath("features.json").write_text(
        json.dumps(features, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    destination.parent.joinpath("model_contract.json").write_text(
        json.dumps(
            {
                "output": {
                    "output_index": output_index,
                    "malicious_index": malicious_index,
                    "kind": output_kind,
                }
            },
            ensure_ascii=False,
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    return {
        "source": str(source),
        "destination": str(destination),
        "input_name": inputs[0].name,
        "input_width": width,
        "feature_dim": len(features),

        "target_opset": target_opset,
        "effective_opset": next(
            (
                int(item.version)
                for item in model.opset_import
                if item.domain in ("", "ai.onnx")
            ),
            None,
        ),
        "warnings": [opset_warning] if opset_warning else [],
        "output_index": output_index,
        "malicious_index": malicious_index,
        "output_kind": output_kind,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--destination", type=Path, required=True)
    parser.add_argument("--features-json", type=Path)
    parser.add_argument("--target-opset", type=int, default=DEFAULT_TARGET_OPSET)
    parser.add_argument("--no-opset-conversion", action="store_true")
    parser.add_argument("--output-index", type=int, default=0)
    parser.add_argument("--malicious-index", type=int, default=1)
    parser.add_argument("--output-kind", choices=["auto", "probability", "logit"], default="auto")
    args = parser.parse_args()
    target = None if args.no_opset_conversion else args.target_opset
    result = convert(
        args.source,
        args.destination,
        args.features_json,
        target,
        args.output_index,
        args.malicious_index,
        args.output_kind,
    )
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))


if __name__ == "__main__":
    main()
