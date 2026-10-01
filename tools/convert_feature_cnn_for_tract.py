"""Convert the bundled feature-CNN ONNX model for tract-onnx.

The original export uses a constant-index `GatherND` pattern for
`adaptive_avg_pool1d(output_size=8)`.  tract-onnx 0.23 cannot optimize that
graph, while the same computation is representable as:

    AveragePool(kernel_shape=[81], strides=[80])

for the model's fixed post-convolution length of 641.  This script rewrites
that subgraph, embeds external weights into the ONNX file, and writes the
sidecars used by EverbloomSecurity's scanner:

    features.json          1283-element feature ordering
    model_contract.json    decode output #1 as malicious probability

Usage:
    python tools/convert_feature_cnn_for_tract.py everbloom_feature_cnn.onnx everbloom_feature_cnn.onnx
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import onnx
from onnx import helper


REMOVED_POOL_NODES = {
    "node_unsqueeze",
    "node_Transpose_33",
    "node_GatherND_41",
    "node_index",
    "node_mean",
    "node_squeeze",
}


def rewrite_model(source: Path, destination: Path) -> None:
    model = onnx.load(source, load_external_data=True)

    rewritten_nodes = []
    inserted_pool = False
    for node in model.graph.node:
        if node.name in REMOVED_POOL_NODES:
            if not inserted_pool:
                rewritten_nodes.append(
                    helper.make_node(
                        "AveragePool",
                        inputs=["relu_1"],
                        outputs=["squeeze"],
                        name="node_adaptive_avg_pool1d_tract",
                        kernel_shape=[81],
                        strides=[80],
                        pads=[0, 0],
                    )
                )
                inserted_pool = True
            continue
        rewritten_nodes.append(node)

    if not inserted_pool:
        raise RuntimeError("expected GatherND adaptive-pool subgraph was not found")

    model.graph.ClearField("node")
    model.graph.node.extend(rewritten_nodes)

    unused_initializers = {"val_1", "val_41", "val_45"}
    kept_initializers = [
        initializer
        for initializer in model.graph.initializer
        if initializer.name not in unused_initializers
    ]
    model.graph.ClearField("initializer")
    model.graph.initializer.extend(kept_initializers)

    removed_value_info = {"unsqueeze", "val_34", "val_42", "index", "mean"}
    kept_value_info = [
        value_info
        for value_info in model.graph.value_info
        if value_info.name not in removed_value_info
    ]
    model.graph.ClearField("value_info")
    model.graph.value_info.extend(kept_value_info)

    model.producer_name = "EverbloomSecurity feature CNN tract converter"
    model.producer_version = "2026.08.09"
    onnx.checker.check_model(model)
    onnx.save_model(model, destination, save_as_external_data=False)


def write_sidecars(model_path: Path) -> None:
    parent = model_path.parent
    features = ["filesize", "stringcount", "entropy"]
    features.extend(f"dllhash_{index}" for index in range(256))
    features.extend(f"apihash_{index}" for index in range(1024))
    if len(features) != 1283:
        raise AssertionError(f"unexpected feature count: {len(features)}")

    (parent / "features.json").write_text(
        json.dumps(features, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    (parent / "model_contract.json").write_text(
        json.dumps(
            {
                "output": {
                    "output_index": 1,
                    "malicious_index": 1,
                    "kind": "probability",
                }
            },
            ensure_ascii=False,
            indent=2,
        ),
        encoding="utf-8",
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("source", type=Path)
    parser.add_argument("destination", type=Path)
    args = parser.parse_args()

    rewrite_model(args.source, args.destination)
    write_sidecars(args.destination)
    print(f"converted {args.source} -> {args.destination}")
    print(f"wrote {args.destination.parent / 'features.json'}")
    print(f"wrote {args.destination.parent / 'model_contract.json'}")


if __name__ == "__main__":
    main()
