#!/usr/bin/env python3
"""Convert ML.NET ONNX-ML tree models into EverbloomSecurity/tract-compatible models.

Some ML.NET tree models are exported as ONNX-ML ``TreeEnsembleRegressor``
graphs with an extra training label input and a Sigmoid calibration tail.
tract-onnx 0.23.x supports
``TreeEnsembleClassifier`` but not ``TreeEnsembleRegressor``.  This script
rewrites the graph into an equivalent classifier shape that EverbloomSecurity can load
through the current tract backend.

The source model is never modified.  The output directory receives:

    everbloom_dense_tree.onnx
                           converted static-batch classifier graph
    features.json          273/283-element feature ordering for EverbloomSecurity
    model_contract.json    decode output #1 as the malicious probability
"""

from __future__ import annotations

import argparse
import copy
import json
from pathlib import Path

import onnx
from onnx import TensorProto, checker, helper, numpy_helper


NODE_ATTRIBUTES = [
    "nodes_treeids",
    "nodes_nodeids",
    "nodes_featureids",
    "nodes_modes",
    "nodes_values",
    "nodes_truenodeids",
    "nodes_falsenodeids",
    "nodes_missing_value_tracks_true",
]


def _tensor_shape_width(model: onnx.ModelProto) -> int:
    for value in model.graph.input:
        if value.name != "Features":
            continue
        dims = value.type.tensor_type.shape.dim
        if len(dims) != 2 or not dims[1].dim_value:
            raise ValueError("Features input must be a 2-D tensor with a fixed feature width")
        return int(dims[1].dim_value)
    raise ValueError("tree model does not contain a Features input")


def _scalar_initializer(model: onnx.ModelProto, name: str, default: float) -> float:
    for initializer in model.graph.initializer:
        if initializer.name == name:
            array = numpy_helper.to_array(initializer)
            return float(array.reshape(-1)[0])
    return default


def _find_tree_regressor(model: onnx.ModelProto) -> onnx.NodeProto:
    matches = [
        node
        for node in model.graph.node
        if node.domain == "ai.onnx.ml" and node.op_type == "TreeEnsembleRegressor"
    ]
    if len(matches) != 1:
        raise ValueError(f"expected exactly one TreeEnsembleRegressor node, found {len(matches)}")
    return matches[0]


def _attribute_map(node: onnx.NodeProto) -> dict[str, onnx.AttributeProto]:
    attrs = {attribute.name: copy.deepcopy(attribute) for attribute in node.attribute}
    missing = [name for name in NODE_ATTRIBUTES if name not in attrs]
    missing.extend(
        name
        for name in ["target_treeids", "target_nodeids", "target_ids", "target_weights"]
        if name not in attrs
    )
    if missing:
        raise ValueError(f"TreeEnsembleRegressor is missing required attributes: {missing}")
    return attrs


def _classifier_attributes(
    attrs: dict[str, onnx.AttributeProto],
    slope: float,
    offset: float,
) -> list[onnx.AttributeProto]:
    converted: list[onnx.AttributeProto] = [copy.deepcopy(attrs[name]) for name in NODE_ATTRIBUTES]

    # Use a full two-column classifier layout so tract does not enter its
    # class-0-only binary-result compatibility path.  Class 0 is a neutral
    # baseline; class 1 carries the original calibrated regressor score.
    class_treeids: list[int] = []
    class_nodeids: list[int] = []
    class_ids: list[int] = []
    class_weights: list[float] = []
    for tree_id, node_id, weight in zip(
        attrs["target_treeids"].ints,
        attrs["target_nodeids"].ints,
        attrs["target_weights"].floats,
    ):
        tree_id = int(tree_id)
        node_id = int(node_id)
        class_treeids.extend([tree_id, tree_id])
        class_nodeids.extend([node_id, node_id])
        class_ids.extend([0, 1])
        class_weights.extend([0.0, float(weight) * slope])

    converted.extend(
        [
            helper.make_attribute("class_treeids", class_treeids),
            helper.make_attribute("class_nodeids", class_nodeids),
            helper.make_attribute("class_ids", class_ids),
            helper.make_attribute("class_weights", class_weights),
            helper.make_attribute("classlabels_int64s", [0, 1]),
            helper.make_attribute("base_values", [0.0, offset]),
            helper.make_attribute("post_transform", "LOGISTIC"),
        ]
    )
    return converted


def dense_tree_feature_map(feature_dim: int) -> list[str]:
    """Return the EverbloomSecurity feature names used for dense tree models."""

    names = [f"bytehist_{index}" for index in range(256)]
    dense_tail = [
        "entropy_raw",
        "max_section_entropy",
        "mean_section_entropy",
        "section_entropy_raw",
        "tail_entropy",
        "head_entropy",
        "pe_overlay_entropy",
        "printable_ratio",
        "null_ratio",
        "distinct_byte_ratio",
        "mean_byte",
        "coverage",
        "file_size_log10",
        "tls_present",
        "section_count",
        "import_count",
        "entropy_norm",
    ]
    names.extend(dense_tail)
    if len(names) < feature_dim:
        names.extend(f"dense_tree_reserved_{index}" for index in range(len(names), feature_dim))
    if len(names) > feature_dim:
        names = names[:feature_dim]
    return names


def convert(source: Path, destination: Path) -> None:
    model = onnx.load(str(source))
    feature_dim = _tensor_shape_width(model)
    tree = _find_tree_regressor(model)
    attrs = _attribute_map(tree)
    slope = _scalar_initializer(model, "Slope", 1.0)
    offset = _scalar_initializer(model, "Offset", 0.0)

    classifier = helper.make_node(
        "TreeEnsembleClassifier",
        inputs=["Features"],
        outputs=["PredictedLabel.output", "Probability.output"],
        name="EverbloomDenseTreeClassifier",
        domain="ai.onnx.ml",
    )
    classifier.attribute.extend(_classifier_attributes(attrs, slope, offset))

    graph = helper.make_graph(
        [classifier],
        "EverbloomSecurity_dense_tree_tract_compatible",
        [
            helper.make_tensor_value_info(
                "Features",
                TensorProto.FLOAT,
                [1, feature_dim],
            )
        ],
        [
            helper.make_tensor_value_info("PredictedLabel.output", TensorProto.INT64, [1]),
            helper.make_tensor_value_info("Probability.output", TensorProto.FLOAT, [1, 2]),
        ],
    )
    converted = helper.make_model(
        graph,
        opset_imports=[
            helper.make_operatorsetid("", 12),
            helper.make_operatorsetid("ai.onnx.ml", 2),
        ],
        producer_name="EverbloomSecurity dense tree converter",
        producer_version="1.0",
    )
    converted.ir_version = model.ir_version
    checker.check_model(converted)

    destination.parent.mkdir(parents=True, exist_ok=True)
    onnx.save(converted, str(destination))
    (destination.parent / "features.json").write_text(
        json.dumps(dense_tree_feature_map(feature_dim), ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    (destination.parent / "model_contract.json").write_text(
        json.dumps(
            {"output": {"output_index": 1, "malicious_index": 1, "kind": "probability"}},
            indent=2,
        ),
        encoding="utf-8",
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path, help="Source ONNX-ML tree model file to read")
    parser.add_argument(
        "--out",
        type=Path,
        default=Path("artifacts/models/tree_ensemble/everbloom_dense_tree.onnx"),
        help="Converted model path to write",
    )
    args = parser.parse_args()

    convert(args.source, args.out)
    print(f"wrote {args.out}")
    print(f"wrote {args.out.parent / 'features.json'}")
    print(f"wrote {args.out.parent / 'model_contract.json'}")


if __name__ == "__main__":
    main()
