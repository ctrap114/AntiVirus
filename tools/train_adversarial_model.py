#!/usr/bin/env python3
"""Train a robust EverbloomSecurity ONNX classifier with constrained PGD examples.

This is a defensive feature-space trainer. It consumes numeric feature vectors
and labels, never edits input files, and never emits executable samples.

The loader accepts ordinary NumPy arrays, JSONL records, and EverbloomSecurity's raw
``dense_test_features.npy``/``dense_test_labels.npy`` fixtures. The exported
model uses a single input tensor and writes a Rust-compatible
``model_contract.json`` sidecar.
"""

from __future__ import annotations

import argparse
import json
import random
import shutil
from pathlib import Path
from typing import Any

import numpy as np

from everbloom_core.adversarial import (
    AdversarialConfig,
    append_derived_feature_columns,
    augment_training_features,
    binary_metrics,
    default_mutable_indices,
    derive_attack_constraints,
    normalize_for_rust_runtime,
    projected_gradient_attack,
    validate_feature_matrix,
)


ROOT = Path(__file__).resolve().parents[1]


def _read_array(path: Path, dtype: np.dtype[Any]) -> np.ndarray:
    """Read a regular .npy file, or a raw array with a legacy .npy suffix."""

    try:
        return np.asarray(np.load(path, allow_pickle=False))
    except (ValueError, OSError, EOFError):
        return np.fromfile(path, dtype=dtype)


def load_dataset(features_path: Path, labels_path: Path | None, feature_dim: int | None) -> tuple[np.ndarray, np.ndarray]:
    if features_path.suffix.lower() in {".jsonl", ".json"}:
        rows = [
            json.loads(line)
            for line in features_path.read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        ]
        features = np.asarray([row["features"] for row in rows], dtype=np.float32)
        labels = np.asarray(
            [row["label"] for row in rows] if labels_path is None else _read_array(labels_path, np.float32),
            dtype=np.float32,
        )
    else:
        if labels_path is None:
            raise ValueError("--labels is required for NumPy/raw feature matrices")
        features = _read_array(features_path, np.float32)
        labels = _read_array(labels_path, np.uint8).astype(np.float32)

    if features.ndim == 1:
        if not feature_dim:
            raise ValueError("--feature-dim is required for a flat feature file")
        if features.size % feature_dim != 0:
            raise ValueError("feature file size is not divisible by --feature-dim")
        features = features.reshape(-1, feature_dim)
    return validate_feature_matrix(features, labels)


def split_indices(labels: np.ndarray, validation_fraction: float, seed: int) -> tuple[np.ndarray, np.ndarray]:
    if not 0.0 <= validation_fraction < 1.0:
        raise ValueError("validation fraction must be in [0, 1)")
    rng = np.random.default_rng(seed)
    train: list[int] = []
    validation: list[int] = []
    for label in (0.0, 1.0):
        candidates = np.flatnonzero(labels == label)
        rng.shuffle(candidates)
        count = int(round(len(candidates) * validation_fraction))
        if len(candidates) > 1 and validation_fraction > 0:
            count = max(1, min(len(candidates) - 1, count))
        validation.extend(candidates[:count].tolist())
        train.extend(candidates[count:].tolist())
    if not train:
        raise ValueError("validation split consumed all samples")
    return np.asarray(train, dtype=np.int64), np.asarray(validation, dtype=np.int64)


def build_robust_mlp(input_dim: int, hidden_dim: int):
    """Build a shape-flexible classifier exported as [batch, 1, feature_dim]."""

    import torch.nn as nn

    class _Model(nn.Module):
        def __init__(self) -> None:
            super().__init__()
            bottleneck = max(16, hidden_dim // 2)
            self.network = nn.Sequential(
                nn.Linear(input_dim, hidden_dim),
                nn.ReLU(),
                nn.Linear(hidden_dim, bottleneck),
                nn.ReLU(),
                nn.Linear(bottleneck, 1),
            )

        def forward(self, features):
            return self.network(features.reshape(features.shape[0], -1)).squeeze(-1)

    return _Model()


def _tensor_metrics(model, features: np.ndarray, labels: np.ndarray) -> dict[str, float]:
    import torch

    model.eval()
    with torch.no_grad():
        logits = model(torch.from_numpy(features)).detach().cpu().numpy()
    scores = 1.0 / (1.0 + np.exp(-np.clip(logits, -60.0, 60.0)))
    return binary_metrics(scores, labels)


def train_model(
    model,
    train_features: np.ndarray,
    train_labels: np.ndarray,
    config: AdversarialConfig,
    epochs: int,
    batch_size: int,
    learning_rate: float,
    seed: int,
) -> None:
    import torch
    import torch.nn.functional as functional

    torch.manual_seed(seed)
    optimizer = torch.optim.AdamW(model.parameters(), lr=learning_rate, weight_decay=1e-4)
    features = torch.from_numpy(train_features)
    labels = torch.from_numpy(train_labels)
    positive = max(1.0, float((train_labels == 1).sum()))
    negative = max(1.0, float((train_labels == 0).sum()))
    pos_weight = torch.tensor([negative / positive], dtype=torch.float32)

    for epoch in range(1, epochs + 1):
        model.train()
        order = torch.randperm(features.shape[0])
        total_loss = 0.0
        batches = 0
        for start in range(0, features.shape[0], batch_size):
            indexes = order[start : start + batch_size]
            clean = features[indexes]
            target = labels[indexes]
            adversarial = projected_gradient_attack(model, clean, target, config)
            clean_logits = model(clean).reshape(-1)
            adversarial_logits = model(adversarial).reshape(-1)
            loss_clean = functional.binary_cross_entropy_with_logits(
                clean_logits, target, pos_weight=pos_weight
            )
            loss_adversarial = functional.binary_cross_entropy_with_logits(
                adversarial_logits, target, pos_weight=pos_weight
            )
            loss = (1.0 - config.adversarial_weight) * loss_clean + config.adversarial_weight * loss_adversarial
            optimizer.zero_grad(set_to_none=True)
            loss.backward()
            torch.nn.utils.clip_grad_norm_(model.parameters(), max_norm=5.0)
            optimizer.step()
            total_loss += float(loss.detach())
            batches += 1
        print(f"epoch={epoch}/{epochs} robust_loss={total_loss / max(1, batches):.5f}")


def export_model(
    model,
    output: Path,
    feature_dim: int,
    feature_map: Path | None,
    feature_map_names: list[str] | None,
    config: AdversarialConfig,
) -> None:
    import torch

    output.parent.mkdir(parents=True, exist_ok=True)
    model.eval()
    dummy = torch.zeros(1, 1, feature_dim, dtype=torch.float32)
    torch.onnx.export(
        model,
        dummy,
        str(output),
        opset_version=17,
        input_names=["input"],
        output_names=["logit"],
        dynamic_axes={"input": {0: "batch"}, "logit": {0: "batch"}},
        # Keep compatibility with PyTorch builds where the new dynamo exporter
        # adds an unnecessary onnxscript dependency.
        dynamo=False,
        do_constant_folding=True,
    )
    contract = {
        "output_kind": "logit",
        "input_layout": ["batch", 1, feature_dim],
        "feature_dim": feature_dim,
        "adversarial_training": {
            "steps": config.steps,
            "step_size": config.step_size,
            "adversarial_weight": config.adversarial_weight,
            "mutable_indices": list(config.mutable_indices),
        },
    }
    output.with_name("model_contract.json").write_text(
        json.dumps(contract, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    if feature_map_names is not None:
        names = feature_map_names
        if not isinstance(names, list) or len(names) != feature_dim:
            raise ValueError(f"feature map must contain exactly {feature_dim} names")
        output.with_name("features.json").write_text(
            json.dumps(names, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
        )
    elif feature_map is not None:
        names = json.loads(feature_map.read_text(encoding="utf-8"))
        if not isinstance(names, list) or len(names) != feature_dim:
            raise ValueError(f"feature map must contain exactly {feature_dim} names: {feature_map}")
        target_map = output.with_name("features.json")
        if feature_map.resolve() != target_map.resolve():
            shutil.copy2(feature_map, target_map)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--features", type=Path, default=ROOT / "dense_test_features.npy")
    parser.add_argument("--labels", type=Path, default=None)
    parser.add_argument("--feature-dim", type=int, default=1283)
    parser.add_argument("--feature-map", type=Path, default=None)
    parser.add_argument("--normalization", choices=["auto", "none"], default="auto")
    parser.add_argument(
        "--add-derived-features",
        action="store_true",
        help="Append eight Rust-compatible interaction/density features to a named 1283-feature map.",
    )
    parser.add_argument("--out", type=Path, default=ROOT / "artifacts" / "models" / "everbloom_adversarial.onnx")
    parser.add_argument("--report", type=Path, default=ROOT / "artifacts" / "quality-baseline" / "adversarial_training.json")
    parser.add_argument("--epochs", type=int, default=20)
    parser.add_argument("--batch-size", type=int, default=32)
    parser.add_argument("--hidden-dim", type=int, default=128)
    parser.add_argument("--learning-rate", type=float, default=1e-3)
    parser.add_argument("--epsilon-fraction", type=float, default=0.02)
    parser.add_argument("--steps", type=int, default=5)
    parser.add_argument("--step-size", type=float, default=0.01)
    parser.add_argument("--adversarial-weight", type=float, default=0.5)
    parser.add_argument(
        "--augment-per-sample",
        type=int,
        default=8,
        help="Number of bounded synthetic feature variants generated from each training sample.",
    )
    parser.add_argument(
        "--no-balance-classes",
        action="store_true",
        help="Do not add bounded minority-class variants to balance the training split.",
    )
    parser.add_argument(
        "--export-augmented",
        type=Path,
        default=None,
        help="Optionally save the expanded training matrix as a compressed .npz file.",
    )
    parser.add_argument("--validation-fraction", type=float, default=0.2)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--dry-run", action="store_true", help="Validate the dataset and constraints without importing torch or training.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    random.seed(args.seed)
    labels_path = args.labels
    if labels_path is None and args.features.suffix.lower() not in {".jsonl", ".json"}:
        labels_path = ROOT / "dense_test_labels.npy"
    features, labels = load_dataset(args.features, labels_path, args.feature_dim)
    feature_map = args.feature_map
    if feature_map is None and features.shape[1] > 12:
        candidate = ROOT / "features.json"
        feature_map = candidate if candidate.exists() else None
    features = normalize_for_rust_runtime(features, feature_map, args.normalization)
    feature_map_names: list[str] | None = None
    if feature_map is not None:
        loaded_names = json.loads(feature_map.read_text(encoding="utf-8"))
        if not isinstance(loaded_names, list) or len(loaded_names) != features.shape[1]:
            raise ValueError(f"feature map must contain exactly {features.shape[1]} names: {feature_map}")
        if args.add_derived_features:
            features, feature_map_names = append_derived_feature_columns(features, loaded_names)
    elif args.add_derived_features:
        raise ValueError("--add-derived-features requires --feature-map or the repository features.json")

    raw_feature_dim = int(features.shape[1] - (8 if feature_map_names is not None else 0))
    train_indexes, validation_indexes = split_indices(labels, args.validation_fraction, args.seed)
    mutable = default_mutable_indices(features.shape[1])
    epsilon, lower, upper = derive_attack_constraints(
        features[train_indexes], mutable, args.epsilon_fraction
    )
    config = AdversarialConfig(
        steps=args.steps,
        step_size=args.step_size,
        epsilon_vector=tuple(float(value) for value in epsilon),
        lower_bound=tuple(float(value) for value in lower),
        upper_bound=tuple(float(value) for value in upper),
        mutable_indices=tuple(mutable),
        adversarial_weight=args.adversarial_weight,
    )
    config.validate(features.shape[1])
    expanded_features, expanded_labels, source_indexes, synthetic = augment_training_features(
        features[train_indexes],
        labels[train_indexes],
        epsilon,
        lower,
        upper,
        mutable,
        copies_per_sample=args.augment_per_sample,
        balance_classes=not args.no_balance_classes,
        seed=args.seed,
    )

    def class_counts(values: np.ndarray) -> dict[str, int]:
        return {"0": int((values == 0).sum()), "1": int((values == 1).sum())}

    if args.export_augmented is not None:
        args.export_augmented.parent.mkdir(parents=True, exist_ok=True)
        np.savez_compressed(
            args.export_augmented,
            features=expanded_features,
            labels=expanded_labels,
            source_index=source_indexes,
            synthetic=synthetic,
        )
        args.export_augmented.with_suffix(".json").write_text(
            json.dumps(
                {
                    "schema": 1,
                    "feature_dim": int(expanded_features.shape[1]),
                    "samples": int(expanded_features.shape[0]),
                    "original_train_samples": int(len(train_indexes)),
                    "synthetic_samples": int(synthetic.sum()),
                    "class_counts": class_counts(expanded_labels),
                    "validation_excluded": True,
                    "derived_features": list(feature_map_names[-8:]) if feature_map_names else [],
                },
                ensure_ascii=False,
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )

    report: dict[str, Any] = {
        "schema": 2,
        "feature_dim": int(features.shape[1]),
        "raw_feature_dim": raw_feature_dim,
        "samples": int(features.shape[0]),
        "train_samples": int(len(train_indexes)),
        "augmented_train_samples": int(len(expanded_features)),
        "synthetic_train_samples": int(synthetic.sum()),
        "validation_samples": int(len(validation_indexes)),
        "training_class_counts_before": class_counts(labels[train_indexes]),
        "training_class_counts_after": class_counts(expanded_labels),
        "validation_is_original_only": True,
        "augmentation": {
            "copies_per_sample": args.augment_per_sample,
            "balanced_classes": not args.no_balance_classes,
            "seed": args.seed,
        },
        "derived_features": list(feature_map_names[-8:]) if feature_map_names else [],
        "mutable_indices": list(mutable),
        "epsilon_fraction": args.epsilon_fraction,
        "epsilon_nonzero_max": float(epsilon.max(initial=0.0)),
        "normalization": args.normalization if feature_map is not None else "none",
        "dry_run": bool(args.dry_run),
    }
    print(json.dumps(report, ensure_ascii=False, indent=2))
    if args.dry_run:
        return 0

    try:
        import torch
    except ImportError as exc:
        raise SystemExit("Training requires the optional ML dependencies: pip install -e \".[ml]\"") from exc

    model = build_robust_mlp(features.shape[1], args.hidden_dim)
    train_model(
        model,
        expanded_features,
        expanded_labels,
        config,
        epochs=args.epochs,
        batch_size=args.batch_size,
        learning_rate=args.learning_rate,
        seed=args.seed,
    )
    clean_metrics = _tensor_metrics(model, features[validation_indexes], labels[validation_indexes]) if len(validation_indexes) else {}
    adversarial_features = projected_gradient_attack(
        model,
        torch.from_numpy(features[validation_indexes]),
        torch.from_numpy(labels[validation_indexes]),
        config,
    ) if len(validation_indexes) else None
    adversarial_metrics = {}
    if adversarial_features is not None:
        adversarial_metrics = _tensor_metrics(model, adversarial_features.cpu().numpy(), labels[validation_indexes])
    export_model(model, args.out, features.shape[1], feature_map, feature_map_names, config)
    report.update({"clean_metrics": clean_metrics, "adversarial_metrics": adversarial_metrics, "output": str(args.out)})
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
