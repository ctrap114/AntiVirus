"""Defensive feature-space adversarial training helpers.

This module deliberately operates on numeric feature vectors only. It never
rewrites samples, patches PE files, or emits executable artifacts. The goal is
to make the detector less sensitive to small, semantically constrained changes
in the feature representation.
"""

from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
from typing import Sequence

import numpy as np


DEFAULT_12D_MUTABLE = (0, 5, 6, 7, 8, 9, 10)

# These columns are derived from the existing 1283-column named feature map.
# They are intentionally appended rather than replacing any existing field so
# old models remain loadable.  The Rust extractor implements the same formulas
# when this feature map is present next to a model.
DERIVED_FEATURE_NAMES = (
    "derived_entropy_filesize_product",
    "derived_entropy_stringcount_product",
    "derived_filesize_stringcount_product",
    "derived_dll_hash_density",
    "derived_api_hash_density",
    "derived_hash_density",
    "derived_entropy_hash_density",
    "derived_stringcount_hash_density",
)


@dataclass(frozen=True)
class AdversarialConfig:
    """Constraints for projected-gradient feature perturbations.

    ``epsilon_vector`` is an absolute per-feature budget. A training driver
    should derive it from the training distribution instead of using one
    scalar for mixed-unit vectors such as ``FileSize`` plus binary hash bits.
    """

    steps: int = 5
    step_size: float = 0.01
    epsilon_vector: tuple[float, ...] = ()
    lower_bound: tuple[float, ...] = ()
    upper_bound: tuple[float, ...] = ()
    mutable_indices: tuple[int, ...] = ()
    random_start: bool = True
    adversarial_weight: float = 0.5

    def validate(self, feature_dim: int) -> None:
        if feature_dim <= 0:
            raise ValueError("feature_dim must be positive")
        if self.steps < 1:
            raise ValueError("steps must be at least 1")
        if self.step_size <= 0:
            raise ValueError("step_size must be positive")
        if not 0.0 <= self.adversarial_weight <= 1.0:
            raise ValueError("adversarial_weight must be between 0 and 1")
        for name, values in (
            ("epsilon_vector", self.epsilon_vector),
            ("lower_bound", self.lower_bound),
            ("upper_bound", self.upper_bound),
        ):
            if values and len(values) != feature_dim:
                raise ValueError(f"{name} must contain {feature_dim} values")
            if values and not np.isfinite(values).all():
                raise ValueError(f"{name} contains non-finite values")
        if self.epsilon_vector and any(value < 0 for value in self.epsilon_vector):
            raise ValueError("epsilon_vector cannot contain negative values")
        if self.lower_bound and self.upper_bound:
            if any(low > high for low, high in zip(self.lower_bound, self.upper_bound)):
                raise ValueError("lower_bound cannot exceed upper_bound")
        if any(index < 0 or index >= feature_dim for index in self.mutable_indices):
            raise ValueError("mutable_indices contains an out-of-range index")


def validate_feature_matrix(features: np.ndarray, labels: np.ndarray) -> tuple[np.ndarray, np.ndarray]:
    """Validate and normalize a feature matrix without changing its units."""

    matrix = np.asarray(features, dtype=np.float32)
    target = np.asarray(labels, dtype=np.float32).reshape(-1)
    if matrix.ndim != 2:
        raise ValueError(f"features must be a 2-D matrix, got shape {matrix.shape}")
    if matrix.shape[0] != target.shape[0]:
        raise ValueError("features and labels contain different sample counts")
    if matrix.shape[0] < 2:
        raise ValueError("at least two labeled samples are required")
    if not np.isfinite(matrix).all() or not np.isfinite(target).all():
        raise ValueError("features and labels must be finite")
    if not np.isin(target, (0.0, 1.0)).all():
        raise ValueError("labels must be binary 0/1 values")
    return matrix, target


def default_mutable_indices(feature_dim: int) -> tuple[int, ...]:
    """Return conservative mutable features for EverbloomSecurity's known layouts.

    In the canonical 12-vector, structural PE facts and the large-file flag
    are kept fixed. In the current 1283-vector, only the three continuous
    header features are mutable; DLL/API hash buckets remain fixed.
    """

    if feature_dim == 12:
        return DEFAULT_12D_MUTABLE
    if feature_dim >= 3:
        return (0, 1, 2)
    return tuple(range(feature_dim))


def derive_attack_constraints(
    features: np.ndarray,
    mutable_indices: Sequence[int],
    epsilon_fraction: float = 0.02,
) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    """Derive scale-aware epsilon and empirical bounds for a feature matrix."""

    matrix = np.asarray(features, dtype=np.float32)
    if matrix.ndim != 2 or not np.isfinite(matrix).all():
        raise ValueError("features must be a finite 2-D matrix")
    if epsilon_fraction <= 0:
        raise ValueError("epsilon_fraction must be positive")
    dimension = matrix.shape[1]
    mutable = np.zeros(dimension, dtype=bool)
    mutable[list(mutable_indices)] = True

    # Use robust observed ranges. This avoids allowing a scalar epsilon to
    # move a FileSize feature by the same absolute amount as a [0, 1] ratio.
    low = np.quantile(matrix, 0.01, axis=0).astype(np.float32)
    high = np.quantile(matrix, 0.99, axis=0).astype(np.float32)
    spread = np.maximum(high - low, 1.0)
    epsilon = (spread * float(epsilon_fraction)).astype(np.float32)

    # The 12 canonical features are normalized by the Rust extractor.
    if dimension == 12:
        low = np.zeros(dimension, dtype=np.float32)
        high = np.ones(dimension, dtype=np.float32)
        epsilon = np.minimum(epsilon, 0.05).astype(np.float32)

    epsilon[~mutable] = 0.0
    return epsilon, low, high


def normalize_for_rust_runtime(
    features: np.ndarray,
    feature_map: Sequence[str] | str | Path | None,
    mode: str = "auto",
) -> np.ndarray:
    """Align legacy feature files with Rust's named-feature extractor."""

    if mode not in {"auto", "none"}:
        raise ValueError("mode must be auto or none")
    if mode == "none" or feature_map is None:
        return np.asarray(features, dtype=np.float32).copy()
    if isinstance(feature_map, (str, Path)):
        names = json.loads(Path(feature_map).read_text(encoding="utf-8"))
    else:
        names = list(feature_map)
    matrix = np.asarray(features, dtype=np.float32)
    if not isinstance(names, list) or len(names) != matrix.shape[1]:
        raise ValueError(f"feature map must contain exactly {matrix.shape[1]} names")
    normalized = matrix.copy()
    size_denominator = np.log1p(128.0 * 1024.0 * 1024.0)
    for index, name in enumerate(names):
        normalized_name = str(name).strip().lower()
        column = normalized[:, index]
        if normalized_name == "entropy" and float(np.max(np.abs(column))) > 1.0:
            normalized[:, index] = np.clip(column / 8.0, 0.0, 1.0)
        elif normalized_name == "filesize" and float(np.max(np.abs(column))) > 1.0:
            normalized[:, index] = np.clip(np.log1p(np.maximum(column, 0.0)) / size_denominator, 0.0, 1.0)
        elif normalized_name == "stringcount" and float(np.max(np.abs(column))) > 1.0:
            normalized[:, index] = np.clip(column / 64.0, 0.0, 1.0)
    return normalized


def append_derived_feature_columns(
    features: np.ndarray,
    feature_names: Sequence[str],
) -> tuple[np.ndarray, list[str]]:
    """Append bounded interaction features supported by the Rust extractor.

    The function only consumes already normalized named features.  It refuses
    ambiguous maps instead of silently creating a model whose training schema
    differs from the runtime schema.
    """

    matrix = np.asarray(features, dtype=np.float32)
    names = [str(name) for name in feature_names]
    if matrix.ndim != 2 or matrix.shape[1] != len(names):
        raise ValueError("features and feature_names have different dimensions")
    normalized_names = [name.strip().lower() for name in names]
    derived_present = [name in normalized_names for name in DERIVED_FEATURE_NAMES]
    if any(derived_present) and not all(derived_present):
        raise ValueError("feature map contains only part of the derived feature set")
    if all(derived_present):
        return matrix.copy(), names

    def find_exact(name: str) -> int:
        try:
            return normalized_names.index(name)
        except ValueError as exc:
            raise ValueError(f"feature map is missing required field: {name}") from exc

    entropy = matrix[:, find_exact("entropy")]
    file_size = matrix[:, find_exact("filesize")]
    string_count = matrix[:, find_exact("stringcount")]
    dll_indices = [index for index, name in enumerate(normalized_names) if name.startswith("dllhash_")]
    api_indices = [index for index, name in enumerate(normalized_names) if name.startswith("apihash_")]
    if not dll_indices or not api_indices:
        raise ValueError("derived named features require DLL/API hash buckets")

    dll_density = matrix[:, dll_indices].mean(axis=1)
    api_density = matrix[:, api_indices].mean(axis=1)
    hash_density = matrix[:, dll_indices + api_indices].mean(axis=1)
    derived = np.column_stack(
        (
            entropy * file_size,
            entropy * string_count,
            file_size * string_count,
            dll_density,
            api_density,
            hash_density,
            entropy * hash_density,
            string_count * hash_density,
        )
    ).astype(np.float32)
    return np.concatenate((matrix, derived), axis=1), names + list(DERIVED_FEATURE_NAMES)


def augment_training_features(
    features: np.ndarray,
    labels: np.ndarray,
    epsilon_vector: Sequence[float],
    lower_bound: Sequence[float],
    upper_bound: Sequence[float],
    mutable_indices: Sequence[int],
    copies_per_sample: int = 8,
    balance_classes: bool = True,
    seed: int = 42,
) -> tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray]:
    """Create bounded, labeled feature-space variants for the training split.

    This is deliberately not a file generator.  Every synthetic row keeps its
    source label, only declared mutable fields receive noise, and validation
    data should never be passed to this function.  The returned arrays are
    ``features, labels, source_index, synthetic``.
    """

    matrix, target = validate_feature_matrix(features, labels)
    copies = int(copies_per_sample)
    if copies < 0:
        raise ValueError("copies_per_sample must be non-negative")
    dimension = matrix.shape[1]
    epsilon = np.asarray(epsilon_vector, dtype=np.float32)
    lower = np.asarray(lower_bound, dtype=np.float32)
    upper = np.asarray(upper_bound, dtype=np.float32)
    if any(values.shape != (dimension,) for values in (epsilon, lower, upper)):
        raise ValueError("augmentation constraints must match feature dimensions")
    if not np.isfinite(epsilon).all() or not np.isfinite(lower).all() or not np.isfinite(upper).all():
        raise ValueError("augmentation constraints must be finite")
    if np.any(epsilon < 0) or np.any(lower > upper):
        raise ValueError("invalid augmentation constraints")
    mutable = np.zeros(dimension, dtype=bool)
    mutable[list(mutable_indices)] = True
    rng = np.random.default_rng(seed)

    rows = [row.copy() for row in matrix]
    row_labels = [float(label) for label in target]
    sources = list(range(matrix.shape[0]))
    synthetic = [False] * matrix.shape[0]

    def make_variant(source_index: int) -> np.ndarray:
        source = matrix[source_index]
        noise = rng.uniform(-epsilon, epsilon).astype(np.float32)
        noise[~mutable] = 0.0
        variant = np.clip(source + noise, lower, upper).astype(np.float32)
        variant[~mutable] = source[~mutable]
        return variant

    for source_index in range(matrix.shape[0]):
        for _ in range(copies):
            rows.append(make_variant(source_index))
            row_labels.append(float(target[source_index]))
            sources.append(source_index)
            synthetic.append(True)

    if balance_classes:
        class_indices = {
            label: [index for index, value in enumerate(row_labels) if value == label]
            for label in (0.0, 1.0)
        }
        target_count = max((len(indices) for indices in class_indices.values()), default=0)
        original_by_class = {
            label: np.flatnonzero(target == label).tolist() for label in (0.0, 1.0)
        }
        for label, indices in class_indices.items():
            candidates = original_by_class[label]
            if not candidates:
                continue
            while len(indices) < target_count:
                source_index = int(rng.choice(candidates))
                rows.append(make_variant(source_index))
                row_labels.append(label)
                sources.append(source_index)
                synthetic.append(True)
                indices.append(len(rows) - 1)

    return (
        np.asarray(rows, dtype=np.float32),
        np.asarray(row_labels, dtype=np.float32),
        np.asarray(sources, dtype=np.int64),
        np.asarray(synthetic, dtype=bool),
    )


def projected_gradient_attack(
    model,
    features,
    labels,
    config: AdversarialConfig,
):
    """Create constrained PGD examples in feature space.

    The attack maximizes the classifier's binary cross-entropy, making it a
    useful training-time stressor. Immutable features are copied from the
    original matrix on every iteration, so the output stays within the
    declared feature semantics.
    """

    import torch
    import torch.nn.functional as functional

    if features.ndim != 2:
        raise ValueError("features tensor must have shape [batch, feature_dim]")
    feature_dim = int(features.shape[1])
    config.validate(feature_dim)
    if labels.reshape(-1).shape[0] != features.shape[0]:
        raise ValueError("features and labels contain different batch sizes")

    device = features.device
    dtype = features.dtype
    epsilon = torch.as_tensor(
        config.epsilon_vector or [0.0] * feature_dim,
        device=device,
        dtype=dtype,
    ).reshape(1, feature_dim)
    lower = torch.as_tensor(
        config.lower_bound or [-float("inf")] * feature_dim,
        device=device,
        dtype=dtype,
    ).reshape(1, feature_dim)
    upper = torch.as_tensor(
        config.upper_bound or [float("inf")] * feature_dim,
        device=device,
        dtype=dtype,
    ).reshape(1, feature_dim)
    mutable = torch.zeros(feature_dim, device=device, dtype=dtype)
    if config.mutable_indices:
        mutable[list(config.mutable_indices)] = 1.0
    else:
        mutable[:] = (epsilon.reshape(-1) > 0).to(dtype)
    mutable = mutable.reshape(1, feature_dim)

    was_training = model.training
    model.eval()
    try:
        if config.random_start:
            delta = torch.empty_like(features).uniform_(-1.0, 1.0) * epsilon
            delta = delta * mutable
            adversarial = torch.maximum(torch.minimum(features + delta, upper), lower)
        else:
            adversarial = features.detach().clone()

        target = labels.reshape(-1).to(dtype=dtype)
        for _ in range(config.steps):
            adversarial = adversarial.detach().requires_grad_(True)
            logits = model(adversarial).reshape(-1)
            loss = functional.binary_cross_entropy_with_logits(logits, target)
            gradient = torch.autograd.grad(loss, adversarial, only_inputs=True)[0]
            candidate = adversarial.detach() + config.step_size * gradient.sign() * mutable
            delta = (candidate - features).clamp(min=-epsilon, max=epsilon)
            adversarial = torch.maximum(torch.minimum(features + delta, upper), lower)
            adversarial = adversarial * mutable + features * (1.0 - mutable)
        return adversarial.detach()
    finally:
        model.train(was_training)


def binary_metrics(scores: np.ndarray, labels: np.ndarray, threshold: float = 0.5) -> dict[str, float]:
    """Calculate stable binary metrics for clean and adversarial reports."""

    probability = np.asarray(scores, dtype=np.float32).reshape(-1)
    target = np.asarray(labels, dtype=np.int32).reshape(-1)
    predicted = (probability >= threshold).astype(np.int32)
    tp = int(((predicted == 1) & (target == 1)).sum())
    tn = int(((predicted == 0) & (target == 0)).sum())
    fp = int(((predicted == 1) & (target == 0)).sum())
    fn = int(((predicted == 0) & (target == 1)).sum())
    total = max(1, len(target))
    return {
        "accuracy": (tp + tn) / total,
        "precision": tp / max(1, tp + fp),
        "recall": tp / max(1, tp + fn),
        "false_positive_rate": fp / max(1, fp + tn),
        "false_negative_rate": fn / max(1, fn + tp),
        "threshold": float(threshold),
    }
