"""Pure-NumPy safety checks for adversarial training constraints."""

import numpy as np
import pytest

from everbloom_core.adversarial import (
    AdversarialConfig,
    DERIVED_FEATURE_NAMES,
    append_derived_feature_columns,
    augment_training_features,
    default_mutable_indices,
    derive_attack_constraints,
    projected_gradient_attack,
    validate_feature_matrix,
)


def test_default_mutable_indices_keep_discrete_features_fixed() -> None:
    assert default_mutable_indices(12) == (0, 5, 6, 7, 8, 9, 10)
    assert default_mutable_indices(1283) == (0, 1, 2)


def test_constraints_are_finite_and_zero_for_immutable_features() -> None:
    features = np.asarray(
        [
            [4.1, 10240.0, 12.0] + [0.0] * 1280,
            [6.9, 512000.0, 4.0] + [1.0] * 1280,
            [3.7, 20480.0, 20.0] + [0.0] * 1280,
        ],
        dtype=np.float32,
    )
    epsilon, lower, upper = derive_attack_constraints(features, (0, 1, 2), 0.02)
    assert np.isfinite(epsilon).all()
    assert np.isfinite(lower).all()
    assert np.isfinite(upper).all()
    assert np.all(epsilon[3:] == 0.0)
    assert np.all(lower <= upper)


def test_invalid_labels_are_rejected() -> None:
    with pytest.raises(ValueError, match="binary"):
        validate_feature_matrix(np.zeros((2, 3), dtype=np.float32), np.asarray([0, 2]))


def test_config_rejects_out_of_range_mutable_index() -> None:
    with pytest.raises(ValueError, match="out-of-range"):
        AdversarialConfig(mutable_indices=(3,)).validate(3)


def test_pgd_respects_immutable_features_and_budget() -> None:
    torch = pytest.importorskip("torch")
    model = torch.nn.Linear(3, 1)
    features = torch.tensor([[0.2, 0.4, 0.6], [0.8, 0.3, 0.1]], dtype=torch.float32)
    labels = torch.tensor([0.0, 1.0], dtype=torch.float32)
    config = AdversarialConfig(
        steps=2,
        step_size=0.01,
        epsilon_vector=(0.05, 0.0, 0.02),
        lower_bound=(0.0, 0.0, 0.0),
        upper_bound=(1.0, 1.0, 1.0),
        mutable_indices=(0, 2),
        random_start=False,
    )
    adversarial = projected_gradient_attack(model, features, labels, config)
    assert torch.equal(adversarial[:, 1], features[:, 1])
    assert torch.all((adversarial - features).abs() <= torch.tensor([0.05, 0.0, 0.02]))
    assert torch.all(adversarial >= 0.0)
    assert torch.all(adversarial <= 1.0)


def test_derived_features_are_bounded_and_named() -> None:
    names = ["Entropy", "FileSize", "StringCount"]
    names += [f"DllHash_{index:03d}" for index in range(2)]
    names += [f"ApiHash_{index:04d}" for index in range(2)]
    features = np.asarray(
        [
            [0.5, 0.25, 0.75, 1.0, 0.0, 1.0, 0.0],
            [0.2, 0.5, 0.25, 0.0, 1.0, 0.0, 1.0],
        ],
        dtype=np.float32,
    )
    expanded, expanded_names = append_derived_feature_columns(features, names)
    assert expanded.shape == (2, 15)
    assert expanded_names[-8:] == list(DERIVED_FEATURE_NAMES)
    assert np.isfinite(expanded).all()
    assert np.all((expanded[:, -8:] >= 0.0) & (expanded[:, -8:] <= 1.0))
    assert np.allclose(expanded[:, -8], features[:, 0] * features[:, 1])


def test_augmentation_keeps_immutable_columns_and_balances_classes() -> None:
    features = np.asarray(
        [[0.2, 0.4, 0.6, 1.0], [0.8, 0.3, 0.1, 0.0], [0.5, 0.2, 0.4, 0.0]],
        dtype=np.float32,
    )
    labels = np.asarray([0.0, 1.0, 1.0], dtype=np.float32)
    expanded, expanded_labels, sources, synthetic = augment_training_features(
        features,
        labels,
        epsilon_vector=(0.1, 0.1, 0.1, 0.0),
        lower_bound=(0.0, 0.0, 0.0, 0.0),
        upper_bound=(1.0, 1.0, 1.0, 1.0),
        mutable_indices=(0, 1, 2),
        copies_per_sample=2,
        seed=7,
    )
    assert expanded.shape[0] > features.shape[0]
    assert (expanded_labels == 0).sum() == (expanded_labels == 1).sum()
    assert np.all(expanded[:, 3] == expanded[np.asarray(sources), 3])
    assert synthetic.sum() == expanded.shape[0] - features.shape[0]
