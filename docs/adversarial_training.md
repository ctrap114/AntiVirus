# Defensive adversarial training

Everbloom Security now includes a feature-space adversarial trainer. It is designed for
robustness testing and model hardening: it consumes numeric feature vectors,
generates bounded projected-gradient (PGD) perturbations, and trains the
classifier on both clean and perturbed vectors. It never modifies PE files,
creates executables, or produces file-level evasion samples.

## Install and validate

The training dependencies are optional because PyTorch and ONNX are large:

```powershell
.\.venv\Scripts\python.exe -m pip install -e ".[ml]"
.\.venv\Scripts\python.exe tools\train_adversarial_model.py --dry-run
```

The default dry run uses the repository's current raw 1283-feature fixture and
automatically converts its legacy `Entropy`, `FileSize`, and `StringCount`
columns to the normalized representation used by Rust. It keeps only those
three continuous fields mutable. DLL/API hash buckets and other discrete
indicators are immutable. Use `--normalization none` only when the input matrix
is already in the Rust runtime representation.

By default, each original training row receives eight bounded feature-space
variants and the minority class is filled to the same count. The validation
split is made before augmentation and contains original rows only. Synthetic
rows are marked in an optional exported `.npz` corpus; no executable or file
sample is created.

## Train a Rust-compatible model

```powershell
.\.venv\Scripts\python.exe tools\train_adversarial_model.py `
  --features dense_test_features.npy `
  --labels dense_test_labels.npy `
  --feature-dim 1283 `
  --augment-per-sample 8 `
  --export-augmented artifacts/ml-corpus/train_augmented.npz `
  --out artifacts/models/everbloom_adversarial.onnx
```

The command writes the ONNX model, `model_contract.json`, and a matching
`features.json` beside it. The contract marks the output as a binary logit and
the input layout as `[batch, 1, feature_dim]`, which is accepted by the Rust
model loader's dynamic-shape path.

To add eight runtime-compatible interaction and hash-density fields, use:

```powershell
.\.venv\Scripts\python.exe tools/train_adversarial_model.py `
  --add-derived-features `
  --out artifacts/models/advanced/everbloom_adversarial_advanced.onnx
```

This produces a 1291-dimensional model and writes the expanded feature map
next to it. Keep models with different feature maps in separate directories;
the Rust extractor recognizes the same formulas, while the
original 1283-dimensional model remains compatible. Derived fields are fixed
during augmentation; only the three continuous source fields are mutable.

For a normal 12-feature dataset, use `--feature-dim 12`; the trainer then uses
the Rust canonical normalized feature bounds and a more granular mutable set.
JSONL input is also supported, with records shaped as:

```json
{"label": 1, "features": [0.8, 0.1, 0.2]}
```

## Safety and interpretation

The `epsilon_fraction` budget is scaled from robust observed feature ranges,
not applied as one absolute value to mixed-unit fields. Validation reports must
compare clean and adversarial accuracy, recall, false-positive rate, and
false-negative rate. A small synthetic corpus is useful for regression tests
but is not evidence of production malware-detection quality; use a governed,
authorized, family-balanced dataset for real training.
