# Inert synthetic corpus experiments

Everbloom Security can validate and improve its AI detector using automatically
generated, fully inert samples that merely *look* suspicious. The generator in
`python/everbloom_core/synthetic.py` builds data-only PE files — it never embeds
functional payloads, shellcode, or exploit code.

## Safety guarantees

Every generated file:

* carries the ASCII marker `EVERBLOOM-SYNTHETIC-CORPUS-NOT-MALWARE`;
* has an entry point consisting of a single `RET` (`0xC3`);
* contains only benign imports (kernel32/advapi32/user32 API names) and
  printable filler bytes;
* is written exclusively under a caller-provided output root;
  `validate_output_root()` refuses protected locations such as `C:\Windows`,
  `C:\Program Files`, or drive roots.

The Rust integration test `engine/tests/synthetic_corpus.rs` enforces these
invariants against checked-in fixtures.

## Families

| Family | Label | Traits |
| --- | --- | --- |
| `benign_like` | 0 | multiple imports, valid timestamp, no TLS |
| `packed_like` | 1 | high entropy, TLS callback, zeroed timestamp |
| `api_heavy_like` | 1 | many imports, low entropy, recent timestamp |
| `stealth_like` | 1 | TLS + zeroed timestamp + moderate entropy |

`extract_features_12()` mirrors the engine's canonical normalized feature
extraction (`AiModel::extract_features_with_size` in
`engine/src/layers/ai.rs`), including the timestamp anomaly score, so Python
training uses exactly what Rust inference sees.

## Running the experiment

```powershell
.\.venv\Scripts\python.exe tools\train_synthetic_experiment.py
```

The tool generates ~900 inert samples under
`artifacts/ml-corpus/synthetic/`, trains two identical MLPs on the 12-dim
features, and compares:

* **baseline** — trained only on `benign_like` + `packed_like`;
* **augmented** — trained on all four families.

Both are evaluated on the same held-out split containing every family.
Reference result (seed 2026): baseline recall 0.69 with 0.00 false-positive
rate; augmented recall 1.00 with 0.00 false-positive rate — a **+0.31 recall
gain on trait combinations the baseline never saw**, at zero FPR cost.

Outputs:

* `artifacts/models/synthetic_experiment/everbloom_synthetic.onnx` — best model,
  exported with the Rust-compatible `[batch, 1, feature_dim]` logit layout plus
  `model_contract.json`;
* `artifacts/quality-baseline/synthetic_experiment.json` — metrics report with
  per-family breakdowns.

Useful flags: `--skip-generation` (reuse an existing manifest), `--force`
(overwrite a previous corpus), `--counts '{"benign_like":400,...}'`,
`--epochs/--hidden-dim/--learning-rate`, `--report`.

## Interpretation

Synthetic corpora measure *representational coverage*: they show how well a
model generalizes to suspicious trait combinations, not how it performs on real
malware. Production quality claims still require governed, authorized,
family-balanced real-world datasets (see `docs/adversarial_training.md`). The
synthetic experiment complements them by providing an unlimited, safe,
reproducible regression harness for detector changes.
