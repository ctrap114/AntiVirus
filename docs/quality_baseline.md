# Detection quality baseline

Everbloom Security keeps a small, inert regression corpus so rule changes can be checked
before a release. The suspicious fixtures contain only detection strings; they
are not executable malware samples and must not be used as a malware dataset.

Run the baseline from the repository root:

```powershell
.\.venv\Scripts\python.exe tools\run_quality_baseline.py
```

The command writes `artifacts/quality-baseline/latest.json`, which is ignored
because timings are machine-specific. The YARA gate currently expects zero
false positives and zero false negatives on the synthetic corpus. The ONNX
section is reported when `onnxruntime` is installed and otherwise is explicitly
marked `skipped`; install the optional runtime before comparing model metrics:

```powershell
.\.venv\Scripts\python.exe -m pip install -e ".[quality]"
```

The metrics are regression signals, not claims about real-world detection
coverage. Production evaluation should use a separately governed, consented
dataset with family-balanced train/test splits and a fixed hardware/software
environment. The default ONNX run uses the repository's five-record feature
fixture (`dense_test_features.npy` plus `dense_test_labels.npy`) and applies the
same legacy-to-Rust normalization as the trainer; pass
`--model-corpus` and `--model-labels` to evaluate another compatible fixture.
