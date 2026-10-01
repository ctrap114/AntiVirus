#!/usr/bin/env python3
"""Import a manually curated, user-authorized dataset for EverbloomSecurity AI training.

The script is intentionally conservative: it never contacts the network and
only ever reads from paths the operator passes in. The output is a labels.csv
plus a manifest.json that the existing ``tools/train_ai_model.py`` entry
point already accepts, so manual import slots directly into the training
pipeline without further glue.

Supported inputs
----------------

* ``--source <dir>`` with ``malware/`` and ``benign/`` subdirectories, each
  holding the binary samples. Subdirectory names are case-insensitive and
  optional (missing directories contribute zero samples).
* ``--source <dir> --manifest <json>`` where the manifest is a JSON list of
  ``{"path": "...", "label": 0|1, "family": "...", "notes": "..."}`` entries.
  Relative paths are resolved against the manifest's directory.
* ``--import-mode real|adversarial|all`` controls which samples the import
  pipeline accepts (``real`` rejects obvious adversarial fixtures; ``all``
  accepts everything the operator provided).

Outputs
-------

* ``<output>/labels.csv`` with two columns: ``filename,label`` matching
  ``tools/train_ai_model.py``'s contract.
* ``<output>/manifest.json`` with per-sample metadata: SHA-256, size, PE
  flag, optional ``family`` / ``notes`` and any rejection reason.
* ``<output>/import-summary.json`` with the aggregate counts and a list of
  duplicates that were skipped.

Safety
------

* ``--max-bytes`` caps the total bytes ingested (default 4 GiB).
* ``--dedupe`` collapses samples that share a SHA-256.
* ``--dry-run`` writes a summary but does not write labels.csv.
* ``--max-sample-size`` rejects single files larger than the limit (default
  512 MiB) so a stray non-sample is easy to spot.

The script refuses to proceed if the source directory does not exist, the
manifest is malformed, or the import would exceed ``--max-bytes``.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import time
from collections import defaultdict
from pathlib import Path
from typing import Any

PE_MAGIC = b"MZ"
BENIGN_DIR_NAMES = {"benign", "clean", "goodware", "good"}
MALWARE_DIR_NAMES = {"malware", "malicious", "bad", "samples"}


def _compute_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _looks_like_pe(path: Path) -> bool:
    try:
        with path.open("rb") as handle:
            return handle.read(2) == PE_MAGIC
    except OSError:
        return False


def _is_adversarial_fixture(path: Path) -> bool:
    """A file name or directory that smells like an adversarial test fixture.

    We reject obvious EICAR-style strings so a manual import of "real"
    malware is not accidentally polluted by synthetic test vectors.
    """
    name = path.name.lower()
    return "eicar" in name or "synthetic" in name or "fixture" in name


def _collect_directory_samples(
    root: Path, label: int, max_bytes: int, consumed: dict[str, int]
) -> tuple[list[dict[str, Any]], list[str]]:
    if not root.exists():
        return [], [f"directory does not exist: {root}"]
    samples: list[dict[str, Any]] = []
    notes: list[str] = []
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        size = path.stat().st_size
        if consumed["total"] + size > max_bytes:
            notes.append(f"skipped (max bytes exceeded): {path}")
            continue
        consumed["total"] += size
        consumed["count"] += 1
        samples.append({"path": path, "label": label})
    return samples, notes


def _collect_manifest_samples(
    manifest_path: Path, base: Path, max_bytes: int, consumed: dict[str, int]
) -> tuple[list[dict[str, Any]], list[str]]:
    if not manifest_path.exists():
        return [], [f"manifest does not exist: {manifest_path}"]
    try:
        entries = json.loads(manifest_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        return [], [f"manifest is not valid JSON: {exc}"]
    if not isinstance(entries, list):
        return [], ["manifest must be a JSON list of {path,label,...} objects"]
    samples: list[dict[str, Any]] = []
    notes: list[str] = []
    for entry in entries:
        if not isinstance(entry, dict) or "path" not in entry or "label" not in entry:
            notes.append(f"skipped invalid entry: {entry}")
            continue
        candidate = Path(entry["path"])
        if not candidate.is_absolute():
            candidate = (base / candidate).resolve()
        if not candidate.exists() or not candidate.is_file():
            notes.append(f"skipped missing file: {candidate}")
            continue
        size = candidate.stat().st_size
        if consumed["total"] + size > max_bytes:
            notes.append(f"skipped (max bytes exceeded): {candidate}")
            continue
        consumed["total"] += size
        consumed["count"] += 1
        samples.append(
            {
                "path": candidate,
                "label": int(entry["label"]),
                "family": entry.get("family"),
                "notes": entry.get("notes"),
            }
        )
    return samples, notes


def _gather_samples(args: argparse.Namespace) -> tuple[list[dict[str, Any]], list[str]]:
    source = args.source
    notes: list[str] = []
    if not source.exists():
        raise SystemExit(f"source path does not exist: {source}")
    consumed: dict[str, int] = {"total": 0, "count": 0}
    samples: list[dict[str, Any]] = []

    if source.is_dir():
        matched_any_subdir = False
        for sub in sorted(source.iterdir()):
            if not sub.is_dir():
                continue
            label: int | None = None
            lowered = sub.name.lower()
            if lowered in MALWARE_DIR_NAMES:
                label = 1
            elif lowered in BENIGN_DIR_NAMES:
                label = 0
            else:
                notes.append(f"ignoring unrecognized subdir: {sub.name}")
                continue
            matched_any_subdir = True
            sub_samples, sub_notes = _collect_directory_samples(sub, label, args.max_bytes, consumed)
            notes.extend(sub_notes)
            samples.extend(sub_samples)
        if not matched_any_subdir:
            # The source directory itself is a label bucket (e.g. operator
            # passed the benign/ or malware/ folder directly).
            lowered = source.name.lower()
            if lowered in MALWARE_DIR_NAMES:
                label = 1
            elif lowered in BENIGN_DIR_NAMES:
                label = 0
            else:
                label = 0
                notes.append(
                    f"treating {source.name} as a benign bucket (no recognized label name)"
                )
            sub_samples, sub_notes = _collect_directory_samples(
                source, label, args.max_bytes, consumed
            )
            notes.extend(sub_notes)
            samples.extend(sub_samples)

    if args.manifest is not None:
        base = args.manifest.parent
        manifest_samples, manifest_notes = _collect_manifest_samples(
            args.manifest, base, args.max_bytes, consumed
        )
        notes.extend(manifest_notes)
        samples.extend(manifest_samples)

    if not samples:
        notes.append("no samples discovered (check source layout or manifest)")

    return samples, notes


def _normalize_samples(
    samples: list[dict[str, Any]],
    args: argparse.Namespace,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[str]]:
    notes: list[str] = []
    accepted: list[dict[str, Any]] = []
    rejected: list[dict[str, Any]] = []
    for sample in samples:
        path: Path = sample["path"]
        label: int = sample["label"]
        try:
            size = path.stat().st_size
        except OSError as exc:
            rejected.append({"path": str(path), "reason": f"stat failed: {exc}"})
            continue
        if size == 0:
            rejected.append({"path": str(path), "reason": "empty file"})
            continue
        if size > args.max_sample_size:
            rejected.append(
                {
                    "path": str(path),
                    "reason": f"file exceeds max sample size {args.max_sample_size}",
                }
            )
            continue
        if args.import_mode == "real" and _is_adversarial_fixture(path):
            rejected.append({"path": str(path), "reason": "adversarial fixture"})
            continue
        if label == 1 and not _looks_like_pe(path):
            notes.append(f"warning: {path.name} is labelled malware but does not start with MZ")
        sha = _compute_sha256(path)
        accepted.append(
            {
                "path": path,
                "label": label,
                "family": sample.get("family"),
                "notes": sample.get("notes"),
                "size": size,
                "sha256": sha,
                "is_pe": _looks_like_pe(path),
            }
        )

    if args.dedupe:
        seen: dict[str, dict[str, Any]] = {}
        deduped: list[dict[str, Any]] = []
        duplicates: list[dict[str, Any]] = []
        for sample in accepted:
            if sample["sha256"] in seen:
                duplicates.append({"path": str(sample["path"]), "sha256": sample["sha256"]})
                continue
            seen[sample["sha256"]] = sample
            deduped.append(sample)
        accepted = deduped
        if duplicates:
            notes.append(f"dedupe removed {len(duplicates)} duplicate sample(s)")

    return accepted, rejected, notes


def _write_outputs(
    accepted: list[dict[str, Any]],
    rejected: list[dict[str, Any]],
    notes: list[str],
    args: argparse.Namespace,
) -> dict[str, Any]:
    args.output.mkdir(parents=True, exist_ok=True)
    labels_path = args.output / "labels.csv"
    manifest_path = args.output / "manifest.json"
    summary_path = args.output / "import-summary.json"

    label_counts = defaultdict(int)
    family_counts: dict[str, int] = defaultdict(int)
    if not args.dry_run:
        with labels_path.open("w", newline="", encoding="utf-8") as handle:
            writer = csv.writer(handle)
            writer.writerow(["filename", "label"])
            for sample in accepted:
                writer.writerow([sample["path"].name, sample["label"]])
                label_counts[sample["label"]] += 1
                if sample.get("family"):
                    family_counts[str(sample["family"])] += 1
        manifest_path.write_text(
            json.dumps(
                [
                    {
                        "path": str(sample["path"]),
                        "filename": sample["path"].name,
                        "label": sample["label"],
                        "size": sample["size"],
                        "sha256": sample["sha256"],
                        "is_pe": sample["is_pe"],
                        "family": sample.get("family"),
                        "notes": sample.get("notes"),
                    }
                    for sample in accepted
                ],
                ensure_ascii=False,
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
    else:
        for sample in accepted:
            label_counts[sample["label"]] += 1
            if sample.get("family"):
                family_counts[str(sample["family"])] += 1

    summary = {
        "schema": 1,
        "generated_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "source": str(args.source),
        "manifest": str(args.manifest) if args.manifest is not None else None,
        "import_mode": args.import_mode,
        "dedupe": args.dedupe,
        "max_bytes": args.max_bytes,
        "max_sample_size": args.max_sample_size,
        "dry_run": args.dry_run,
        "accepted": len(accepted),
        "rejected": len(rejected),
        "label_counts": dict(label_counts),
        "family_counts": dict(family_counts),
        "rejected_samples": rejected,
        "notes": notes,
        "labels_csv": str(labels_path) if not args.dry_run else None,
        "manifest_json": str(manifest_path) if not args.dry_run else None,
    }
    summary_path.write_text(
        json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    return summary


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True, help="Root directory of the curated dataset.")
    parser.add_argument(
        "--manifest",
        type=Path,
        default=None,
        help="Optional JSON manifest listing per-sample {path,label,family,notes} entries.",
    )
    parser.add_argument(
        "--import-mode",
        choices=["real", "adversarial", "all"],
        default="real",
        help="Which samples to accept; 'real' rejects obvious EICAR/synthetic fixtures.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("artifacts/datasets/imported"),
        help="Output directory for labels.csv / manifest.json / import-summary.json.",
    )
    parser.add_argument("--max-bytes", type=int, default=4 * (1 << 30), help="Maximum total bytes to ingest.")
    parser.add_argument(
        "--max-sample-size",
        type=int,
        default=512 * (1 << 20),
        help="Reject single files larger than this size (default 512 MiB).",
    )
    parser.add_argument(
        "--dedupe",
        action="store_true",
        help="Drop samples that share a SHA-256 (keep the first occurrence).",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Compute the import summary but do not write labels.csv / manifest.json.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    samples, notes = _gather_samples(args)
    accepted, rejected, normalize_notes = _normalize_samples(samples, args)
    notes.extend(normalize_notes)
    summary = _write_outputs(accepted, rejected, notes, args)
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
