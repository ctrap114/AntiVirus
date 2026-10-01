#!/usr/bin/env python3
"""Assemble an evaluation manifest for engine/examples/eval_harness.rs.

The harness needs a `category` column to answer the question that dominates
false-positive work - *which kind of benign file is being flagged* - and none
of the corpora in this repository carry one. This tool derives it and writes a
single normalised JSONL manifest.

Categories are assigned from the sample's family when the source manifest has
one, otherwise from its directory, and are prefixed so the origin is obvious:

    synthetic_inert_api_heavy_like   generated filler with API-name density
    synthetic_inert_packed_like      generated high-entropy container
    synthetic_inert_stealth_like     generated low-signal filler
    regression_benign                tests/corpus/benign
    regression_malicious             tests/corpus/malicious

Nothing here downloads or fabricates samples: it only relabels files that are
already on disk, and it refuses to emit an entry whose file is missing.

Usage
-----
    python tools/build_eval_manifest.py --out artifacts/quality-baseline/eval-corpus.jsonl
    python tools/build_eval_manifest.py --out /tmp/eval.jsonl --source tests/corpus/manifest.json
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# Manifest -> (category prefix, category-from-family, category-from-directory)
DEFAULT_SOURCES: list[tuple[Path, str, str]] = [
    (
        ROOT / "artifacts" / "ml-corpus" / "synthetic" / "manifest.jsonl",
        "synthetic_inert",
        "synthetic_inert",
    ),
    (
        ROOT / "artifacts" / "ml-corpus" / "synthetic_rust" / "manifest.jsonl",
        "synthetic_inert",
        "synthetic_inert",
    ),
    (ROOT / "tests" / "corpus" / "manifest.json", "regression", "regression"),
]

NORMALISE = {
    "1": "malicious",
    "0": "benign",
    "true": "malicious",
    "false": "benign",
}


def normalise_label(value) -> str | None:
    """Accept every spelling the corpora use: word, int, or float.

    `artifacts/ml-corpus/synthetic` writes `0`/`1` while `.../synthetic_rust`
    writes `0.0`/`1.0`; treating only the integer form as a label silently
    dropped 900 labelled samples into the unlabelled bucket.
    """
    if value is None:
        return None
    text = str(value).strip().lower()
    if text in NORMALISE:
        return NORMALISE[text]
    if text in {"malicious", "malware", "benign", "clean"}:
        return "malicious" if text in {"malicious", "malware"} else "benign"
    try:
        number = float(text)
    except ValueError:
        return None
    if number == 1.0:
        return "malicious"
    if number == 0.0:
        return "benign"
    return None


def load_source(path: Path) -> list[dict]:
    if not path.is_file():
        print(f"skip    {path.relative_to(ROOT)}: not present")
        return []
    text = path.read_text(encoding="utf-8")
    if path.suffix.lower() == ".json":
        document = json.loads(text)
        if isinstance(document, dict):
            return list(document.get("samples", []))
        return list(document)
    rows = []
    for index, line in enumerate(text.splitlines(), start=1):
        line = line.strip()
        if not line or line.startswith("//"):
            continue
        try:
            rows.append(json.loads(line))
        except json.JSONDecodeError as error:
            print(f"warn    {path.name}:{index}: {error}", file=sys.stderr)
    return rows


def categorise(row: dict, prefix: str, from_family: str, base: Path) -> str:
    family = row.get("family")
    if family:
        return f"{from_family}_{family}"
    raw = str(row.get("path", ""))
    parent = Path(raw).parent.name
    if parent and parent not in {".", ""}:
        return f"{prefix}_{parent}"
    return prefix


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--source", type=Path, action="append", default=None,
                        help="manifest to include (repeatable); defaults to every known corpus")
    args = parser.parse_args()

    if args.source:
        sources = [(path, path.stem, path.stem) for path in args.source]
    else:
        sources = DEFAULT_SOURCES

    entries: list[dict] = []
    missing = 0
    counts: dict[str, int] = {}
    label_counts: dict[str, int] = {}

    for manifest, prefix, family_prefix in sources:
        rows = load_source(manifest)
        if not rows:
            continue
        base = manifest.parent
        for row in rows:
            raw_path = row.get("path")
            if not raw_path:
                continue
            resolved = Path(raw_path)
            if not resolved.is_absolute():
                resolved = base / resolved
            if not resolved.is_file():
                missing += 1
                continue
            label = normalise_label(row.get("label"))
            category = categorise(row, prefix, family_prefix, base)
            try:
                relative = resolved.resolve().relative_to(ROOT).as_posix()
            except ValueError:
                relative = str(resolved)
            entries.append(
                {
                    "path": relative,
                    "label": label,
                    "family": row.get("family"),
                    "category": category,
                }
            )
            counts[category] = counts.get(category, 0) + 1
            label_counts[label or "unlabelled"] = label_counts.get(label or "unlabelled", 0) + 1

    if not entries:
        print("error: no usable samples found", file=sys.stderr)
        return 1

    args.out.parent.mkdir(parents=True, exist_ok=True)
    with args.out.open("w", encoding="utf-8", newline="\n") as handle:
        for entry in entries:
            handle.write(json.dumps(entry, ensure_ascii=False) + "\n")

    print(f"wrote {args.out.relative_to(ROOT) if args.out.is_relative_to(ROOT) else args.out}")
    print(f"  samples {len(entries)}  skipped-missing {missing}")
    print(f"  labels  {dict(sorted(label_counts.items()))}")
    for category, count in sorted(counts.items()):
        print(f"  {category:<40} {count}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
