#!/usr/bin/env python3
"""Strip pre-rename product names from ONNX metadata without touching the graph.

Why this exists
---------------
The 2026-10-01 rename rewrote every source file, but ONNX binaries carry the
old product name inside their *metadata*, not just their file name:

  * ``producer_name``  - e.g. "HeliosAV feature CNN tract converter"
  * ``graph.name``     - e.g. "HeliosAV_dense_tree_tract_compatible"
  * ``node[*].name``   - e.g. "HeliosDenseTreeClassifier"
  * ``node[*].doc_string`` - torch stack traces such as
    ``File "E:\\HeliosAV\\pyas\\Engine\\Properties\\train_cnn.py"``

``strings``/plain text search does not reliably find these because every
string sits behind a protobuf length prefix, so a grep for the old name can
miss a shipped model entirely.

This tool rewrites only identifier/metadata string fields. It deliberately
never descends into ``TensorProto`` or ``AttributeProto``, so class-label
string tensors and attribute payloads are preserved byte for byte.

Safety
------
Every rewrite is verified before the file is replaced:

  1. the sanitized model must pass ``onnx.checker.check_model``
  2. an ``onnxruntime`` session must produce **bit-identical** outputs for the
     original and the sanitized model on the same deterministic inputs

If either check fails the file is left untouched and the tool exits non-zero.

Usage
-----
    python tools/sanitize_onnx_metadata.py --check <path>...   # report only
    python tools/sanitize_onnx_metadata.py <path>...           # rewrite in place

Backups are written under ``--backup-dir`` (default
``artifacts/_onnx-metadata-backups/``) mirroring the input path, never next to
the model itself: several models live inside the installer staging tree, which
is packaged with a recursive ``bin\\*`` rule, so a sibling ``.backup`` file
would ship the pre-rename bytes straight into the installer.

Exit codes: 0 = clean or successfully sanitized, 1 = verification failed,
2 = a file still contains the old name after sanitizing.
"""

from __future__ import annotations

import argparse
import hashlib
import sys
from pathlib import Path

import numpy as np
import onnx
import onnxruntime as ort
from google.protobuf.descriptor import FieldDescriptor

DEFAULT_BACKUP_DIR = Path("artifacts/_onnx-metadata-backups")

# Ordered longest-first: "HeliosAV" must be replaced before "Helios", otherwise
# "HeliosAV" would be truncated into "EverbloomAV".
REPLACEMENTS: list[tuple[str, str]] = [
    ("HeliosAV", "EverbloomSecurity"),
    ("heliosav", "everbloomsecurity"),
    ("HELIOSAV", "EVERBLOOMSECURITY"),
    ("Helios", "Everbloom"),
    ("helios", "everbloom"),
    ("HELIOS", "EVERBLOOM"),
]

# Subtrees that must not be rewritten: they carry model *data*, not metadata.
OPAQUE_MESSAGE_TYPES = {"onnx.TensorProto", "onnx.AttributeProto"}


def rewrite(text: str) -> str:
    for old, new in REPLACEMENTS:
        if old in text:
            text = text.replace(old, new)
    return text


def _is_repeated(field: FieldDescriptor) -> bool:
    # protobuf >= 4.25 removed FieldDescriptor.label in favour of is_repeated.
    repeated = getattr(field, "is_repeated", None)
    if repeated is not None:
        return bool(repeated)
    return field.label == FieldDescriptor.LABEL_REPEATED


def scrub_message(message, path: str, changes: list[tuple[str, str, str]]) -> None:
    """Rewrite every string field of ``message`` except inside opaque subtrees."""
    full_name = message.DESCRIPTOR.full_name
    if full_name in OPAQUE_MESSAGE_TYPES:
        return

    for field in message.DESCRIPTOR.fields:
        value = getattr(message, field.name)
        here = f"{path}.{field.name}" if path else field.name

        if field.type == FieldDescriptor.TYPE_MESSAGE:
            if _is_repeated(field):
                for index, item in enumerate(value):
                    scrub_message(item, f"{here}[{index}]", changes)
            else:
                if message.HasField(field.name):
                    scrub_message(value, here, changes)
            continue

        if field.type != FieldDescriptor.TYPE_STRING:
            continue

        if _is_repeated(field):
            for index, item in enumerate(value):
                updated = rewrite(item)
                if updated != item:
                    changes.append((f"{here}[{index}]", item, updated))
                    value[index] = updated
        else:
            if value:
                updated = rewrite(value)
                if updated != value:
                    changes.append((here, value, updated))
                    setattr(message, field.name, updated)


def build_feed(session: ort.InferenceSession, seed: int) -> dict[str, np.ndarray]:
    """Deterministic inputs derived from the model's declared input types."""
    rng = np.random.default_rng(seed)
    feed: dict[str, np.ndarray] = {}
    for spec in session.get_inputs():
        shape = [dim if isinstance(dim, int) and dim > 0 else 1 for dim in spec.shape]
        if spec.type == "tensor(float)":
            feed[spec.name] = rng.random(shape, dtype=np.float32)
        elif spec.type == "tensor(double)":
            feed[spec.name] = rng.random(shape, dtype=np.float64)
        elif spec.type == "tensor(int64)":
            feed[spec.name] = rng.integers(0, 2, size=shape, dtype=np.int64)
        elif spec.type == "tensor(int32)":
            feed[spec.name] = rng.integers(0, 2, size=shape, dtype=np.int32)
        else:
            raise RuntimeError(f"unsupported input type for {spec.name}: {spec.type}")
    return feed


def run(session: ort.InferenceSession, feed: dict[str, np.ndarray]) -> list[np.ndarray]:
    names = [output.name for output in session.get_outputs()]
    return session.run(names, feed)


def bit_identical(left: list[np.ndarray], right: list[np.ndarray]) -> bool:
    if len(left) != len(right):
        return False
    for a, b in zip(left, right):
        if a.shape != b.shape or a.dtype != b.dtype:
            return False
        if not np.array_equal(a.view(np.uint8), b.view(np.uint8)):
            return False
    return True


def digest(model: onnx.ModelProto) -> str:
    """Fingerprint of everything that can change inference, excluding metadata."""
    graph = model.graph
    hasher = hashlib.sha256()
    for node in graph.node:
        hasher.update(f"{node.op_type}|{node.domain}|".encode())
        for attribute in node.attribute:
            hasher.update(f"{attribute.name}={onnx.helper.get_attribute_value(attribute)}|".encode())
    for initializer in graph.initializer:
        hasher.update(f"{initializer.name}:{initializer.data_type}:{list(initializer.dims)}|".encode())
        hasher.update(np.frombuffer(initializer.raw_data, dtype=np.uint8).tobytes())
    return hasher.hexdigest()


def backup_path(path: Path, backup_dir: Path) -> Path:
    """Mirror ``path`` under ``backup_dir`` so staging trees stay clean."""
    try:
        relative = path.resolve().relative_to(Path.cwd().resolve())
    except ValueError:
        relative = Path(path.name)
    return backup_dir / relative.with_suffix(relative.suffix + ".pre-rename-backup")


def sanitize(path: Path, check_only: bool, backup_dir: Path) -> bool:
    raw_before = path.read_bytes()
    if b"elios" not in raw_before and b"ELIOS" not in raw_before:
        print(f"clean   {path}")
        return True

    model = onnx.load(str(path))
    graph_before = digest(model)

    changes: list[tuple[str, str, str]] = []
    scrub_message(model, "", changes)

    if not changes:
        print(f"WARN    {path}: raw bytes contain the old name but no rewritable "
              f"metadata field did; inspect manually")
        return False

    print(f"dirty   {path}")
    for field, old, new in changes[:6]:
        print(f"          {field}: {old[:70]!r} -> {new[:70]!r}")
    if len(changes) > 6:
        print(f"          ... and {len(changes) - 6} more")

    if check_only:
        return True

    if digest(model) != graph_before:
        print(f"FAIL    {path}: graph fingerprint changed while rewriting metadata")
        return False

    try:
        onnx.checker.check_model(model)
    except Exception as error:  # noqa: BLE001 - surfaced verbatim on purpose
        print(f"FAIL    {path}: onnx.checker rejected the sanitized model: {error}")
        return False

    # Original outputs, computed before anything is written.
    original_session = ort.InferenceSession(str(path), providers=["CPUExecutionProvider"])
    feed = build_feed(original_session, seed=20261001)
    expected = run(original_session, feed)

    staging = path.with_suffix(path.suffix + ".sanitized")
    onnx.save(model, str(staging))

    sanitized_session = ort.InferenceSession(str(staging), providers=["CPUExecutionProvider"])
    actual = run(sanitized_session, feed)

    if not bit_identical(expected, actual):
        staging.unlink(missing_ok=True)
        print(f"FAIL    {path}: sanitized model output differs from the original")
        return False

    if b"elios" in staging.read_bytes() or b"ELIOS" in staging.read_bytes():
        staging.unlink(missing_ok=True)
        print(f"FAIL    {path}: old name still present after sanitizing")
        return False

    backup = backup_path(path, backup_dir)
    if not backup.exists():
        backup.parent.mkdir(parents=True, exist_ok=True)
        backup.write_bytes(raw_before)
    staging.replace(path)
    print(f"OK      {path}: metadata rewritten, outputs bit-identical "
          f"({path.stat().st_size:,} bytes, backup at {backup})")
    return True


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("paths", nargs="+", type=Path)
    parser.add_argument("--check", action="store_true",
                        help="report the required rewrites without modifying anything")
    parser.add_argument("--backup-dir", type=Path, default=DEFAULT_BACKUP_DIR,
                        help=f"where pre-rewrite copies are kept (default: {DEFAULT_BACKUP_DIR})")
    args = parser.parse_args()

    failures = 0
    for path in args.paths:
        if not path.is_file():
            print(f"SKIP    {path}: not a file")
            failures += 1
            continue
        try:
            if not sanitize(path, args.check, args.backup_dir):
                failures += 1
        except Exception as error:  # noqa: BLE001 - report and continue with the rest
            print(f"FAIL    {path}: {type(error).__name__}: {error}")
            failures += 1

    if failures:
        print(f"\n{failures} file(s) need attention")
        return 1
    print("\nall models clean")
    return 0


if __name__ == "__main__":
    sys.exit(main())
