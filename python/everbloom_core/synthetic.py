"""Inert synthetic PE corpus generator for defensive detector evaluation.

This module builds **data-only** PE files that carry suspicious-looking
*static* traits (high entropy sections, unusual entry-point placement, TLS
tables, long import tables) while being guaranteed inert:

- the entry point is a single ``RET`` instruction (0xC3) with no other code;
- imported names are never resolved or called at runtime by our own files
  because execution stops immediately, and many templates deliberately use
  non-existent export names so loading fails harmlessly;
- every artifact embeds the ASCII marker ``EVERBLOOM-SYNTHETIC-CORPUS``;
- generation refuses to write outside a caller-provided output root.

The corpus exists so EverbloomSecurity's own AI model, heuristics and regression tests
can be trained/evaluated without touching real malware. It must never be used
to evade third-party defenses: the traits are static decoys, not functional
capabilities.
"""

from __future__ import annotations

import hashlib
import json
import struct
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Sequence

import numpy as np

SYNTHETIC_MARKER = b"EVERBLOOM-SYNTHETIC-CORPUS-NOT-MALWARE"
DOS_STUB = b"This program cannot be run in DOS mode.\r\r\n$"
FILE_ALIGNMENT = 0x200
SECTION_ALIGNMENT = 0x1000
HEADER_SIZE = 0x400

FORBIDDEN_OUTPUT_HINTS = (
    "c:\\windows",
    "c:\\program files",
    "c:\\programdata",
    "c:\\users\\default",
)


def _align_up(value: int, alignment: int) -> int:
    return (value + alignment - 1) // alignment * alignment


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    buffer = np.frombuffer(data, dtype=np.uint8)
    counts = np.bincount(buffer, minlength=256)
    probabilities = counts[counts > 0] / buffer.size
    return float(-(probabilities * np.log2(probabilities)).sum())


@dataclass(frozen=True)
class SectionSpec:
    """A section whose body is filled by one of the fill strategies."""

    name: str
    virtual_size: int
    characteristics: int
    fill: str = "zeros"          # zeros | random | mixed | ascii
    random_fraction: float = 0.0  # for "mixed": share of pseudo-random bytes

    def build(self, rng: np.random.Generator) -> bytes:
        size = self.virtual_size
        if self.fill == "random":
            return rng.integers(0, 256, size=size, dtype=np.uint8).tobytes()
        if self.fill == "ascii":
            words = (b"kernel32 ", b"stdcall ", b"offset ", b"lea eax ", b".debug ")
            body = bytearray()
            while len(body) < size:
                body += words[int(rng.integers(0, len(words)))]
            return bytes(body[:size])
        if self.fill == "mixed":
            fraction = min(max(self.random_fraction, 0.0), 1.0)
            body = bytearray(size)
            noisy = int(size * fraction)
            if noisy:
                body[:noisy] = rng.integers(0, 256, size=noisy, dtype=np.uint8).tobytes()
            return bytes(body)
        return bytes(size)


@dataclass(frozen=True)
class ImportSpec:
    """One DLL plus its (possibly fictional) import names."""

    dll: str
    functions: Sequence[str]


@dataclass
class PeTemplate:
    """Parameters describing one family of synthetic samples."""

    label: int
    family: str
    sections: Sequence[SectionSpec]
    imports: Sequence[ImportSpec] = field(default_factory=tuple)
    tls_present: bool = False
    entry_in_last_section: bool = False
    timestamp_mode: str = "recent"   # recent | zero | ancient | future
    subsystem: int = 3               # 3=console, 2=gui
    overlay_bytes: int = 0


# ---------------------------------------------------------------------------
# Minimal PE32+ builder
# ---------------------------------------------------------------------------


def _section_header(spec: SectionSpec, rva: int, raw_offset: int, raw_size: int) -> bytes:
    name = spec.name.encode("ascii")[:8].ljust(8, b"\x00")
    return struct.pack(
        "<8sIIIIIIHHI",
        name,
        spec.virtual_size,
        rva,
        raw_size,
        raw_offset,
        0,      # relocs
        0,      # line numbers
        0,
        0,
        spec.characteristics,
    )


def _build_import_blob(
    imports: Sequence[ImportSpec], rva_base: int
) -> tuple[bytes, int, int, int, int]:
    """Build descriptors + thunks + hint/name entries inside one flat blob.

    Layout: ``[(n+1) descriptors][per-dll: hint/names, ILT, IAT][dll names]``.
    Returns ``(blob, import_dir_rva, import_dir_size, iat_rva, iat_size)``.
    """

    descriptor_size = 20
    total_dlls = len(imports)
    offset = descriptor_size * (total_dlls + 1)

    plan: list[tuple[ImportSpec, list[int], int, int]] = []
    for spec in imports:
        name_rvas: list[int] = []
        for function in spec.functions:
            name_rvas.append(rva_base + offset)
            offset += 2 + len(function.encode("ascii")) + 1
        ilt_offset = offset
        offset += 8 * (len(spec.functions) + 1)
        iat_offset = offset
        offset += 8 * (len(spec.functions) + 1)
        plan.append((spec, name_rvas, ilt_offset, iat_offset))

    dll_name_offsets: list[tuple[int, int]] = []
    for spec in imports:
        encoded = spec.dll.encode("ascii") + b"\x00"
        dll_name_offsets.append((rva_base + offset, len(encoded)))
        offset += len(encoded)

    blob = bytearray(offset)

    def write_at(blob_offset: int, payload: bytes) -> None:
        if blob_offset < 0 or blob_offset + len(payload) > len(blob):
            raise ValueError("import blob write out of range")
        blob[blob_offset : blob_offset + len(payload)] = payload

    iat_start: int | None = None
    iat_end = 0
    for index, ((spec, name_rvas, ilt_offset, iat_offset), (name_rva, _)) in enumerate(
        zip(plan, dll_name_offsets)
    ):
        for function, name_rva_entry in zip(spec.functions, name_rvas):
            write_at(
                name_rva_entry - rva_base,
                struct.pack("<H", 0) + function.encode("ascii") + b"\x00",
            )
        thunk_values = [*name_rvas, 0]
        for slot, value in enumerate(thunk_values):
            payload = struct.pack("<Q", value)
            write_at(ilt_offset + 8 * slot, payload)
            write_at(iat_offset + 8 * slot, payload)
        write_at(name_rva - rva_base, spec.dll.encode("ascii") + b"\x00")
        write_at(
            index * descriptor_size,
            struct.pack(
                "<IIIII",
                rva_base + ilt_offset,
                0,
                0,
                name_rva,
                rva_base + iat_offset,
            ),
        )
        span_bytes = 8 * len(thunk_values)
        if iat_start is None:
            iat_start = iat_offset
        iat_end = max(iat_end, iat_offset + span_bytes)

    assert iat_start is not None
    return bytes(blob), rva_base, descriptor_size * (total_dlls + 1), iat_start, iat_end - iat_start


def build_pe(template: PeTemplate, seed: int) -> bytes:
    """Assemble an inert PE image from a template."""

    rng = np.random.default_rng(seed)

    dos = bytearray(0x40)
    dos[0:2] = b"MZ"
    struct.pack_into("<H", dos, 0x02, 0x90)     # e_cblp
    struct.pack_into("<H", dos, 0x04, 0x03)     # e_cp
    struct.pack_into("<H", dos, 0x18, 0x40)     # e_lfarlc
    e_lfanew = 0x80
    struct.pack_into("<I", dos, 0x3C, e_lfanew)

    stub = bytearray(e_lfanew - len(dos))
    stub[0 : len(DOS_STUB)] = DOS_STUB

    sections = list(template.sections)
    section_count = len(sections)

    headers_size = HEADER_SIZE
    first_section_raw = _align_up(headers_size, FILE_ALIGNMENT)

    bodies = [spec.build(rng) for spec in sections]
    raw_sizes = [_align_up(len(body), FILE_ALIGNMENT) or FILE_ALIGNMENT for body in bodies]
    raw_offsets: list[int] = []
    current = first_section_raw
    for size in raw_sizes:
        raw_offsets.append(current)
        current += size

    rvas: list[int] = []
    current_rva = _align_up(headers_size, SECTION_ALIGNMENT)
    for body in bodies:
        rvas.append(current_rva)
        current_rva += max(_align_up(len(body), SECTION_ALIGNMENT), SECTION_ALIGNMENT)

    text_rva = rvas[0]

    # Import blob lives at the start of the second section (.rdata).
    import_rva = import_size = iat_rva = iat_size = 0
    if template.imports:
        blob, import_rva, import_size, iat_rva, iat_size = _build_import_blob(
            template.imports, rvas[1]
        )
        body = bytearray(bodies[1])
        blob_view = memoryview(body)
        needed = len(blob)
        if len(blob_view) < needed:  # pragma: no cover - templates guarantee space
            raise ValueError(".rdata template too small for import table")
        blob_view[:needed] = blob
        bodies[1] = bytes(body)

    tls_descriptor = b""
    tls_dir_rva = tls_dir_size = 0
    if template.tls_present:
        callbacks_slot_rva = rvas[1] + 0x400
        callbacks_va = 0x140000000 + callbacks_slot_rva
        index_slot_rva = rvas[1] + 0x420
        tls_descriptor = struct.pack(
            "<QQQQQI",
            0x140000000 + rvas[1] + 0x440,  # StartAddressOfRawData
            0x140000000 + rvas[1] + 0x480,  # EndAddressOfRawData
            0x140000000 + index_slot_rva,   # AddressOfIndex
            callbacks_va,                   # AddressOfCallBacks
            0,                              # SizeOfZeroFill/Characteristics union
            0,                              # Characteristics
        )
        tls_dir_rva = rvas[1] + 0x800
        tls_dir_size = len(tls_descriptor)
        body = bytearray(bodies[1])
        end = tls_dir_rva - rvas[1] + len(tls_descriptor)
        if end > len(body):  # pragma: no cover - templates guarantee space
            raise ValueError(".rdata template too small for TLS directory")
        body[tls_dir_rva - rvas[1] : end] = tls_descriptor
        bodies[1] = bytes(body)

    if template.entry_in_last_section:
        entry_rva = rvas[-1]
        body = bytearray(bodies[-1])
        body[0] = 0xC3  # RET
        marker_at = 16
        body[marker_at : marker_at + len(SYNTHETIC_MARKER)] = SYNTHETIC_MARKER
        bodies[-1] = bytes(body)
    else:
        entry_rva = text_rva
        body = bytearray(bodies[0])
        body[0] = 0xC3
        marker_at = 16
        body[marker_at : marker_at + len(SYNTHETIC_MARKER)] = SYNTHETIC_MARKER
        bodies[0] = bytes(body)

    now = 1_750_000_000
    timestamp_modes = {
        "recent": now,
        "zero": 0,
        "ancient": 100_000_000,
        "future": 3_500_000_000,
    }
    timestamp = timestamp_modes[template.timestamp_mode]

    coff = struct.pack(
        "<HHIIIHH",
        0x8664,                 # AMD64
        section_count,
        timestamp,
        0,
        0,
        240,                    # SizeOfOptionalHeader (PE32+)
        0x0022,                 # EXECUTABLE_IMAGE | LARGE_ADDRESS_AWARE
    )

    size_of_image = _align_up(current_rva, SECTION_ALIGNMENT)
    size_of_headers = headers_size
    optional = bytearray(240)
    code_size = raw_sizes[0]
    initialized = sum(raw_sizes[1:])
    struct.pack_into("<H", optional, 0, 0x20B)             # PE32+
    struct.pack_into("<BB", optional, 2, 14, 0)            # linker version
    struct.pack_into("<I", optional, 4, code_size)
    struct.pack_into("<I", optional, 8, initialized)
    struct.pack_into("<I", optional, 12, 0)
    struct.pack_into("<I", optional, 16, entry_rva)
    struct.pack_into("<I", optional, 20, text_rva)
    struct.pack_into("<Q", optional, 24, 0x140000000)      # ImageBase
    struct.pack_into("<I", optional, 32, SECTION_ALIGNMENT)
    struct.pack_into("<I", optional, 36, FILE_ALIGNMENT)
    struct.pack_into("<HH", optional, 40, 6, 0)            # OS version
    struct.pack_into("<HH", optional, 44, 6, 0)            # Subsystem version
    struct.pack_into("<I", optional, 48, size_of_headers)
    struct.pack_into("<I", optional, 56, size_of_image)
    struct.pack_into("<H", optional, 60, template.subsystem)
    struct.pack_into("<H", optional, 62, 0x160)            # DllCharacteristics
    struct.pack_into("<QQ", optional, 64, 0x100000, 0x1000)
    struct.pack_into("<QQ", optional, 72, 0x100000, 0x1000)
    struct.pack_into("<I", optional, 108, 16)              # NumberOfRvaAndSizes

    # Data directory [1] = Import, [12] = IAT, [9] = TLS.
    dir_base = 112
    if import_size:
        struct.pack_into("<II", optional, dir_base + 8, import_rva, import_size)
        struct.pack_into("<II", optional, dir_base + 12 * 8, iat_rva, iat_size)
    if tls_dir_size:
        struct.pack_into("<II", optional, dir_base + 9 * 8, tls_dir_rva, tls_dir_size)

    pe_sig = b"PE\x00\x00"
    section_headers = b"".join(
        _section_header(spec, rva, off, size)
        for spec, rva, off, size in zip(sections, rvas, raw_offsets, raw_sizes)
    )

    header_block = bytearray(headers_size)
    head = bytes(dos) + bytes(stub) + pe_sig + coff + bytes(optional) + section_headers
    header_block[: len(head)] = head

    image = bytearray(header_block)
    for body, off in zip(bodies, raw_offsets):
        pad_target = off + _align_up(len(body), FILE_ALIGNMENT)
        image.extend(b"\x00" * (off - len(image)))
        image.extend(body)
        image.extend(b"\x00" * (pad_target - len(image)))

    if template.overlay_bytes:
        noise = rng.integers(0, 256, size=template.overlay_bytes, dtype=np.uint8).tobytes()
        image.extend(noise)

    if SYNTHETIC_MARKER not in image:  # pragma: no cover - safety net
        raise RuntimeError("synthetic marker missing from generated image")
    return bytes(image)


# ---------------------------------------------------------------------------
# Family templates
# ---------------------------------------------------------------------------


COMMON_BENIGN_IMPORTS = (
    ImportSpec("KERNEL32.dll", ("CreateFileW", "ReadFile", "CloseHandle", "GetLastError")),
    ImportSpec("api-ms-win-crt-runtime-l1-1-0.dll", ("_initterm", "__C_specific_handler")),
)

SUSPICIOUS_IMPORT_NAMES = (
    "VirtualAllocEx",
    "WriteProcessMemory",
    "CreateRemoteThread",
    "SetWindowsHookExW",
    "CryptEncrypt",
    "WinExec",
    "URLDownloadToFileW",
    "RegSetValueExW",
    "NtUnmapViewOfSection",
    "GetAsyncKeyState",
)


def benign_like(seed_shift: int = 0) -> PeTemplate:
    return PeTemplate(
        label=0,
        family="benign_like",
        sections=(
            SectionSpec(".text", 0x600, 0x60000020, fill="mixed", random_fraction=0.25),
            SectionSpec(".rdata", 0x900, 0x40000040, fill="ascii"),
            SectionSpec(".data", 0x400, 0xC0000040),
            SectionSpec(".rsrc", 0x300, 0x40000040, fill="ascii"),
        ),
        imports=COMMON_BENIGN_IMPORTS,
        subsystem=2,
    )


def packed_like() -> PeTemplate:
    return PeTemplate(
        label=1,
        family="packed_like",
        sections=(
            SectionSpec(".text", 0x200, 0x60000020),
            SectionSpec(".themida", 0x1800, 0xE00000E0, fill="random"),
            SectionSpec(".data", 0x200, 0xC0000040, fill="random"),
        ),
        imports=(ImportSpec("KERNEL32.dll", ("LoadLibraryA", "GetProcAddress", "VirtualProtect")),),
        tls_present=True,
        entry_in_last_section=True,
        timestamp_mode="zero",
        overlay_bytes=2048,
    )


def api_heavy_like() -> PeTemplate:
    return PeTemplate(
        label=1,
        family="api_heavy_like",
        sections=(
            SectionSpec(".text", 0x800, 0x60000020, fill="mixed", random_fraction=0.5),
            SectionSpec(".rdata", 0xA00, 0x40000040, fill="mixed", random_fraction=0.35),
            SectionSpec(".data", 0x400, 0xC0000040, fill="mixed", random_fraction=0.2),
        ),
        imports=(
            ImportSpec("advapi32.dll", SUSPICIOUS_IMPORT_NAMES[:6]),
            ImportSpec("ws2_32.dll", SUSPICIOUS_IMPORT_NAMES[6:]),
            ImportSpec("user32.dll", ("SetWindowsHookExW", "GetAsyncKeyState")),
            ImportSpec("wininet.dll", ("InternetOpenW", "HttpSendRequestW")),
        ),
        timestamp_mode="ancient",
    )


def stealth_like() -> PeTemplate:
    """High entropy everywhere, no imports, oversized last section."""

    return PeTemplate(
        label=1,
        family="stealth_like",
        sections=(
            SectionSpec(".flat", 0x2000, 0xE00000E0, fill="random"),
            SectionSpec(".bss", 0xC00, 0xC0000040, fill="mixed", random_fraction=0.6),
        ),
        tls_present=True,
        entry_in_last_section=True,
        timestamp_mode="future",
        overlay_bytes=4096,
    )


FAMILY_BUILDERS = {
    "benign_like": benign_like,
    "packed_like": packed_like,
    "api_heavy_like": api_heavy_like,
    "stealth_like": stealth_like,
}


# ---------------------------------------------------------------------------
# Feature extraction mirror of engine/src/layers/ai.rs (12 dims)
# ---------------------------------------------------------------------------


def extract_features_12(blob: bytes, now_seconds: int | None = None) -> np.ndarray:
    features = np.zeros(12, dtype=np.float32)
    features[0] = min(1.0, len(blob) / max(1, len(blob)))

    if blob[:2] == b"MZ":
        e_lfanew = struct.unpack_from("<I", blob, 0x3C)[0]
        if blob[e_lfanew : e_lfanew + 4] == b"PE\x00\x00":
            coff = e_lfanew + 4
            section_count = struct.unpack_from("<H", blob, coff + 2)[0]
            stamp = struct.unpack_from("<I", blob, coff + 4)[0]
            opt = coff + 20
            magic = struct.unpack_from("<H", blob, opt)[0]
            features[1] = min(1.0, section_count / 32.0)
            import_count = _count_imports(blob, e_lfanew) if magic == 0x20B else 0
            features[2] = min(1.0, import_count / 256.0)
            dirs = opt + 112
            if magic == 0x20B:
                tls_rva, tls_size = struct.unpack_from("<II", blob, dirs + 9 * 8)
                if tls_size:
                    features[3] = 1.0
                features[4] = _timestamp_anomaly(stamp, now_seconds)
                features[5] = _first_section_entropy(blob, opt, section_count)

    printable = sum(1 for byte in blob if 0x20 <= byte <= 0x7E or byte in (9, 10, 13, 32))
    features[6] = printable / max(1, len(blob))
    features[7] = blob.count(0) / max(1, len(blob))
    seen = np.unique(np.frombuffer(blob, dtype=np.uint8)).size
    features[8] = seen / 256.0
    features[9] = (sum(blob) / max(1, len(blob))) / 255.0
    features[10] = _entropy(blob) / 8.0
    features[11] = 1.0 if len(blob) > 1024 * 1024 else 0.0
    return features


def _timestamp_anomaly(timestamp: int, now_seconds: int | None) -> float:
    if timestamp == 0:
        return 1.0
    now = now_seconds if now_seconds is not None else 1_800_000_000
    thirty_days = 60 * 60 * 24 * 30
    twenty_years = 60 * 60 * 24 * 365 * 20
    if timestamp > now + thirty_days:
        return 1.0
    if timestamp < now - twenty_years:
        return 0.75
    return 0.0


def _first_section_entropy(blob: bytes, opt: int, section_count: int) -> float:
    magic = struct.unpack_from("<H", blob, opt)[0]
    if magic != 0x20B or section_count < 1:
        return 0.0
    first_header = opt + 240
    if first_header + 40 > len(blob):
        return 0.0
    raw_size, raw_ptr = struct.unpack_from("<II", blob, first_header + 16)
    if raw_size and raw_ptr + raw_size <= len(blob):
        return float(min(1.0, _entropy(blob[raw_ptr : raw_ptr + raw_size]) / 8.0))
    return 0.0


def _count_imports(blob: bytes, e_lfanew: int) -> int:
    opt = e_lfanew + 24
    dirs = opt + 112
    import_rva, import_size = struct.unpack_from("<II", blob, dirs + 8)
    if not import_rva or not import_size:
        return 0

    def rva_to_offset(rva: int) -> int:
        header = opt + 240
        for _ in range(struct.unpack_from("<H", blob, e_lfanew + 6)[0]):
            if header + 40 > len(blob):
                return 0
            virt_size, virt_addr, raw_size, raw_ptr = struct.unpack_from(
                "<IIII", blob, header + 8
            )
            if virt_addr <= rva < virt_addr + max(virt_size, raw_size):
                delta = rva - virt_addr
                if delta < raw_size:
                    return raw_ptr + delta
                return 0
            header += 40
        return 0

    total = 0
    desc_off = rva_to_offset(import_rva)
    while desc_off and desc_off + 20 <= len(blob):
        original_first_thunk, _, _, _, first_thunk = struct.unpack_from(
            "<IIIII", blob, desc_off
        )
        if original_first_thunk == 0 and first_thunk == 0:
            break
        thunk_rva = original_first_thunk or first_thunk
        thunk_off = rva_to_offset(thunk_rva)
        while thunk_off and thunk_off + 8 <= len(blob):
            value = struct.unpack_from("<Q", blob, thunk_off)[0]
            if value == 0:
                break
            total += 1
            thunk_off += 8
        desc_off += 20
        if total > 4096:  # pragma: no cover - guard rail
            break
    return total


# ---------------------------------------------------------------------------
# Corpus writer
# ---------------------------------------------------------------------------


def validate_output_root(root: Path) -> Path:
    resolved = root.expanduser().resolve()
    lowered = str(resolved).lower()
    for forbidden in FORBIDDEN_OUTPUT_HINTS:
        if lowered.startswith(forbidden.lower()):
            raise ValueError(f"refusing to write corpus under protected location: {resolved}")
    if resolved == Path(resolved.anchor):
        raise ValueError("refusing to use a drive root as corpus output")
    return resolved


def generate_corpus(
    output_root: Path,
    counts: dict[str, int],
    seed: int = 2026,
    force: bool = False,
) -> dict[str, object]:
    """Generate an inert synthetic corpus plus its manifest."""

    root = validate_output_root(Path(output_root))
    samples_dir = root / "samples"
    if samples_dir.exists() and any(samples_dir.iterdir()) and not force:
        raise FileExistsError(f"{samples_dir} is not empty; pass --force to regenerate")

    manifest_path = root / "manifest.jsonl"
    summary_path = root / "summary.json"
    samples_dir.mkdir(parents=True, exist_ok=True)

    records: list[dict[str, object]] = []
    index = 0
    for family, count in counts.items():
        if family not in FAMILY_BUILDERS:
            raise KeyError(f"unknown family {family!r}; known: {sorted(FAMILY_BUILDERS)}")
        template_builder = FAMILY_BUILDERS[family]
        for position in range(count):
            template = template_builder()
            local_seed = seed * 1_000_003 + index * 7 + 11
            blob = build_pe(template, local_seed)
            digest = hashlib.sha256(blob).hexdigest()
            path = samples_dir / f"{family}_{index:06d}_{digest[:12]}.bin"
            path.write_bytes(blob)
            records.append(
                {
                    "path": str(path.relative_to(root)),
                    "label": template.label,
                    "family": family,
                    "seed": local_seed,
                    "sha256": digest,
                    "size": len(blob),
                }
            )
            index += 1

    with manifest_path.open("w", encoding="utf-8") as handle:
        for record in records:
            handle.write(json.dumps(record) + "\n")

    labels = Counter(record["label"] for record in records)
    families = Counter(record["family"] for record in records)
    summary = {
        "generator": "everbloom_core.synthetic",
        "safety_marker": SYNTHETIC_MARKER.decode("ascii"),
        "entry_stub": "single RET (0xC3)",
        "output_root": str(root),
        "sample_count": len(records),
        "label_counts": dict(labels),
        "family_counts": dict(families),
        "seed": seed,
    }
    summary_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    return summary


def load_corpus_features(
    manifest_path: Path, now_seconds: int | None = None
) -> tuple[np.ndarray, np.ndarray, list[str], list[str]]:
    """Extract 12-dimensional runtime-style features for every manifest row."""

    manifest_path = Path(manifest_path)
    root = manifest_path.parent
    features: list[np.ndarray] = []
    labels: list[np.ndarray] = []
    families: list[str] = []
    paths: list[str] = []
    for line in manifest_path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        record = json.loads(line)
        blob = (root / str(record["path"])).read_bytes()
        if SYNTHETIC_MARKER not in blob:
            raise ValueError(f"safety marker missing from {record['path']}")
        features.append(extract_features_12(blob, now_seconds=now_seconds))
        labels.append(np.float32(record["label"]))
        families.append(str(record["family"]))
        paths.append(str(record["path"]))
    if not features:
        return (
            np.zeros((0, 12), dtype=np.float32),
            np.zeros((0,), dtype=np.float32),
            [],
            [],
        )
    return (
        np.vstack(features).astype(np.float32),
        np.asarray(labels, dtype=np.float32),
        families,
        paths,
    )
