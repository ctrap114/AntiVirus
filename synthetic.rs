//! Inert synthetic PE corpus generator for defensive detector evaluation.
//!
//! This is the native counterpart of `python/heliosav_core/synthetic.py`. It
//! builds **data-only** PE images that carry suspicious-looking *static*
//! traits while being guaranteed inert:
//!
//! - the entry point is a single `RET` (`0xC3`) with no other code;
//! - imported names are never resolved because execution stops immediately,
//!   and many templates deliberately use non-existent export names so loading
//!   fails harmlessly;
//! - every artifact embeds the ASCII marker [`SYNTHETIC_MARKER`];
//! - generation refuses to write under protected system locations.
//!
//! The corpus lets HeliosAV train and evaluate its own AI detector without
//! touching real malware. The traits are static decoys, not functional
//! capabilities, and must never be used to evade third-party defenses.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use serde::Serialize;
use sha2::{Digest, Sha256};

pub const SYNTHETIC_MARKER: &[u8] = b"HELIOSAV-SYNTHETIC-CORPUS-NOT-MALWARE";
const DOS_STUB: &[u8] = b"This program cannot be run in DOS mode.\r\r\n$";
const FILE_ALIGNMENT: u32 = 0x200;
const SECTION_ALIGNMENT: u32 = 0x1000;
const HEADER_SIZE: usize = 0x400;

const FORBIDDEN_OUTPUT_PREFIXES: [&str; 4] = [
    "c:\\windows",
    "c:\\program files",
    "c:\\programdata",
    "c:\\users\\default",
];

// ---------------------------------------------------------------------------
// Deterministic RNG (SplitMix64) so generation needs no external crate.
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct Rng {
    state: u64,
}

impl Rng {
    pub fn new(seed: u64) -> Self {
        Self {
            state: seed ^ 0x2545_F491_4F6C_DD1D,
        }
    }

    fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    fn fill_bytes(&mut self, target: &mut [u8]) {
        for chunk in target.chunks_mut(8) {
            let value = self.next_u64().to_le_bytes();
            chunk.copy_from_slice(&value[..chunk.len()]);
        }
    }

    /// Draw one byte where a bounded share of positions are pseudo-random and
    /// the remainder are zero, mirroring the Python "mixed" fill strategy.
    fn mixed_byte(&mut self, random_fraction: f32) -> u8 {
        let draw = (self.next_u64() % 10_000) as f32 / 10_000.0;
        if draw < random_fraction.clamp(0.0, 1.0) {
            (self.next_u64() & 0xFF) as u8
        } else {
            0
        }
    }
}

// ---------------------------------------------------------------------------
// Templates
// ---------------------------------------------------------------------------

#[derive(Clone, Copy)]
pub enum Fill {
    Zeros,
    Random,
    Mixed(f32),
    Ascii,
}

#[derive(Clone, Copy)]
pub enum TimestampMode {
    Recent,
    Zero,
    Ancient,
    Future,
}

#[derive(Clone)]
pub struct SectionSpec {
    name: &'static str,
    virtual_size: usize,
    characteristics: u32,
    fill: Fill,
}

#[derive(Clone, Copy)]
pub struct ImportSpec {
    dll: &'static str,
    functions: &'static [&'static str],
}

#[derive(Clone)]
pub struct PeTemplate {
    pub label: f32,
    pub family: &'static str,
    sections: Vec<SectionSpec>,
    imports: Vec<ImportSpec>,
    tls_present: bool,
    entry_in_last_section: bool,
    timestamp_mode: TimestampMode,
    subsystem: u16,
    overlay_bytes: usize,
}

pub const FAMILY_NAMES: [&str; 7] = [
    "benign_like",
    "packed_like",
    "api_heavy_like",
    "stealth_like",
    "credential_stealer_like",
    "downloader_like",
    "ransomware_like",
];

const COMMON_BENIGN_IMPORTS: [ImportSpec; 2] = [
    ImportSpec {
        dll: "KERNEL32.dll",
        functions: &["CreateFileW", "ReadFile", "CloseHandle", "GetLastError"],
    },
    ImportSpec {
        dll: "api-ms-win-crt-runtime-l1-1-0.dll",
        functions: &["_initterm", "__C_specific_handler"],
    },
];

const SUSPICIOUS_IMPORT_NAMES: [&str; 10] = [
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
];

fn section(name: &'static str, virtual_size: usize, characteristics: u32, fill: Fill) -> SectionSpec {
    SectionSpec {
        name,
        virtual_size,
        characteristics,
        fill,
    }
}

pub fn family_template(family: &str) -> Option<PeTemplate> {
    let template = match family {
        "benign_like" => PeTemplate {
            label: 0.0,
            family: "benign_like",
            sections: vec![
                section(".text", 0x600, 0x6000_0020, Fill::Mixed(0.25)),
                section(".rdata", 0x900, 0x4000_0040, Fill::Ascii),
                section(".data", 0x400, 0xC000_0040, Fill::Zeros),
                section(".rsrc", 0x300, 0x4000_0040, Fill::Ascii),
            ],
            imports: COMMON_BENIGN_IMPORTS.to_vec(),
            tls_present: false,
            entry_in_last_section: false,
            timestamp_mode: TimestampMode::Recent,
            subsystem: 2,
            overlay_bytes: 0,
        },
        "packed_like" => PeTemplate {
            label: 1.0,
            family: "packed_like",
            sections: vec![
                section(".text", 0x200, 0x6000_0020, Fill::Zeros),
                section(".themida", 0x1800, 0xE000_00E0, Fill::Random),
                section(".data", 0x200, 0xC000_0040, Fill::Random),
            ],
            imports: vec![ImportSpec {
                dll: "KERNEL32.dll",
                functions: &["LoadLibraryA", "GetProcAddress", "VirtualProtect"],
            }],
            tls_present: true,
            entry_in_last_section: true,
            timestamp_mode: TimestampMode::Zero,
            subsystem: 3,
            overlay_bytes: 2048,
        },
        "api_heavy_like" => PeTemplate {
            label: 1.0,
            family: "api_heavy_like",
            sections: vec![
                section(".text", 0x800, 0x6000_0020, Fill::Mixed(0.5)),
                section(".rdata", 0xA00, 0x4000_0040, Fill::Mixed(0.35)),
                section(".data", 0x400, 0xC000_0040, Fill::Mixed(0.2)),
            ],
            imports: vec![
                ImportSpec {
                    dll: "advapi32.dll",
                    functions: &SUSPICIOUS_IMPORT_NAMES[..6],
                },
                ImportSpec {
                    dll: "ws2_32.dll",
                    functions: &SUSPICIOUS_IMPORT_NAMES[6..],
                },
                ImportSpec {
                    dll: "user32.dll",
                    functions: &["SetWindowsHookExW", "GetAsyncKeyState"],
                },
                ImportSpec {
                    dll: "wininet.dll",
                    functions: &["InternetOpenW", "HttpSendRequestW"],
                },
            ],
            tls_present: false,
            entry_in_last_section: false,
            timestamp_mode: TimestampMode::Ancient,
            subsystem: 3,
            overlay_bytes: 0,
        },
        "stealth_like" => PeTemplate {
            label: 1.0,
            family: "stealth_like",
            sections: vec![
                section(".flat", 0x2000, 0xE000_00E0, Fill::Random),
                section(".bss", 0xC00, 0xC000_0040, Fill::Mixed(0.6)),
            ],
            imports: Vec::new(),
            tls_present: true,
            entry_in_last_section: true,
            timestamp_mode: TimestampMode::Future,
            subsystem: 3,
            overlay_bytes: 4096,
        },
        "credential_stealer_like" => PeTemplate {
            label: 1.0,
            family: "credential_stealer_like",
            sections: vec![
                section(".text", 0x700, 0x6000_0020, Fill::Mixed(0.35)),
                section(".rdata", 0xB00, 0x4000_0040, Fill::Mixed(0.25)),
                section(".data", 0x400, 0xC000_0040, Fill::Mixed(0.2)),
                section(".rsrc", 0x200, 0x4000_0040, Fill::Ascii),
            ],
            imports: vec![
                ImportSpec {
                    dll: "user32.dll",
                    functions: &["GetAsyncKeyState", "SetWindowsHookExW"],
                },
                ImportSpec {
                    dll: "advapi32.dll",
                    functions: &["RegOpenKeyExW", "RegQueryValueExW", "CryptAcquireContextW"],
                },
                ImportSpec {
                    dll: "KERNEL32.dll",
                    functions: &["VirtualAlloc", "WriteProcessMemory", "ReadProcessMemory"],
                },
                ImportSpec {
                    dll: "ws2_32.dll",
                    functions: &["send", "recv", "connect", "closesocket"],
                },
            ],
            tls_present: true,
            entry_in_last_section: false,
            timestamp_mode: TimestampMode::Future,
            subsystem: 3,
            overlay_bytes: 1536,
        },
        "downloader_like" => PeTemplate {
            label: 1.0,
            family: "downloader_like",
            sections: vec![
                section(".text", 0x800, 0x6000_0020, Fill::Mixed(0.4)),
                section(".rdata", 0xC00, 0x4000_0040, Fill::Mixed(0.3)),
                section(".data", 0x600, 0xC000_0040, Fill::Mixed(0.25)),
                section(".rsrc", 0x300, 0x4000_0040, Fill::Ascii),
            ],
            imports: vec![
                ImportSpec {
                    dll: "urlmon.dll",
                    functions: &["URLDownloadToFileW"],
                },
                ImportSpec {
                    dll: "wininet.dll",
                    functions: &["InternetOpenW", "InternetConnectW", "HttpSendRequestW"],
                },
                ImportSpec {
                    dll: "KERNEL32.dll",
                    functions: &["CreateFileW", "WriteFile", "CloseHandle", "GetTempPathW"],
                },
            ],
            tls_present: false,
            entry_in_last_section: false,
            timestamp_mode: TimestampMode::Ancient,
            subsystem: 3,
            overlay_bytes: 2048,
        },
        "ransomware_like" => PeTemplate {
            label: 1.0,
            family: "ransomware_like",
            sections: vec![
                section(".text", 0x900, 0x6000_0020, Fill::Mixed(0.45)),
                section(".rdata", 0x1000, 0x4000_0040, Fill::Mixed(0.3)),
                section(".data", 0x700, 0xC000_0040, Fill::Mixed(0.3)),
                section(".rsrc", 0x400, 0x4000_0040, Fill::Ascii),
            ],
            imports: vec![
                ImportSpec {
                    dll: "advapi32.dll",
                    functions: &["CryptEncrypt", "CryptAcquireContextW", "RegSetValueExW"],
                },
                ImportSpec {
                    dll: "KERNEL32.dll",
                    functions: &[
                        "FindFirstFileW",
                        "FindNextFileW",
                        "MoveFileW",
                        "DeleteFileW",
                        "GetSystemMetricsW",
                    ],
                },
                ImportSpec {
                    dll: "user32.dll",
                    functions: &["MessageBoxW", "GetWindowTextW"],
                },
            ],
            tls_present: true,
            entry_in_last_section: true,
            timestamp_mode: TimestampMode::Zero,
            subsystem: 3,
            overlay_bytes: 4096,
        },
        _ => return None,
    };
    Some(template)
}

fn align_up(value: usize, alignment: usize) -> usize {
    value.div_ceil(alignment) * alignment
}

fn put_u16(buffer: &mut [u8], offset: usize, value: u16) {
    buffer[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn put_u32(buffer: &mut [u8], offset: usize, value: u32) {
    buffer[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn put_u64(buffer: &mut [u8], offset: usize, value: u64) {
    buffer[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn section_body(spec: &SectionSpec, rng: &mut Rng) -> Vec<u8> {
    let size = spec.virtual_size;
    let mut body = vec![0u8; size];
    match spec.fill {
        Fill::Zeros => {}
        Fill::Random => rng.fill_bytes(&mut body),
        Fill::Mixed(fraction) => {
            for byte in body.iter_mut() {
                *byte = rng.mixed_byte(fraction);
            }
        }
        Fill::Ascii => {
            const WORDS: [&[u8]; 5] = [
                b"kernel32 ",
                b"stdcall ",
                b"offset ",
                b"lea eax ",
                b".debug ",
            ];
            let mut cursor = 0;
            while cursor < size {
                let word = WORDS[(rng.next_u64() % WORDS.len() as u64) as usize];
                let take = word.len().min(size - cursor);
                body[cursor..cursor + take].copy_from_slice(&word[..take]);
                cursor += take;
            }
        }
    }
    body
}

struct ImportBlobPlan<'a> {
    spec: &'a ImportSpec,
    name_rvas: Vec<u32>,
    ilt_offset: usize,
    iat_offset: usize,
}

/// Build descriptors + thunks + hint/name entries inside one flat blob laid
/// out at `rva_base` (the start of `.rdata`):
/// `[(n+1) descriptors][per-dll: hint/names, ILT, IAT][dll names]`.
fn build_import_blob(imports: &[ImportSpec], rva_base: u32) -> (Vec<u8>, u32, u32, u32, u32) {
    const DESCRIPTOR_SIZE: usize = 20;
    let total_dlls = imports.len();
    let mut offset = DESCRIPTOR_SIZE * (total_dlls + 1);

    let mut plan: Vec<ImportBlobPlan> = Vec::with_capacity(total_dlls);
    for spec in imports {
        let mut name_rvas = Vec::with_capacity(spec.functions.len());
        for function in spec.functions {
            name_rvas.push(rva_base + offset as u32);
            offset += 2 + function.len() + 1;
        }
        let ilt_offset = offset;
        offset += 8 * (spec.functions.len() + 1);
        let iat_offset = offset;
        offset += 8 * (spec.functions.len() + 1);
        plan.push(ImportBlobPlan {
            spec,
            name_rvas,
            ilt_offset,
            iat_offset,
        });
    }

    let mut dll_name_offsets = Vec::with_capacity(total_dlls);
    for spec in imports {
        dll_name_offsets.push(rva_base + offset as u32);
        offset += spec.dll.len() + 1;
    }

    let mut blob = vec![0u8; offset];
    let mut iat_start: Option<usize> = None;
    let mut iat_end = 0usize;

    for (index, entry) in plan.iter().enumerate() {
        for (function, name_rva) in entry.spec.functions.iter().zip(&entry.name_rvas) {
            let at = (*name_rva - rva_base) as usize;
            blob[at + 2..at + 2 + function.len()].copy_from_slice(function.as_bytes());
        }
        let thunk_values: Vec<u64> = entry
            .name_rvas
            .iter()
            .map(|rva| *rva as u64)
            .chain(std::iter::once(0))
            .collect();
        for (slot, value) in thunk_values.iter().enumerate() {
            let encoded = value.to_le_bytes();
            let ilt_at = entry.ilt_offset + 8 * slot;
            let iat_at = entry.iat_offset + 8 * slot;
            blob[ilt_at..ilt_at + 8].copy_from_slice(&encoded);
            blob[iat_at..iat_at + 8].copy_from_slice(&encoded);
        }
        let name_at = (dll_name_offsets[index] - rva_base) as usize;
        blob[name_at..name_at + entry.spec.dll.len()]
            .copy_from_slice(entry.spec.dll.as_bytes());

        let descriptor = index * DESCRIPTOR_SIZE;
        put_u32(&mut blob, descriptor, rva_base + entry.ilt_offset as u32);
        put_u32(&mut blob, descriptor + 4, 0);
        put_u32(&mut blob, descriptor + 8, 0);
        put_u32(&mut blob, descriptor + 12, dll_name_offsets[index]);
        put_u32(&mut blob, descriptor + 16, rva_base + entry.iat_offset as u32);

        let span = 8 * thunk_values.len();
        if iat_start.is_none() {
            iat_start = Some(entry.iat_offset);
        }
        iat_end = iat_end.max(entry.iat_offset + span);
    }

    let iat_start = iat_start.unwrap_or(0);
    (
        blob,
        rva_base,
        (DESCRIPTOR_SIZE * (total_dlls + 1)) as u32,
        rva_base + iat_start as u32,
        (iat_end - iat_start) as u32,
    )
}

fn timestamp_value(mode: TimestampMode) -> u32 {
    match mode {
        TimestampMode::Recent => 1_750_000_000,
        TimestampMode::Zero => 0,
        TimestampMode::Ancient => 100_000_000,
        TimestampMode::Future => 3_500_000_000,
    }
}

/// Assemble one inert PE image from a template.
pub fn build_pe(template: &PeTemplate, seed: u64) -> Vec<u8> {
    let mut rng = Rng::new(seed);

    let mut dos = vec![0u8; 0x40];
    dos[0] = b'M';
    dos[1] = b'Z';
    put_u16(&mut dos, 0x02, 0x90);
    put_u16(&mut dos, 0x04, 0x03);
    put_u16(&mut dos, 0x18, 0x40);
    const E_LFANEW: usize = 0x80;
    put_u32(&mut dos, 0x3C, E_LFANEW as u32);

    let mut stub = vec![0u8; E_LFANEW - dos.len()];
    stub[..DOS_STUB.len()].copy_from_slice(DOS_STUB);

    let sections = &template.sections;
    let first_section_raw = align_up(HEADER_SIZE, FILE_ALIGNMENT as usize);

    let mut bodies: Vec<Vec<u8>> =
        sections.iter().map(|s| section_body(s, &mut rng)).collect();
    let raw_sizes: Vec<usize> = bodies
        .iter()
        .map(|body| align_up(body.len(), FILE_ALIGNMENT as usize).max(FILE_ALIGNMENT as usize))
        .collect();
    let mut raw_offsets = Vec::with_capacity(bodies.len());
    let mut current = first_section_raw;
    for size in &raw_sizes {
        raw_offsets.push(current);
        current += size;
    }

    let mut current_rva = align_up(HEADER_SIZE, SECTION_ALIGNMENT as usize);
    let mut rvas = Vec::with_capacity(bodies.len());
    for spec in sections.iter() {
        rvas.push(current_rva);
        current_rva += align_up(spec.virtual_size, SECTION_ALIGNMENT as usize)
            .max(SECTION_ALIGNMENT as usize);
    }
    let text_rva = rvas[0];

    let mut import_rva = 0u32;
    let mut import_size = 0u32;
    let mut iat_rva = 0u32;
    let mut iat_size = 0u32;
    if !template.imports.is_empty() && bodies.len() >= 2 {
        let (blob, dir_rva, dir_size, iat_dir_rva, iat_dir_size) =
            build_import_blob(&template.imports, rvas[1] as u32);
        assert!(
            bodies[1].len() >= blob.len(),
            ".rdata template too small for import table"
        );
        bodies[1][..blob.len()].copy_from_slice(&blob);
        import_rva = dir_rva;
        import_size = dir_size;
        iat_rva = iat_dir_rva;
        iat_size = iat_dir_size;
    }

    let mut tls_descriptor: Vec<u8> = Vec::new();
    let mut tls_dir_rva = 0u32;
    if template.tls_present && bodies.len() >= 2 {
        const IMAGE_BASE: u64 = 0x1400_0000;
        let callbacks_slot_rva = rvas[1] + 0x400;
        let index_slot_rva = rvas[1] + 0x420;
        tls_descriptor = Vec::with_capacity(40);
        tls_descriptor.extend_from_slice(&(IMAGE_BASE + (rvas[1] + 0x440) as u64).to_le_bytes());
        tls_descriptor.extend_from_slice(&(IMAGE_BASE + (rvas[1] + 0x480) as u64).to_le_bytes());
        tls_descriptor.extend_from_slice(&(IMAGE_BASE + index_slot_rva as u64).to_le_bytes());
        tls_descriptor.extend_from_slice(&(IMAGE_BASE + callbacks_slot_rva as u64).to_le_bytes());
        tls_descriptor.extend_from_slice(&0u64.to_le_bytes());
        tls_descriptor.extend_from_slice(&0u32.to_le_bytes());
        tls_dir_rva = (rvas[1] + 0x800) as u32;
        let at = (tls_dir_rva as usize) - rvas[1];
        assert!(
            at + tls_descriptor.len() <= bodies[1].len(),
            ".rdata template too small for TLS directory"
        );
        bodies[1][at..at + tls_descriptor.len()].copy_from_slice(&tls_descriptor);
    }

    // Entry point: a single RET plus the safety marker near the section head.
    let entry_rva = if template.entry_in_last_section {
        let last = bodies.len() - 1;
        bodies[last][0] = 0xC3;
        bodies[last][16..16 + SYNTHETIC_MARKER.len()].copy_from_slice(SYNTHETIC_MARKER);
        rvas[last]
    } else {
        bodies[0][0] = 0xC3;
        bodies[0][16..16 + SYNTHETIC_MARKER.len()].copy_from_slice(SYNTHETIC_MARKER);
        text_rva
    };

    let timestamp = timestamp_value(template.timestamp_mode);

    let mut coff = [0u8; 20];
    put_u16(&mut coff, 0, 0x8664);
    put_u16(&mut coff, 2, sections.len() as u16);
    put_u32(&mut coff, 4, timestamp);
    put_u32(&mut coff, 8, 0);
    put_u32(&mut coff, 12, 0);
    put_u16(&mut coff, 16, 240); // SizeOfOptionalHeader (PE32+)
    put_u16(&mut coff, 18, 0x0022); // EXECUTABLE_IMAGE | LARGE_ADDRESS_AWARE

    let size_of_image = align_up(current_rva, SECTION_ALIGNMENT as usize) as u32;
    let code_size = raw_sizes[0] as u32;
    let initialized: u32 = raw_sizes[1..].iter().map(|v| *v as u32).sum();

    let mut optional = vec![0u8; 240];
    put_u16(&mut optional, 0, 0x20B);
    optional[2] = 14; // linker major
    optional[3] = 0;
    put_u32(&mut optional, 4, code_size);
    put_u32(&mut optional, 8, initialized);
    put_u32(&mut optional, 12, 0);
    put_u32(&mut optional, 16, entry_rva as u32);
    put_u32(&mut optional, 20, text_rva as u32);
    put_u64(&mut optional, 24, 0x1400_0000); // ImageBase
    put_u32(&mut optional, 32, SECTION_ALIGNMENT);
    put_u32(&mut optional, 36, FILE_ALIGNMENT);
    put_u16(&mut optional, 40, 6);
    put_u16(&mut optional, 42, 0);
    put_u16(&mut optional, 44, 6);
    put_u16(&mut optional, 46, 0);
    put_u32(&mut optional, 48, HEADER_SIZE as u32);
    put_u32(&mut optional, 56, size_of_image);
    put_u16(&mut optional, 60, template.subsystem);
    put_u16(&mut optional, 62, 0x160); // DllCharacteristics
    put_u64(&mut optional, 64, 0x100_000);
    put_u64(&mut optional, 72, 0x1000);
    put_u64(&mut optional, 80, 0x100_000);
    put_u64(&mut optional, 88, 0x1000);
    put_u32(&mut optional, 108, 16); // NumberOfRvaAndSizes

    let dir_base = 112usize;
    if import_size > 0 {
        put_u32(&mut optional, dir_base + 8, import_rva);
        put_u32(&mut optional, dir_base + 12, import_size);
        put_u32(&mut optional, dir_base + 12 * 8, iat_rva);
        put_u32(&mut optional, dir_base + 12 * 8 + 4, iat_size);
    }
    if !tls_descriptor.is_empty() {
        put_u32(&mut optional, dir_base + 9 * 8, tls_dir_rva);
        put_u32(
            &mut optional,
            dir_base + 9 * 8 + 4,
            tls_descriptor.len() as u32,
        );
    }

    let mut section_headers = Vec::with_capacity(sections.len() * 40);
    for index in 0..sections.len() {
        let spec = &sections[index];
        let mut header = [0u8; 40];
        let name_bytes = spec.name.as_bytes();
        let name_len = name_bytes.len().min(8);
        header[..name_len].copy_from_slice(&name_bytes[..name_len]);
        put_u32(&mut header, 8, spec.virtual_size as u32);
        put_u32(&mut header, 12, rvas[index] as u32);
        put_u32(&mut header, 16, raw_sizes[index] as u32);
        put_u32(&mut header, 20, raw_offsets[index] as u32);
        put_u32(&mut header, 36, spec.characteristics);
        section_headers.extend_from_slice(&header);
    }

    let mut head = Vec::new();
    head.extend_from_slice(&dos);
    head.extend_from_slice(&stub);
    head.extend_from_slice(b"PE\0\0");
    head.extend_from_slice(&coff);
    head.extend_from_slice(&optional);
    head.extend_from_slice(&section_headers);

    let mut image = vec![0u8; HEADER_SIZE];
    image[..head.len()].copy_from_slice(&head);

    for index in 0..bodies.len() {
        let pad_target = raw_offsets[index] + raw_sizes[index];
        image.resize(raw_offsets[index], 0);
        image.extend_from_slice(&bodies[index]);
        image.resize(pad_target, 0);
    }

    if template.overlay_bytes > 0 {
        let mut noise = vec![0u8; template.overlay_bytes];
        rng.fill_bytes(&mut noise);
        image.extend_from_slice(&noise);
    }

    assert!(
        contains_subslice(&image, SYNTHETIC_MARKER),
        "synthetic marker missing from generated image"
    );
    image
}

fn contains_subslice(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

// ---------------------------------------------------------------------------
// Corpus writer
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
pub struct CorpusRecord {
    pub path: String,
    pub label: f32,
    pub family: String,
    pub seed: u64,
    pub sha256: String,
    pub size: usize,
}

#[derive(Debug, Serialize)]
pub struct CorpusSummary {
    pub generator: &'static str,
    pub safety_marker: String,
    pub entry_stub: &'static str,
    pub output_root: String,
    pub sample_count: usize,
    pub family_counts: std::collections::BTreeMap<String, usize>,
    pub seed: u64,
}

/// Refuse protected system locations and drive roots as corpus outputs.
pub fn validate_output_root(root: &Path) -> Result<PathBuf, String> {
    let resolved = root
        .canonicalize()
        .unwrap_or_else(|_| root.to_path_buf());
    // Windows canonical paths carry a \\?\ verbatim prefix; strip it before
    // comparing against protected locations.
    let display_path = resolved
        .to_string_lossy()
        .trim_start_matches(r"\\?\")
        .to_string();
    let lowered = display_path.to_ascii_lowercase();
    for forbidden in FORBIDDEN_OUTPUT_PREFIXES {
        if lowered.starts_with(forbidden) {
            return Err(format!(
                "refusing to write corpus under protected location: {}",
                display_path
            ));
        }
    }
    // Drive roots ("c:\", "c:") must never become corpus outputs.
    let trimmed = lowered.trim_end_matches('\\');
    if trimmed.len() <= 2 && trimmed.ends_with(':') {
        return Err(format!(
            "refusing to use a drive root as corpus output: {}",
            display_path
        ));
    }
    Ok(PathBuf::from(&display_path))
}

pub fn generate_corpus(
    output_root: &Path,
    counts: &[(&str, usize)],
    seed: u64,
    force: bool,
) -> Result<(PathBuf, Vec<CorpusRecord>, CorpusSummary), String> {
    let root = validate_output_root(output_root)?;
    let samples_dir = root.join("samples");
    if samples_dir.exists()
        && fs::read_dir(&samples_dir)
            .map(|entries| entries.count() > 0)
            .unwrap_or(false)
        && !force
    {
        return Err(format!(
            "{} is not empty; pass force to regenerate",
            samples_dir.display()
        ));
    }
    if force && samples_dir.exists() {
        // Drop any partially-written or orphaned sample files so the new
        // corpus replaces the old one instead of piling up stale artifacts.
        fs::remove_dir_all(&samples_dir).map_err(|error| error.to_string())?;
    }

    fs::create_dir_all(&samples_dir).map_err(|error| error.to_string())?;

    let mut records: Vec<CorpusRecord> = Vec::new();
    let mut family_counts = std::collections::BTreeMap::new();
    let mut index: u64 = 0;
    for (family, count) in counts {
        let template = family_template(family)
            .ok_or_else(|| format!("unknown family {family:?}; known: {:?}", FAMILY_NAMES))?;
        for _ in 0..*count {
            let local_seed = seed
                .wrapping_mul(1_000_003)
                .wrapping_add(index.wrapping_mul(7))
                .wrapping_add(11);
            let blob = build_pe(&template, local_seed);
            let digest = Sha256::digest(&blob);
            let digest_hex = hex::encode(digest);
            let file_name = format!("{}_{}_{}.bin", family, format_args!("{index:06}"), &digest_hex[..12]);
            let path = samples_dir.join(file_name);
            fs::write(&path, &blob).map_err(|error| error.to_string())?;
            *family_counts.entry(family.to_string()).or_insert(0usize) += 1;
            records.push(CorpusRecord {
                path: path
                    .strip_prefix(&root)
                    .unwrap_or(&path)
                    .to_string_lossy()
                    .replace('\\', "/"),
                label: template.label,
                family: family.to_string(),
                seed: local_seed,
                sha256: digest_hex,
                size: blob.len(),
            });
            index += 1;
        }
    }

    let manifest_path = root.join("manifest.jsonl");
    let mut manifest = fs::File::create(&manifest_path).map_err(|error| error.to_string())?;
    for record in &records {
        writeln!(manifest, "{}", serde_json::to_string(record).map_err(|e| e.to_string())?)
            .map_err(|error| error.to_string())?;
    }

    let summary = CorpusSummary {
        generator: "heliosav_engine::layers::synthetic",
        safety_marker: String::from_utf8_lossy(SYNTHETIC_MARKER).to_string(),
        entry_stub: "single RET (0xC3)",
        output_root: root.to_string_lossy().to_string(),
        sample_count: records.len(),
        family_counts,
        seed,
    };
    let summary_path = root.join("summary.json");
    fs::write(
        &summary_path,
        serde_json::to_string_pretty(&summary).map_err(|e| e.to_string())?,
    )
    .map_err(|error| error.to_string())?;

    Ok((root, records, summary))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_samples_are_marked_and_inert() {
        for family in FAMILY_NAMES {
            let template = family_template(family).expect("known family");
            let blob = build_pe(&template, 42);

            assert!(
                contains_subslice(&blob, SYNTHETIC_MARKER),
                "safety marker missing for {family}"
            );
            assert_eq!(&blob[..2], b"MZ");

            // Entry point must be a single RET inside a section payload.
            let e_lfanew =
                u32::from_le_bytes([blob[0x3c], blob[0x3d], blob[0x3e], blob[0x3f]]) as usize;
            assert_eq!(&blob[e_lfanew..e_lfanew + 4], b"PE\0\0");
            let opt = e_lfanew + 4 + 20;
            let entry = u32::from_le_bytes([
                blob[opt + 16],
                blob[opt + 17],
                blob[opt + 18],
                blob[opt + 19],
            ]);
            let section_table = opt + 240;
            let count =
                u16::from_le_bytes([blob[e_lfanew + 6], blob[e_lfanew + 7]]) as usize;
            let mut stub_found = false;
            for index in 0..count {
                let header = section_table + 40 * index;
                let va = u32::from_le_bytes([
                    blob[header + 12],
                    blob[header + 13],
                    blob[header + 14],
                    blob[header + 15],
                ]) as u64;
                let raw_size = u32::from_le_bytes([
                    blob[header + 16],
                    blob[header + 17],
                    blob[header + 18],
                    blob[header + 19],
                ]) as u64;
                let raw_ptr = u32::from_le_bytes([
                    blob[header + 20],
                    blob[header + 21],
                    blob[header + 22],
                    blob[header + 23],
                ]) as usize;
                if va <= entry as u64 && (entry as u64) < va + raw_size.max(1) {
                    assert_eq!(
                        blob[raw_ptr + (entry as usize - va as usize)],
                        0xC3,
                        "entry must stay RET for {family}"
                    );
                    stub_found = true;
                    break;
                }
            }
            assert!(stub_found, "entry RVA did not map into any section: {family}");
        }
    }

    #[test]
    fn generation_is_deterministic_per_seed() {
        let template = family_template("packed_like").unwrap();
        let first = build_pe(&template, 7);
        let second = build_pe(&template, 7);
        let other = build_pe(&template, 8);
        assert_eq!(first, second);
        assert_ne!(first, other);
    }

    #[test]
    fn families_carry_distinct_static_traits() {
        use crate::layers::ai::AiModel;
        let benign = AiModel::extract_features(&build_pe(&family_template("benign_like").unwrap(), 5));
        let packed = AiModel::extract_features(&build_pe(&family_template("packed_like").unwrap(), 5));
        let stealth = AiModel::extract_features(&build_pe(&family_template("stealth_like").unwrap(), 5));

        assert_eq!(benign[3], 0.0, "benign family has no TLS");
        assert!(
            packed[3] == 1.0 && stealth[3] == 1.0,
            "packed/stealth carry TLS"
        );
        assert!(
            stealth[10] > benign[10],
            "stealth entropy {} must exceed benign {}",
            stealth[10],
            benign[10]
        );
        assert_eq!(benign[2] > 0.0, true, "benign parses imports");
    }

    #[test]
    fn refuses_protected_output_locations() {
        for forbidden in [
            "C:\\Windows\\Temp\\corpus",
            "c:\\program files\\x",
            "C:\\",
        ] {
            assert!(
                validate_output_root(Path::new(forbidden)).is_err(),
                "must refuse {forbidden}"
            );
        }
        let allowed = std::env::temp_dir().join("heliosav_synthetic_ok");
        assert!(validate_output_root(&allowed).is_ok());
    }

    #[test]
    fn corpus_writer_emits_manifest_and_summary() {
        let root = std::env::temp_dir().join(format!("heliosav_corpus_test_{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let (root, records, summary) =
            generate_corpus(&root, &[("benign_like", 1), ("packed_like", 1)], 99, false)
                .expect("generate");
        assert_eq!(records.len(), 2);
        assert_eq!(summary.sample_count, 2);
        let manifest = root.join("manifest.jsonl");
        let content = fs::read_to_string(&manifest).expect("manifest");
        assert_eq!(content.lines().count(), 2);
        for record in &records {
            let bytes = fs::read(root.join(&record.path)).expect("sample file");
            assert!(contains_subslice(&bytes, SYNTHETIC_MARKER));
        }
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn writer_refuses_to_overwrite_without_force() {
        let root =
            std::env::temp_dir().join(format!("heliosav_corpus_force_{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        generate_corpus(&root, &[("benign_like", 1)], 1, false).expect("first run");
        let second = generate_corpus(&root, &[("benign_like", 1)], 1, false);
        assert!(second.is_err(), "second run without force must fail");
        let third = generate_corpus(&root, &[("benign_like", 1)], 1, true);
        assert!(third.is_ok(), "force regeneration must succeed");
        let _ = fs::remove_dir_all(&root);
    }
}
