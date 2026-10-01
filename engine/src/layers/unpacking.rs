//! Bounded, non-executing unpacking and de-obfuscation assessment.
//!
//! This module never invokes a sample, loads a decoded image, or writes a
//! decoded payload to disk. It only recognizes common packer markers and
//! decodes small candidate strings/headers in memory so the heuristic layer
//! can correlate them with other evidence.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PackerFamily {
    Upx,
    Aspack,
    Themida,
    VmProtect,
    Generic,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnpackingAssessment {
    pub packer: Option<PackerFamily>,
    pub packer_confidence: u8,
    pub decoded_string_count: usize,
    pub decoded_payload_count: usize,
    pub indicators: Vec<String>,
}

impl UnpackingAssessment {
    pub fn score(&self) -> f32 {
        let mut score: f32 = if self.packer.is_some() { 0.15 } else { 0.0 };
        if self.decoded_string_count > 0 {
            score += 0.15;
        }
        if self.decoded_payload_count > 0 {
            score += 0.65;
        }
        score.clamp(0.0, 1.0)
    }
}

const MAX_HEADER_SCAN_BYTES: usize = 8 * 1024 * 1024;
const MAX_BASE64_CANDIDATES: usize = 64;
const MAX_BASE64_TOKEN_BYTES: usize = 4096;
const MAX_DECODED_BYTES: usize = 1024 * 1024;

pub fn assess_unpacking(data: &[u8]) -> UnpackingAssessment {
    let scan = &data[..data.len().min(MAX_HEADER_SCAN_BYTES)];
    let (packer, packer_confidence, mut indicators) = detect_packer(scan);
    let (decoded_string_count, decoded_payload_count) =
        inspect_encoded_candidates(scan, &mut indicators);
    let mut assessment = UnpackingAssessment {
        packer,
        packer_confidence,
        decoded_string_count,
        decoded_payload_count,
        indicators,
    };
    if assessment.decoded_payload_count > 0 {
        assessment
            .indicators
            .push("unpacking_decoded_embedded_pe".to_string());
        // Corroboration signal for the static `embedded_payload` rulebook
        // entry: a successfully decoded nested image is stronger evidence
        // than a raw MZ marker alone.
        assessment.indicators.push(format!(
            "embedded_payload_decoded:{}",
            assessment.decoded_payload_count
        ));
    }
    assessment
}

fn detect_packer(data: &[u8]) -> (Option<PackerFamily>, u8, Vec<String>) {
    let mut indicators = Vec::new();
    let detect = |needles: &[&[u8]]| needles.iter().any(|needle| contains_ascii(data, needle));

    if detect(&[b"UPX0", b"UPX1", b"UPX!"]) {
        indicators.push("packer_detected:upx".to_string());
        return (Some(PackerFamily::Upx), 95, indicators);
    }
    if detect(&[b"ASPack", b".aspack", b".adata"]) {
        indicators.push("packer_detected:aspack".to_string());
        return (Some(PackerFamily::Aspack), 90, indicators);
    }
    if detect(&[b"Themida", b".themida"]) {
        indicators.push("packer_detected:themida".to_string());
        return (Some(PackerFamily::Themida), 90, indicators);
    }
    if detect(&[b"VMProtect", b".vmp0", b".vmp1"]) {
        indicators.push("packer_detected:vmprotect".to_string());
        return (Some(PackerFamily::VmProtect), 90, indicators);
    }
    (None, 0, indicators)
}

fn inspect_encoded_candidates(data: &[u8], indicators: &mut Vec<String>) -> (usize, usize) {
    let mut strings = 0usize;
    let mut payloads = 0usize;
    let mut candidates = 0usize;
    let mut start = None;

    for index in 0..=data.len() {
        let valid = index < data.len() && is_base64_byte(data[index]);
        if valid && start.is_none() {
            start = Some(index);
        }
        if (!valid || index == data.len()) && start.is_some() {
            let begin = start.take().unwrap_or(index);
            let length = index.saturating_sub(begin);
            if (24..=MAX_BASE64_TOKEN_BYTES).contains(&length) && candidates < MAX_BASE64_CANDIDATES
            {
                candidates += 1;
                if let Some(decoded) = decode_base64(&data[begin..index]) {
                    if looks_like_pe(&decoded) {
                        payloads += 1;
                        indicators.push("base64_obfuscated_pe".to_string());
                    } else if looks_like_interesting_text(&decoded) {
                        strings += 1;
                    }
                }
            }
        }
    }

    let (xor_payloads, xor_strings) = inspect_single_byte_xor(data, indicators);
    (strings + xor_strings, payloads + xor_payloads)
}

fn inspect_single_byte_xor(data: &[u8], indicators: &mut Vec<String>) -> (usize, usize) {
    let scan = &data[..data.len().min(2 * 1024 * 1024)];
    let mut payloads = 0usize;
    let mut strings = 0usize;
    let mut examined = 0usize;

    for index in 0..scan.len().saturating_sub(0x40) {
        if examined >= 32 {
            break;
        }
        let key = scan[index] ^ b'M';
        if key == 0 || (scan[index + 1] ^ key) != b'Z' {
            continue;
        }
        let mut e_lfanew = [0u8; 4];
        for (offset, byte) in e_lfanew.iter_mut().enumerate() {
            *byte = scan[index + 0x3c + offset] ^ key;
        }
        let pe_offset = u32::from_le_bytes(e_lfanew) as usize;
        let Some(signature_offset) = index.checked_add(pe_offset) else {
            continue;
        };
        if signature_offset + 4 > scan.len() {
            continue;
        }
        let mut signature = [0u8; 4];
        for (offset, byte) in signature.iter_mut().enumerate() {
            *byte = scan[signature_offset + offset] ^ key;
        }
        if signature == *b"PE\0\0" {
            payloads += 1;
            examined += 1;
            indicators.push("xor_obfuscated_pe".to_string());
        }
    }

    // A short XOR text candidate is only counted when it contains a
    // high-value command/network marker after decoding. Random binary data
    // therefore does not become an obfuscation alert by itself.
    for key in 1u8..=u8::MAX {
        if strings >= 8 {
            break;
        }
        let mut decoded = Vec::with_capacity(128);
        for byte in scan.iter().take(128) {
            decoded.push(*byte ^ key);
        }
        if looks_like_interesting_text(&decoded) {
            strings += 1;
            indicators.push("xor_obfuscated_command_or_url".to_string());
        }
    }
    (payloads, strings)
}

fn decode_base64(input: &[u8]) -> Option<Vec<u8>> {
    if input.is_empty() || input.len() % 4 != 0 {
        return None;
    }
    let output_size = input.len() / 4 * 3;
    if output_size > MAX_DECODED_BYTES {
        return None;
    }
    let mut output = Vec::with_capacity(output_size);
    for chunk in input.chunks_exact(4) {
        let values = [
            base64_value(chunk[0])?,
            base64_value(chunk[1])?,
            base64_value(chunk[2])?,
            base64_value(chunk[3])?,
        ];
        output.push((values[0] << 2) | (values[1] >> 4));
        if chunk[2] != b'=' {
            output.push((values[1] << 4) | (values[2] >> 2));
        }
        if chunk[3] != b'=' {
            output.push((values[2] << 6) | values[3]);
        }
    }
    Some(output)
}

fn base64_value(byte: u8) -> Option<u8> {
    match byte {
        b'A'..=b'Z' => Some(byte - b'A'),
        b'a'..=b'z' => Some(byte - b'a' + 26),
        b'0'..=b'9' => Some(byte - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        b'=' => Some(0),
        _ => None,
    }
}

fn is_base64_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/' | b'=')
}

fn looks_like_pe(data: &[u8]) -> bool {
    if data.len() < 0x40 || &data[..2] != b"MZ" {
        return false;
    }
    let e_lfanew = u32::from_le_bytes(data[0x3c..0x40].try_into().unwrap()) as usize;
    e_lfanew.checked_add(4).is_some_and(|end| end <= data.len())
        && &data[e_lfanew..e_lfanew + 4] == b"PE\0\0"
}

fn looks_like_interesting_text(data: &[u8]) -> bool {
    let text = String::from_utf8_lossy(data).to_ascii_lowercase();
    [
        "http://",
        "https://",
        "powershell",
        "cmd.exe",
        "rundll32",
        "regsvr32",
        "appdata",
        "cookie",
    ]
    .iter()
    .any(|marker| text.contains(marker))
}

fn contains_ascii(data: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && data.windows(needle.len()).any(|window| {
            window
                .iter()
                .zip(needle.iter())
                .all(|(left, right)| left.eq_ignore_ascii_case(right))
        })
}

pub fn encode_base64(data: &[u8]) -> Vec<u8> {
    const TABLE: &[u8; 64] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut output = Vec::new();
    for chunk in data.chunks(3) {
        let a = chunk[0];
        let b = *chunk.get(1).unwrap_or(&0);
        let c = *chunk.get(2).unwrap_or(&0);
        output.push(TABLE[(a >> 2) as usize]);
        output.push(TABLE[((a << 4 | b >> 4) & 0x3f) as usize]);
        output.push(if chunk.len() > 1 {
            TABLE[((b << 2 | c >> 6) & 0x3f) as usize]
        } else {
            b'='
        });
        output.push(if chunk.len() > 2 {
            TABLE[(c & 0x3f) as usize]
        } else {
            b'='
        });
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognizes_packer_markers_without_unpacking_or_execution() {
        let assessment = assess_unpacking(b"UPX0 UPX1 UPX!");
        assert_eq!(assessment.packer, Some(PackerFamily::Upx));
        assert!(assessment
            .indicators
            .iter()
            .any(|indicator| indicator == "packer_detected:upx"));
    }

    #[test]
    fn detects_base64_embedded_pe_header() {
        let mut payload = vec![0u8; 96];
        payload[0..2].copy_from_slice(b"MZ");
        payload[0x3c..0x40].copy_from_slice(&0x40u32.to_le_bytes());
        payload[0x40..0x44].copy_from_slice(b"PE\0\0");
        let encoded = crate::layers::unpacking::encode_base64(&payload);
        let assessment = assess_unpacking(&encoded);
        assert_eq!(assessment.decoded_payload_count, 1);
        assert!(assessment.score() >= 0.65);
    }
}
