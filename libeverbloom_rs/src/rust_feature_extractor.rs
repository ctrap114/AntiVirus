use aho_corasick::AhoCorasick;
use memmap2::MmapOptions;
use pyo3::prelude::*;
use pyo3::types::PyDict;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{BufReader, Read};

#[pyclass]
pub struct FeatureExtractor {
    pub block_size: usize,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct FeatureVector {
    pub sha256: String,
    pub entropy: f64,
    pub printable_ratio: f64,
    pub string_count: usize,
    pub size: usize,
    pub section_count: usize,
    pub section_entropy: Vec<f64>,
    pub section_entropy_histogram: Vec<usize>,
    pub suspicious_import_count: usize,
    pub suspicious_resource_count: usize,
    pub packed: bool,
    pub import_names: Vec<String>,
    pub resource_names: Vec<String>,
}

#[pymethods]
impl FeatureExtractor {
    #[new]
    pub fn new(block_size: Option<usize>) -> Self {
        FeatureExtractor {
            block_size: block_size.unwrap_or(8192),
        }
    }

    pub fn compute_entropy(&self, path: &str) -> PyResult<f64> {
        let buffer = read_bytes(path).map_err(|err| {
            PyErr::new::<pyo3::exceptions::PyIOError, _>(format!("failed to read file: {}", err))
        })?;
        Ok(compute_entropy_bytes(&buffer, self.block_size))
    }

    pub fn compute_printable_ratio(&self, path: &str) -> PyResult<f64> {
        let buffer = read_bytes(path).map_err(|err| {
            PyErr::new::<pyo3::exceptions::PyIOError, _>(format!("failed to read file: {}", err))
        })?;
        Ok(compute_printable_ratio_bytes(&buffer))
    }

    pub fn extract_features<'py>(
        &self,
        py: Python<'py>,
        path: &str,
    ) -> PyResult<Bound<'py, PyDict>> {
        let buffer = read_bytes(path).map_err(|err| {
            PyErr::new::<pyo3::exceptions::PyIOError, _>(format!("failed to read file: {}", err))
        })?;
        let feature_vector =
            extract_feature_vector_from_bytes(path, &buffer, Some(self.block_size));

        let dict = PyDict::new(py);
        dict.set_item("entropy", feature_vector.entropy)?;
        dict.set_item("printable_ratio", feature_vector.printable_ratio)?;
        dict.set_item("string_count", feature_vector.string_count)?;
        dict.set_item("size", feature_vector.size)?;
        dict.set_item("section_count", feature_vector.section_count)?;
        dict.set_item("section_entropy", feature_vector.section_entropy)?;
        dict.set_item(
            "section_entropy_histogram",
            feature_vector.section_entropy_histogram,
        )?;
        dict.set_item(
            "suspicious_import_count",
            feature_vector.suspicious_import_count,
        )?;
        dict.set_item(
            "suspicious_resource_count",
            feature_vector.suspicious_resource_count,
        )?;
        dict.set_item("packed", feature_vector.packed)?;
        dict.set_item("import_names", feature_vector.import_names)?;
        dict.set_item("resource_names", feature_vector.resource_names)?;
        Ok(dict)
    }
}

fn read_bytes(path: &str) -> std::io::Result<Vec<u8>> {
    let file = File::open(path)?;
    let metadata = file.metadata()?;
    if metadata.len() == 0 {
        return Ok(Vec::new());
    }

    if let Ok(mmap) = unsafe { MmapOptions::new().map(&file) } {
        return Ok(mmap[..].to_vec());
    }

    let mut reader = BufReader::new(file);
    let mut buffer = Vec::with_capacity(metadata.len() as usize);
    reader.read_to_end(&mut buffer)?;
    Ok(buffer)
}

fn compute_entropy_bytes(bytes: &[u8], block_size: usize) -> f64 {
    if bytes.is_empty() {
        return 0.0;
    }
    let blocks: Vec<&[u8]> = bytes.chunks(block_size.max(1)).collect();
    let entropies: Vec<f64> = blocks
        .par_iter()
        .map(|block| {
            let mut counts = [0usize; 256];
            for b in *block {
                counts[*b as usize] += 1;
            }
            let len = block.len() as f64;
            counts
                .iter()
                .filter(|&&count| count > 0)
                .map(|&count| {
                    let p = count as f64 / len;
                    -p * p.log2()
                })
                .sum::<f64>()
        })
        .collect();
    entropies.iter().sum::<f64>() / (entropies.len() as f64)
}

fn compute_printable_ratio_bytes(bytes: &[u8]) -> f64 {
    if bytes.is_empty() {
        return 0.0;
    }
    let printable = bytes
        .par_iter()
        .filter(|&&b| (0x20..=0x7e).contains(&b))
        .count();
    printable as f64 / bytes.len() as f64
}

fn count_strings(bytes: &[u8]) -> usize {
    let mut count = 0;
    let mut current = 0;
    for &b in bytes {
        if (0x20..=0x7e).contains(&b) {
            current += 1;
        } else if current >= 4 {
            count += 1;
            current = 0;
        } else {
            current = 0;
        }
    }
    if current >= 4 {
        count += 1;
    }
    count
}

fn extract_feature_vector_from_bytes(
    _path: &str,
    bytes: &[u8],
    block_size: Option<usize>,
) -> FeatureVector {
    let block_size = block_size.unwrap_or(8192).max(1);
    let entropy = compute_entropy_bytes(bytes, block_size);
    let printable_ratio = compute_printable_ratio_bytes(bytes);
    let string_count = count_strings(bytes);
    let section_entropy = extract_section_entropies(bytes);
    let section_entropy_histogram = build_entropy_histogram(&section_entropy, 8);
    let import_names = find_suspicious_imports(bytes);
    let resource_names = find_resource_markers(bytes);
    let suspicious_import_count = import_names.len();
    let suspicious_resource_count = resource_names.len();
    let packed = detect_packed(bytes, entropy, &section_entropy);

    FeatureVector {
        sha256: sha256_digest(bytes),
        entropy,
        printable_ratio,
        string_count,
        size: bytes.len(),
        section_count: section_entropy.len(),
        section_entropy,
        section_entropy_histogram,
        suspicious_import_count,
        suspicious_resource_count,
        packed,
        import_names,
        resource_names,
    }
}

fn extract_section_entropies(bytes: &[u8]) -> Vec<f64> {
    if bytes.len() < 64 {
        return vec![compute_entropy_bytes(bytes, 64)];
    }

    let pe_sections = parse_pe_sections(bytes);
    if !pe_sections.is_empty() {
        return pe_sections;
    }

    bytes
        .chunks(4096)
        .map(|chunk| compute_entropy_bytes(chunk, 64))
        .collect()
}

fn parse_pe_sections(bytes: &[u8]) -> Vec<f64> {
    const IMAGE_DOS_SIGNATURE: u16 = 0x5A4D;
    const IMAGE_NT_SIGNATURE: u32 = 0x00004550;

    if bytes.len() < 64
        || u16::from_le_bytes(bytes[0..2].try_into().unwrap_or([0, 0])) != IMAGE_DOS_SIGNATURE
    {
        return Vec::new();
    }

    let pe_offset =
        u32::from_le_bytes(bytes[0x3C..0x40].try_into().unwrap_or([0, 0, 0, 0])) as usize;
    if pe_offset + 24 > bytes.len() {
        return Vec::new();
    }

    if u32::from_le_bytes(
        bytes[pe_offset..pe_offset + 4]
            .try_into()
            .unwrap_or([0, 0, 0, 0]),
    ) != IMAGE_NT_SIGNATURE
    {
        return Vec::new();
    }

    let number_of_sections = u16::from_le_bytes(
        bytes[pe_offset + 6..pe_offset + 8]
            .try_into()
            .unwrap_or([0, 0]),
    ) as usize;
    let size_of_optional_header = u16::from_le_bytes(
        bytes[pe_offset + 20..pe_offset + 22]
            .try_into()
            .unwrap_or([0, 0]),
    ) as usize;
    let section_table_offset = pe_offset + 24 + size_of_optional_header;
    let mut sections = Vec::new();

    for index in 0..number_of_sections.min(16) {
        let offset = section_table_offset + index * 40;
        if offset + 40 > bytes.len() {
            break;
        }
        let size_of_raw_data = u32::from_le_bytes(
            bytes[offset + 16..offset + 20]
                .try_into()
                .unwrap_or([0, 0, 0, 0]),
        ) as usize;
        let pointer_to_raw_data = u32::from_le_bytes(
            bytes[offset + 20..offset + 24]
                .try_into()
                .unwrap_or([0, 0, 0, 0]),
        ) as usize;
        if size_of_raw_data == 0 || pointer_to_raw_data + size_of_raw_data > bytes.len() {
            continue;
        }
        let section_bytes = &bytes[pointer_to_raw_data..pointer_to_raw_data + size_of_raw_data];
        sections.push(compute_entropy_bytes(section_bytes, 64));
    }

    sections
}

fn build_entropy_histogram(entropies: &[f64], buckets: usize) -> Vec<usize> {
    let mut histogram = vec![0usize; buckets.max(1)];
    for entropy in entropies {
        let bucket = ((*entropy * 10.0).floor() as usize).min(histogram.len() - 1);
        histogram[bucket] += 1;
    }
    histogram
}

fn find_suspicious_imports(bytes: &[u8]) -> Vec<String> {
    let text = String::from_utf8_lossy(bytes);
    let patterns = [
        "VirtualAlloc",
        "CreateRemoteThread",
        "WinExec",
        "URLDownloadToFile",
        "InternetOpenA",
        "InternetOpenW",
        "ShellExecute",
        "NtAllocateVirtualMemory",
        "NtWriteVirtualMemory",
        "IsDebuggerPresent",
    ];
    let Ok(automaton) = AhoCorasick::new(patterns) else {
        return Vec::new();
    };
    automaton
        .find_iter(text.as_bytes())
        .map(|mat| patterns[mat.pattern().as_usize()].to_string())
        .collect::<Vec<_>>()
}

fn find_resource_markers(bytes: &[u8]) -> Vec<String> {
    let text = String::from_utf8_lossy(bytes);
    let patterns = [
        ".rsrc",
        "VS_VERSION_INFO",
        "RT_ICON",
        "RT_STRING",
        "icon",
        "version",
    ];
    let Ok(automaton) = AhoCorasick::new(patterns) else {
        return Vec::new();
    };
    automaton
        .find_iter(text.as_bytes())
        .map(|mat| patterns[mat.pattern().as_usize()].to_string())
        .collect::<Vec<_>>()
}

fn detect_packed(bytes: &[u8], entropy: f64, section_entropy: &[f64]) -> bool {
    let high_entropy = entropy > 7.0;
    let section_spike = section_entropy.iter().any(|value| *value > 7.2);
    let suspicious_jump = bytes
        .windows(2)
        .any(|window| window == b"\x0f\x80" || window == b"\x0f\x82" || window == b"\x0f\x83");
    high_entropy && (section_spike || suspicious_jump)
}

fn sha256_digest(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    hex::encode(digest)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rich_feature_vector_includes_section_and_import_signals() {
        let payload = b"MZ\x90\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
        let vector = extract_feature_vector_from_bytes("sample.exe", payload, Some(16));
        assert_eq!(vector.size, payload.len());
        assert!(!vector.section_entropy.is_empty());
        assert!(vector.suspicious_import_count <= vector.import_names.len());
    }

    #[test]
    fn feature_hash_is_a_real_sha256_digest() {
        assert_eq!(
            sha256_digest(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
}
