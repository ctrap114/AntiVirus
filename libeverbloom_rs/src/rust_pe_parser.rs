use pelite::pe32::{Pe as Pe32, PeFile as PeFile32};
use pelite::pe64::{Pe as Pe64, PeFile as PeFile64};
use pyo3::prelude::*;
use pyo3::types::PyDict;
use std::fs::File;
use std::io::Read;

#[pyclass]
pub struct PeParser {}

#[pymethods]
impl PeParser {
    #[new]
    pub fn new() -> Self {
        PeParser {}
    }

    pub fn parse_file<'py>(&self, py: Python<'py>, path: &str) -> PyResult<Bound<'py, PyDict>> {
        let mut file = File::open(path).map_err(|err| {
            PyErr::new::<pyo3::exceptions::PyIOError, _>(format!("failed to open file: {}", err))
        })?;
        let mut buffer = Vec::new();
        file.read_to_end(&mut buffer).map_err(|err| {
            PyErr::new::<pyo3::exceptions::PyIOError, _>(format!("failed to read file: {}", err))
        })?;

        let metadata = PyDict::new(py);
        let sections_list = PyDict::new(py);

        // pelite exposes separate PE32 and PE32+ views. Try the native 64-bit
        // layout first, then fall back to the 32-bit optional header instead of
        // rejecting valid x86 executables.
        if let Ok(pe) = PeFile64::from_bytes(&buffer) {
            let dos_header = pe.dos_header();
            let optional_header = pe.optional_header();
            let sections = pe.section_headers();
            metadata.set_item("bitness", 64)?;
            metadata.set_item("machine", format!("0x{:x}", dos_header.e_magic))?;
            metadata.set_item("image_base", optional_header.ImageBase)?;
            metadata.set_item("entry_point", optional_header.AddressOfEntryPoint)?;
            metadata.set_item("section_count", sections.iter().count())?;
            for section in sections.iter() {
                let section_name = String::from_utf8_lossy(&section.Name)
                    .trim_end_matches('\0')
                    .to_string();
                let section_info = PyDict::new(py);
                section_info.set_item("name", section_name.clone())?;
                section_info.set_item("virtual_size", section.VirtualSize)?;
                section_info.set_item("virtual_address", section.VirtualAddress)?;
                section_info.set_item("characteristics", section.Characteristics)?;
                sections_list.set_item(section_name, section_info)?;
            }
        } else {
            let pe = PeFile32::from_bytes(&buffer).map_err(|err| {
                PyErr::new::<pyo3::exceptions::PyValueError, _>(format!(
                    "PE32/PE32+ parse failed: {}",
                    err
                ))
            })?;
            let dos_header = pe.dos_header();
            let optional_header = pe.optional_header();
            let sections = pe.section_headers();
            metadata.set_item("bitness", 32)?;
            metadata.set_item("machine", format!("0x{:x}", dos_header.e_magic))?;
            metadata.set_item("image_base", optional_header.ImageBase)?;
            metadata.set_item("entry_point", optional_header.AddressOfEntryPoint)?;
            metadata.set_item("section_count", sections.iter().count())?;
            for section in sections.iter() {
                let section_name = String::from_utf8_lossy(&section.Name)
                    .trim_end_matches('\0')
                    .to_string();
                let section_info = PyDict::new(py);
                section_info.set_item("name", section_name.clone())?;
                section_info.set_item("virtual_size", section.VirtualSize)?;
                section_info.set_item("virtual_address", section.VirtualAddress)?;
                section_info.set_item("characteristics", section.Characteristics)?;
                sections_list.set_item(section_name, section_info)?;
            }
        }
        metadata.set_item("sections", sections_list)?;
        Ok(metadata)
    }
}
