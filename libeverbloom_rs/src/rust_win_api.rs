use pyo3::prelude::*;
use pyo3::types::PyDict;
use std::ffi::OsStr;
use std::iter::once;
use std::os::windows::ffi::OsStrExt;
use windows::core::PCWSTR;
use windows::Win32::Foundation::ERROR_SUCCESS;
use windows::Win32::System::Registry::{
    RegCloseKey, RegOpenKeyExW, RegQueryValueExW, HKEY, HKEY_LOCAL_MACHINE, KEY_READ,
};

const MAX_REGISTRY_VALUE_SIZE: u32 = 16 * 1024 * 1024;

#[pyclass]
pub struct WinApi {}

#[pymethods]
impl WinApi {
    #[new]
    pub fn new() -> Self {
        WinApi {}
    }

    pub fn query_registry_value<'py>(
        &self,
        py: Python<'py>,
        hive: &str,
        key_path: &str,
        value_name: &str,
    ) -> PyResult<Bound<'py, PyDict>> {
        let root = match hive.to_uppercase().as_str() {
            "HKLM" | "HKEY_LOCAL_MACHINE" => HKEY_LOCAL_MACHINE,
            _ => {
                return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(
                    "unsupported registry hive",
                ))
            }
        };

        let key_wide: Vec<u16> = OsStr::new(key_path).encode_wide().chain(once(0)).collect();
        let mut handle = HKEY::default();
        let status =
            unsafe { RegOpenKeyExW(root, PCWSTR(key_wide.as_ptr()), 0, KEY_READ, &mut handle) };

        if status != ERROR_SUCCESS {
            return Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
                "failed to open registry key: {}",
                status.0
            )));
        }

        let value_wide: Vec<u16> = OsStr::new(value_name)
            .encode_wide()
            .chain(once(0))
            .collect();
        let mut data_type = 0u32;
        let mut data_len = 0u32;
        let size_result = unsafe {
            RegQueryValueExW(
                handle,
                PCWSTR(value_wide.as_ptr()),
                None,
                Some(&mut data_type as *mut u32 as *mut _),
                None,
                Some(&mut data_len),
            )
        };

        if size_result != ERROR_SUCCESS {
            unsafe { RegCloseKey(handle) };
            return Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
                "failed to query registry value size: {}",
                size_result.0
            )));
        }

        if data_len > MAX_REGISTRY_VALUE_SIZE {
            unsafe { RegCloseKey(handle) };
            return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(format!(
                "registry value is too large: {} bytes",
                data_len
            )));
        }

        let mut buffer = vec![0u8; data_len as usize];
        let result = unsafe {
            RegQueryValueExW(
                handle,
                PCWSTR(value_wide.as_ptr()),
                None,
                Some(&mut data_type as *mut u32 as *mut _),
                Some(buffer.as_mut_ptr()),
                Some(&mut data_len),
            )
        };
        if result != ERROR_SUCCESS {
            unsafe { RegCloseKey(handle) };
            return Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
                "failed to query registry value: {}",
                result.0
            )));
        }

        buffer.truncate(data_len as usize);
        let value_str = if matches!(data_type, 1 | 2 | 7) && buffer.len() % 2 == 0 {
            let wide = buffer
                .chunks_exact(2)
                .map(|chunk| u16::from_ne_bytes([chunk[0], chunk[1]]))
                .take_while(|value| *value != 0)
                .collect::<Vec<_>>();
            String::from_utf16_lossy(&wide)
        } else {
            format!("0x{}", hex::encode(&buffer))
        };
        let dict = PyDict::new(py);
        dict.set_item("data", value_str)?;
        dict.set_item("type", data_type)?;

        unsafe { RegCloseKey(handle) };
        Ok(dict)
    }
}
