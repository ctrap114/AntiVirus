use pyo3::prelude::*;
use pyo3::types::PyDict;
use std::path::Path;

#[cfg(feature = "with_yara")]
use yara::{Compiler, Rules};

#[pyclass]
pub struct YaraRuleEngine {
    #[cfg(feature = "with_yara")]
    rules: Option<Rules>,
}

#[pymethods]
impl YaraRuleEngine {
    #[new]
    pub fn new() -> Self {
        YaraRuleEngine {
            #[cfg(feature = "with_yara")]
            rules: None,
        }
    }

    pub fn load_rules(&mut self, source: &str) -> PyResult<bool> {
        #[cfg(feature = "with_yara")]
        {
            let compiler = Compiler::new().map_err(|e| {
                PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
                    "failed to create YARA compiler: {}",
                    e
                ))
            })?;
            let compiler = compiler.add_rules_file(source).map_err(|e| {
                PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
                    "failed to compile rules: {}",
                    e
                ))
            })?;
            let rules = compiler.compile_rules().map_err(|e| {
                PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
                    "failed to compile rules: {}",
                    e
                ))
            })?;
            self.rules = Some(rules);
            Ok(true)
        }
        #[cfg(not(feature = "with_yara"))]
        {
            Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(
                "YARA support is disabled at build time.",
            ))
        }
    }

    /// Load YARA rules from a string (in-memory)
    pub fn load_rules_from_string(&mut self, rules_text: &str) -> PyResult<bool> {
        #[cfg(feature = "with_yara")]
        {
            let compiler = Compiler::new().map_err(|e| {
                PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
                    "failed to create YARA compiler: {}",
                    e
                ))
            })?;
            let compiler = compiler.add_rules_str(rules_text).map_err(|e| {
                PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
                    "failed to compile rules: {}",
                    e
                ))
            })?;
            let rules = compiler.compile_rules().map_err(|e| {
                PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
                    "failed to compile rules: {}",
                    e
                ))
            })?;
            self.rules = Some(rules);
            Ok(true)
        }
        #[cfg(not(feature = "with_yara"))]
        {
            Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(
                "YARA support is disabled at build time.",
            ))
        }
    }

    /// Scan a byte buffer and return matches as a Python dict
    pub fn scan_bytes<'py>(&self, py: Python<'py>, buf: &[u8]) -> PyResult<Bound<'py, PyDict>> {
        #[cfg(feature = "with_yara")]
        {
            if let Some(rules) = &self.rules {
                let matches = rules.scan_mem(buf, 10).map_err(|e| {
                    PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
                        "YARA scan failed: {}",
                        e
                    ))
                })?;
                let results = PyDict::new(py);
                results.set_item("count", matches.len())?;
                results.set_item(
                    "matched_rules",
                    matches
                        .iter()
                        .map(|m| m.identifier.to_string())
                        .collect::<Vec<String>>(),
                )?;
                Ok(results)
            } else {
                Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(
                    "no rules loaded",
                ))
            }
        }
        #[cfg(not(feature = "with_yara"))]
        {
            Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(
                "YARA support is disabled at build time.",
            ))
        }
    }
    pub fn scan_path<'py>(&self, py: Python<'py>, path: &str) -> PyResult<Bound<'py, PyDict>> {
        let path_obj = Path::new(path);
        if !path_obj.exists() {
            return Err(PyErr::new::<pyo3::exceptions::PyFileNotFoundError, _>(
                "rule scan path does not exist",
            ));
        }
        #[cfg(feature = "with_yara")]
        {
            if let Some(rules) = &self.rules {
                let matches = rules.scan_file(path, 10).map_err(|e| {
                    PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
                        "YARA scan failed: {}",
                        e
                    ))
                })?;
                let results = PyDict::new(py);
                results.set_item("count", matches.len())?;
                results.set_item(
                    "matched_rules",
                    matches
                        .iter()
                        .map(|m| m.identifier.to_string())
                        .collect::<Vec<String>>(),
                )?;
                Ok(results)
            } else {
                Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(
                    "no rules loaded",
                ))
            }
        }
        #[cfg(not(feature = "with_yara"))]
        {
            Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(
                "YARA support is disabled at build time.",
            ))
        }
    }
}
