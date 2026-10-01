use crate::rust_feature_extractor::FeatureExtractor;
use pyo3::prelude::*;
use pyo3::types::PyDict;
use rayon::join;
use std::fs::File;
use std::io::{BufReader, Read};
use std::path::Path;

#[pyclass]
pub struct ScanPipeline {
    extractor: FeatureExtractor,
}

#[pymethods]
impl ScanPipeline {
    #[new]
    pub fn new(block_size: Option<usize>) -> Self {
        ScanPipeline {
            extractor: FeatureExtractor::new(block_size),
        }
    }

    pub fn run_scan<'py>(&self, py: Python<'py>, path: &str) -> PyResult<Bound<'py, PyDict>> {
        let file_path = Path::new(path);
        if !file_path.exists() {
            return Err(PyErr::new::<pyo3::exceptions::PyFileNotFoundError, _>(
                "path does not exist",
            ));
        }

        let mut data = Vec::new();
        let mut reader = BufReader::new(File::open(path).map_err(|err| {
            PyErr::new::<pyo3::exceptions::PyIOError, _>(format!("failed to open file: {}", err))
        })?);
        reader.read_to_end(&mut data).map_err(|err| {
            PyErr::new::<pyo3::exceptions::PyIOError, _>(format!("failed to read file: {}", err))
        })?;

        let (entropy, printable_ratio) = join(
            || self.extractor.compute_entropy(path).unwrap_or(0.0),
            || self.extractor.compute_printable_ratio(path).unwrap_or(0.0),
        );

        let dict = PyDict::new(py);
        dict.set_item("path", path)?;
        dict.set_item("entropy", entropy)?;
        dict.set_item("printable_ratio", printable_ratio)?;
        dict.set_item("size", data.len())?;
        Ok(dict)
    }
}
