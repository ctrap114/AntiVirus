use aho_corasick::{AhoCorasick, AhoCorasickBuilder};
use pyo3::prelude::*;
use pyo3::types::PyList;

#[pyclass]
pub struct PatternMatcher {
    automaton: AhoCorasick,
    patterns: Vec<String>,
}

#[pymethods]
impl PatternMatcher {
    #[new]
    pub fn new(patterns: Vec<String>) -> PyResult<Self> {
        let automaton = AhoCorasickBuilder::new()
            .build(patterns.clone())
            .map_err(|error| {
                PyErr::new::<pyo3::exceptions::PyValueError, _>(format!(
                    "failed to build matcher: {error}"
                ))
            })?;
        Ok(PatternMatcher {
            automaton,
            patterns,
        })
    }

    pub fn add_patterns(&mut self, patterns: Vec<String>) -> PyResult<()> {
        let mut combined = self.patterns.clone();
        combined.extend(patterns);
        self.automaton = AhoCorasickBuilder::new()
            .build(combined.clone())
            .map_err(|error| {
                PyErr::new::<pyo3::exceptions::PyValueError, _>(format!(
                    "failed to rebuild matcher: {error}"
                ))
            })?;
        self.patterns = combined;
        Ok(())
    }

    pub fn find_matches<'py>(&self, py: Python<'py>, text: &str) -> PyResult<Bound<'py, PyList>> {
        let mut results = Vec::new();
        for mat in self.automaton.find_iter(text) {
            results.push((mat.pattern().as_usize(), mat.start(), mat.end()));
        }
        PyList::new(py, results)
    }
}
