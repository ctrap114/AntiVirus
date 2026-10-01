use pyo3::prelude::*;
use pyo3::types::PyModule;

mod rust_cache;
mod rust_feature_extractor;
mod rust_fs_monitor;
mod rust_pattern_matcher;
mod rust_pe_parser;
mod rust_rule_engine;
mod rust_sandbox_queue;
mod rust_scan_pipeline;
mod rust_win_api;

#[pymodule]
fn libeverbloom_rs(_py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<rust_pe_parser::PeParser>()?;
    m.add_class::<rust_feature_extractor::FeatureExtractor>()?;
    m.add_class::<rust_rule_engine::YaraRuleEngine>()?;
    m.add_class::<rust_pattern_matcher::PatternMatcher>()?;
    m.add_class::<rust_cache::ShardedLruCache>()?;
    m.add_class::<rust_fs_monitor::FsMonitor>()?;
    m.add_class::<rust_win_api::WinApi>()?;
    m.add_class::<rust_scan_pipeline::ScanPipeline>()?;
    m.add_class::<rust_sandbox_queue::SandboxQueue>()?;
    Ok(())
}
