//! Opt-in integration tests for the real Windows isolation backends.
//!
//! They are ignored by default because they require Windows Sandbox or a
//! usable AppContainer host and must never execute an arbitrary repository
//! binary accidentally. Set `EVERBLOOM_SANDBOX_FIXTURE` to a deliberately
//! controlled `.exe`, `.cmd`, or `.ps1` fixture before running this test.

#[cfg(windows)]
#[test]
#[ignore = "requires EVERBLOOM_SANDBOX_FIXTURE and a configured isolated backend"]
fn controlled_fixture_produces_report_and_cleanup_state() {
    use everbloom_engine::sandbox::run_sandbox;
    use std::path::PathBuf;
    use std::time::Duration;

    let fixture = std::env::var_os("EVERBLOOM_SANDBOX_FIXTURE")
        .map(PathBuf::from)
        .expect("set EVERBLOOM_SANDBOX_FIXTURE to a controlled sample");
    assert!(fixture.is_file(), "fixture must be a regular file");

    let runtime = tokio::runtime::Runtime::new().expect("create integration runtime");
    let report = runtime
        .block_on(run_sandbox(fixture.clone(), Duration::from_secs(45)))
        .expect("sandbox execution should return a structured result");

    assert!(!report.isolation_backend.is_empty());
    assert!(report.isolation_verified, "backend must prove isolation");
    assert!(report.cleanup_verified, "backend must prove cleanup");
    assert!(report.duration_ms > 0);
    assert!(!report.unpacking.status.is_empty());

    // A guest report is either a bounded candidate result or an explicit
    // not_available result; it must never be silently omitted.
    assert!(matches!(
        report.unpacking.status.as_str(),
        "not_available" | "no_candidate" | "candidate" | "recovered_candidate"
    ));
}

#[cfg(not(windows))]
#[test]
fn real_sandbox_integration_is_windows_only() {
    // Keep the test target visible in CI on non-Windows hosts without
    // pretending that a host process is an acceptable isolation substitute.
    assert!(cfg!(not(windows)));
}
