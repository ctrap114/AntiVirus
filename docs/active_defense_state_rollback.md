# Everbloom Security Active Defense Extension

This document describes the new process-level state machine, rollback planning, and Windows data source extension added to the Everbloom Security engine.

## New Architecture Components

### Process-State Machine

- Implemented in `engine/src/layers/process_state.rs`.
- Tracks per-process state transitions from observed sandbox/behavior events.
- States:
  - `Observed`
  - `Monitored`
  - `Suspicious`
  - `Instrumented`
  - `Malicious`
  - `Blocked`
- Updates using `BehaviorEventKind` and the sandbox target PID.
- Stored in scan results via `ScanResult.process_state`.

### Rollback Planner

- Implemented in `engine/src/layers/rollback.rs`.
- Generates a `RollbackRecord` from sandbox artifacts.
- Records file and registry undo actions plus process kill recommendations.
- Attached to scan results via `ScanResult.rollback_record`.

### Real Windows ETW/Minifilter Data Source

- `sandbox_monitor/src/lib.rs` now enables a real Windows kernel ETW session with kernel providers for:
  - Process events
  - File I/O
  - Network activity
  - Registry operations
- Added placeholder `monitor_minifilter` entrypoint for future Windows minifilter integration.
- `engine/src/sandbox.rs` preserves the sandbox target PID and injects it into behavior event derivation.

## Integration Points

- `engine/src/scanner.rs` now uses sandbox telemetry to:
  - derive behavior events
  - update the process state machine
  - attach rollback metadata
- Behavior event derivation now carries `process_id` to tie events back to the monitored process.

## Notes

- The current ETW implementation starts a real Windows kernel trace session and records live trace heartbeats.
- The minifilter path is available as a stub interface and can be extended to consume file system and registry callback data from a Windows minifilter driver.
