Cuckoo Sandbox integration
==========================

Overview
--------
This document describes a recommended asynchronous integration pattern between Everbloom Security and a Cuckoo Sandbox deployment. The goal is to submit suspicious samples to a sandbox, receive a callback or poll for results, and merge the behavioral summary back into Everbloom Security's `ScanResponse` or incident store.

Design
------
- Submission: Everbloom Security posts samples (multipart/form-data) to the Cuckoo API `/tasks/create/file` endpoint.
- Tracking: Cuckoo returns a `task_id`; Everbloom Security stores mapping: `task_id -> scan_id` in a small queue DB (e.g., SQLite or Redis).
- Results: Everbloom Security either polls `/tasks/view/<task_id>` or subscribes to a webhook that Cuckoo calls when analysis completes.
- Post-processing: When a report is available, fetch `/reports/get/<report_id>` (or `/tasks/report/<task_id>`) and extract the behavior summary (processes, network, dropped files, etc.).

Queueing & Scaling
------------------
- Use a small persistent queue to track outstanding tasks (Redis list or SQLite table).
- Worker service (async Python `asyncio` + `aiohttp`) pulls tasks, submits to Cuckoo, stores the returned `task_id`.
- A separate result worker polls or receives webhook calls and then writes summarized results back to Everbloom Security (via IPC or direct db).

Security & Hardening
--------------------
- Ensure sample transport is over TLS and authenticated (Cuckoo API key).
- Sanitize filenames and do not execute untrusted shell commands.
- Rate-limit submissions to the sandbox to avoid resource exhaustion.

Example fields to merge into `ScanResponse`
-------------------------------------------
- `sanbox_status`: pending | completed | error
- `sandbox_report_url`: URL to the full report
- `behavior_summary`: short text summary
- `processes`, `network_connections`, `dropped_files` (as arrays)

Example workflow
----------------
1. Everbloom Security detects suspicious sample and writes it to disk.
2. Everbloom Security queues the sample path in `sandbox_queue`.
3. `sandbox_worker` picks queue entry, uploads to Cuckoo, receives `task_id`.
4. `sandbox_worker` updates `ScanResponse` with `sandbox_status: pending` and stores mapping.
5. On completion, `result_worker` fetches report, extracts summary, and updates the `ScanResponse` with `sandbox_status: completed` and `sandbox_report_url`.

References
----------
- Cuckoo API docs: https://cuckoosandbox.org/
- Example Cuckoo client: https://github.com/cuckoosandbox/cuckoo/tree/master/utils
