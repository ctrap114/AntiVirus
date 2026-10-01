# ClamAV integration

Everbloom Security can use a local, resident [ClamAV](https://www.clamav.net/) `clamd`
daemon as an independent second-opinion layer. The engine talks to clamd over
its loopback TCP protocol (`zINSTREAM`) instead of linking `libclamav`, so the
Rust engine stays isolated from ClamAV's native ABI and `freshclam` keeps
owning the signature database lifecycle.

## Threat model and boundaries

- The endpoint defaults to `127.0.0.1:3310` and must never be exposed on a
  public interface; clamd's TCP protocol is unauthenticated.
- A `FOUND` verdict is treated like any other engine detection
  (`clamav:<signature>` reason) and participates in caching, enforcement and
  quarantine flows.
- An unavailable clamd is **never** a detection and never blocks the scan
  pipeline. Files scanned while clamd is down stay explicitly incomplete
  instead of being silently marked clean by that layer alone.
- Scans stream file contents to the local daemon. Only enable the layer for
  files you are allowed to process with local tooling.

## Installing clamd (Windows)

1. Install the official ClamAV Windows MSI from clamav.net.
2. Copy `clamd.conf` and `freshclam.conf` samples next to the binaries and set:
   - `TCPSocket 3310`
   - `TCPAddr 127.0.0.1`
   - `MaxScanSize` / `StreamMaxLength` consistent with Everbloom Security limits.
3. Run `freshclam.exe` once to download the signature databases.
4. Start `clamd.exe` (a service or a scheduled task both work).

## Engine configuration

The engine attaches a clamd client at startup and logs one probe line:

```text
clamav layer endpoint=127.0.0.1:3310 available=true clamd ready at ...
```

Environment variables:

| Variable | Default | Meaning |
|---|---|---|
| `EVERBLOOM_CLAMAV` | `false` | Enables the layer for scans (legacy IPC + NDJSON default). |
| `EVERBLOOM_CLAMD_ENDPOINT` | `127.0.0.1:3310` | clamd host:port. |
| `EVERBLOOM_CLAMD_CONNECT_TIMEOUT_MS` | `750` | Connect timeout per attempt. |
| `EVERBLOOM_CLAMD_SCAN_TIMEOUT_MS` | `60000` | Read/write timeout for one scan. |
| `EVERBLOOM_CLAMD_MAX_STREAM_BYTES` | `4 GiB` | Skip files larger than this. |
| `EVERBLOOM_CLAMD_MAX_INFLIGHT` | `2` | Concurrent clamd scans (bounded gate). |
| `EVERBLOOM_CLAMD_RETRY_COOLDOWN_SECS` | `300` | After a failed connect, skip attempts for this long. |

NDJSON deployments may also set `"scan_options": {"enable_clamav": true}` per
request; an explicit request value wins over the environment default.

## Failure behavior

- Failed connections start the retry cooldown so batch scans never pay the
  connect timeout once per file while clamd is down.
- An explicit `VERSION` probe bypasses the cooldown, so UI/diagnostic probes
  can observe a daemon that just came back online.
- Cooldown fast-paths report `clamav unavailable; retrying in Ns` through
  debug logging only; they do not alter scan verdicts.
