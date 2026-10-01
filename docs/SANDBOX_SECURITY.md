# Everbloom Security sandbox security

Everbloom Security never executes an untrusted sample through an unrestricted host
process in production. On Windows, dynamic analysis first tries the built-in
AppContainer + Job Object backend. If that backend cannot be created for the
current machine, the engine tries the optional Windows Sandbox feature. If
both are unavailable, it fails closed and reports `sandbox_unavailable`.

## Isolation policy

The preferred local backend uses a fresh AppContainer profile and Job Object
with:

- no AppContainer network capabilities;
- a restricted token with all removable privileges disabled;
- process creation suspended until the process is assigned to the Job Object;
- child-process-tree termination when the Job Object is closed;
- a 1 GiB per-process and 2 GiB per-job memory ceiling;
- a 32-process active-process ceiling;
- desktop, clipboard, handle, and window-system restrictions;
- no inherited handles;
- only `.exe`, `.com`, and `.scr` targets.

For target types the local backend does not cover, or when its prerequisites
are unavailable, a fresh Windows Sandbox virtual machine is configured with:

- networking disabled;
- virtual GPU disabled;
- clipboard, audio, video, and printer redirection disabled;
- Protected Client enabled;
- one dedicated host input directory mapped read-only;
- no writable host directory;
- a 512 MiB maximum sample size;
- a 4096 MiB Windows Sandbox memory ceiling;
- a 30-second minimum and 10-minute maximum session timeout;
- one sandbox session at a time.

Only `.exe`, `.com`, `.scr`, `.bat`, `.cmd`, `.ps1`, and `.msi` targets are
executed automatically. The sample is first copied to a dedicated temporary
directory, and the original file location is never mapped into the guest.

## Windows setup

Windows Sandbox requires a supported Windows Pro, Enterprise, or Education
edition, hardware virtualization, and the optional
`Containers-DisposableClientVM` Windows feature.

Enable **Windows Sandbox** from **Turn Windows features on or off**, then restart
Windows. After restarting Everbloom Security, the setting
**Enable isolated Windows Sandbox analysis** becomes available under
**Settings > Engine Config**.

## Isolation levels and limitations

`windows_appcontainer_job` is host-level restricted execution, not a VM. It
reduces privileges and storage/network access through Windows security
boundaries, but it does not provide the same kernel boundary as Windows
Sandbox. The report records the backend name and resource controls; operators
should treat the Windows Sandbox fallback as the stronger boundary.

Neither backend maps a writable guest-to-host report directory. The local
backend reports session completion and timeout, but it does not yet export
rich file, registry, or network telemetry. Timeouts and isolation failures
are treated as suspicious. Static hash, YARA, heuristic, and AI layers should
remain the primary detection path.

## Fail-closed guarantees

The engine and the `libeverbloom_rs` `SandboxQueue` use the same priority chain:
local AppContainer + Job Object first, Windows Sandbox second, and no
direct-host execution fallback. Non-Windows builds report that no secure
backend is available. A queue report is considered trustworthy only when both
`isolation_verified` and `cleanup_verified` are true.

Before launch, the backend validates the canonical sample path, regular-file
type, size limit, supported extension, staged copy size, trusted security
objects, and (for the fallback) the generated `.wsb` policy. The local backend
creates the process suspended and only resumes it after assigning the process
to its Job Object.

When a local session exceeds its timeout, its Job Object terminates the whole
process tree and the process handle must signal termination. For the Windows
Sandbox fallback, the backend uses the trusted `taskkill.exe` from `System32`
to terminate the launcher process tree. Failure to verify cleanup is reported
as an untrusted sandbox result instead of being treated as a clean execution.

The current host does not provide rich guest telemetry because no writable host
directory is mapped into the guest. The `api_calls` field therefore contains
isolation-control metadata, while the scanner filters those control records out
of sample-behavior scoring.
