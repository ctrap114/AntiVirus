# Everbloom Security Driver Framework (C++)

This directory contains an initial C++ skeleton for the antivirus driver modules described in the project plan.

## Modules
- Core protection engine
- Self-protection
- File protection / ransomware guard
- AMSI / script and memory payload inspection
- Realtime scanning
- Network firewall
- Advanced threat detection

## Kernel enforcement

`sys_driver.cpp` is the control-plane entry point; `src/kernel_components.cpp`
registers the enforcement surfaces. There are **six**, not three — this list
previously under-reported them, which made the driver look like a pure control
plane when it also installs registry, handle and network interception.

| Surface | Registration | Veto |
|---|---|---|
| Process create/exit | `PsSetCreateProcessNotifyRoutineEx` (`kernel_components.cpp:942`) | yes |
| Image load | `PsSetLoadImageNotifyRoutine` (`:985`) | **no** — telemetry only |
| File system | `FltRegisterFilter` / `FltStartFiltering` (`:950`/`:954`) | yes |
| Registry | `CmRegisterCallbackEx` (`:541`) | yes |
| Object handles | `ObRegisterCallbacks` (`:572`) | yes |
| Network | `FwpsCalloutRegister2` (`:868`) | yes |

The six surfaces are described by one table, `g_enforcement_matrix`, so the
install order, the rollback order and the advertised capability flags cannot
drift apart. See `docs/driver_matrix_architecture.md` for the design and the
capability-derivation rule.

Detail on the first three:

- `PsSetCreateProcessNotifyRoutineEx`: denies a matching process by setting
  `CreationStatus` to `STATUS_ACCESS_DENIED`.
- File-system minifilter pre-operation callbacks: completes matching create,
  write and set-information requests with `STATUS_ACCESS_DENIED`. With driver
  protection enabled it also denies the audited vulnerable-driver basenames,
  browser credential-store reads, raw-disk/MBR writes, and a bounded
  high-volume document-write burst, plus a slow-encryption window requiring
  24 document writes across four families or 48 across three families within
  60 seconds (128 fixed nonpaged tracker slots; no pool allocation in the
  callback).
- WFP `ALE_AUTH_CONNECT_V4` terminating callout: sets `FWP_ACTION_BLOCK` for a
  matching IPv4 address and port.

The process-create callback additionally blocks tightly matched destructive
backup/recovery commands (`vssadmin`, `wbadmin`, `diskshadow`, `wmic
shadowcopy`, and the recovery-disabled `bcdedit` form). The image-load callback
is telemetry-only because Windows does not provide a supported veto there;
new vulnerable-driver opens are denied by the minifilter before the loader can
use them.

## Integer inference core

`include/everbloom_kernel_matrix.h` is an integer-only, allocation-free,
lock-free inference core. It is shaped that way for two kernel constraints: the
WFP classify callback runs at `DISPATCH_LEVEL`, where floating point is not
permitted, and the x64 kernel stack is roughly 12 KB, so no working buffer may
live on it. The model is therefore exported offline as quantized int8 weights
(`tract`/ONNX cannot be linked into a kernel image).

`include/everbloom_kernel_model.h` defines the 12-feature contract that the
offline exporter and the kernel must agree on. Features come only from what a
process-creation callback already holds - the image path and the command line -
each a bounded computation over a bounded string. This vocabulary is
deliberately **not** the engine's twelve PE features (`coverage`,
`section_entropy`, ...): those describe a file's bytes, these describe how a
process is being launched, and a model trained on one must not be evaluated
against the other.

`src/kernel_model.cpp` holds the weight tables and the scoring entry point. It
includes **no kernel header**, so the user-mode harness evaluates the exact
tables the driver ships; only the section placement of the data is
kernel-specific. The embedded weights are untrained bootstrap values, written
down so the whole path is live and tested rather than left as unverified
scaffolding; a trained model exported by `tools/` replaces them with no code
change.

Two details of the core are load bearing and easy to get wrong:

- The fixed-point rescale normalises the multiplier to Q31 and allows a right
  shift up to 62. A realistic per-tensor scale near 1e-2 needs a shift near 37,
  so a bound of 31 would silently cut the multiplier to about 24 significant
  bits.
- Rounding is half-away-from-zero, implemented by comparing the truncated
  remainder against the halfway threshold. The obvious "add half, then
  arithmetic-shift" shortcut is wrong on the negative side, because an
  arithmetic shift floors: it maps an exactly representable `-1000.0` to
  `-1001`.

**How the score reaches user mode.** `EverbloomProcessNotify` builds the features
and scores every process creation once driver enforcement is on, but records an
event only when the score crosses the model's advisory threshold, so the bounded
event ring does not fill with ordinary launches. The score travels in the
event's `Status` field under the dedicated `EVERBLOOM_EVENT_KIND_MODEL_SCORE`
kind. `Status` is the only spare numeric field in `EVERBLOOM_DRIVER_EVENT`, and
giving it a per-kind meaning lets the engine read the number directly rather
than parsing the reason string, without adding a field to a struct that
`driver_bridge.rs` mirrors in Rust for what is only an advisory signal.

The path never vetoes, and `record_kernel_behavior_event` in the engine
deliberately does not map a score onto a behaviour event: the model reads only
the image path and the command line, which user-mode correlation already holds,
so feeding a score back in would present this pipeline's own input as if it were
independent evidence. A build with no model linked in advertises no
`EVERBLOOM_CAPABILITY_KERNEL_MODEL`, so nothing waits on scores that cannot
arrive.

## Optional driver image integrity check

The Rust engine can verify the driver image before enabling the driver bridge.
Set `EVERBLOOM_DRIVER_PATH` and either `EVERBLOOM_DRIVER_SHA256` or a detached
`<driver>.sha256` file containing a 64-character SHA-256 digest. A mismatch or
unreadable configured digest disables the user-mode driver bridge and is
logged to the engine file log. If no path/digest is configured, the engine
reports integrity as unconfigured and retains the existing driver setting.

The Rust service owns policy decisions and submits only fixed-width policy
commands. Kernel policy storage is non-paged, capped at 64 rules per category,
and starts empty. IPv6 and wildcard path policies are intentionally not
enabled in this first enforcement slice. Every control request now requires a
non-zero request ID, a NUL-terminated target buffer, and a caller PID matching
the process issuing the IRP when the request originates in user mode. WFP
registration failures also roll back the partially-created dynamic session so
the driver does not leave a half-installed callout behind.

## Signed package and bring-up

`package/everbloom_driver.inf` and `package/sign_driver.ps1` provide the INF,
catalog generation and kernel-mode verification workflow. The workflow does
not generate or store a private key and does not install or load the driver.

The shipped altitude `329671` is usable as-is and is not a bring-up blocker.
Only a WHQL / attestation submission needs a Microsoft-assigned value, which is
a paperwork step rather than a functional prerequisite; see `package/README.md`.

To actually load and verify the driver on a development machine, use
`tools/dev_driver.ps1 -Action sign|install|status|smoke|uninstall`. Two details
there are deliberate: it avoids `sc.exe`, which is blacklisted on some hardened
hosts, by driving the SCM API directly with `SERVICE_KERNEL_DRIVER`; and it
takes the probe verdict from a report file rather than an exit code, because the
engine is linked as a GUI-subsystem binary that PowerShell neither waits for nor
reports a status code for.

The underlying probe is `everbloom_engine.exe --driver-status`, which opens
`\\.\EverbloomSecurity`, issues `EVERBLOOM_IOCTL_CAPABILITIES_QUERY` and exits without
starting the IPC server. It reports `kernel_model: true` only when an integer
model is genuinely linked into the loaded image, so it is the authoritative
answer to whether in-kernel scoring is live.

## Build

The kernel toolchain comes from the WDK at **`10.0.28000.0`**. The
`10.0.26100.0` kit ships only `ucrt`/`um`/`shared` and has no `km` tree, so the
`find_path` hints in `CMakeLists.txt` probe `10.0.28000.0` first. `rc.exe` and
`mt.exe` must also be on `PATH`, or CMake's compiler probe fails before it ever
reaches the driver sources.

```bash
export PATH="/f/insiders/VC/Tools/MSVC/14.51.36231/bin/Hostx64/x64:/c/Program Files (x86)/Windows Kits/10/bin/10.0.26100.0/x64:$PATH"
export INCLUDE="F:/insiders/VC/Tools/MSVC/14.51.36231/include;C:/Program Files (x86)/Windows Kits/10/Include/10.0.26100.0/ucrt;C:/Program Files (x86)/Windows Kits/10/Include/10.0.26100.0/um;C:/Program Files (x86)/Windows Kits/10/Include/10.0.26100.0/shared"
export LIB="F:/insiders/VC/Tools/MSVC/14.51.36231/lib/x64;C:/Program Files (x86)/Windows Kits/10/Lib/10.0.26100.0/ucrt/x64;C:/Program Files (x86)/Windows Kits/10/Lib/10.0.26100.0/um/x64"

cmake -S driver -B driver/build -G Ninja -DCMAKE_BUILD_TYPE=Debug
cmake --build driver/build
```

`driver/build` is already covered by the `**/build/` rule in `.gitignore`.

Verified output: `everbloom_driver.sys`, x64, subsystem `Native` (1), entry point
`DriverEntry`, importing `FLTMGR.SYS` and `fwpkclnt.sys`. Two user-mode harnesses
build and pass: `everbloom_kernel_matrix_tests` (99 assertions covering the
inference core, the feature extractor and the embedded model) and
`everbloom_kernel_policy_path_tests`.

Kernel sources must stay **ASCII-only**: the toolchain compiles under codepage
936, and a non-ASCII byte in a comment raises `C4819`. Use `-` rather than a
typographic dash.
