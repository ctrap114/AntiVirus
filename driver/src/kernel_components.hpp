#pragma once

#include <fltKernel.h>

NTSTATUS EverbloomKernelComponentsInitialize(PDRIVER_OBJECT driver_object);
VOID EverbloomKernelComponentsShutdown();

/*
 * Enforcement matrix.
 *
 * Every kernel enforcement surface the driver installs is one row of a static
 * table in kernel_components.cpp. Initialization walks the table forward and
 * shutdown walks it backward, so the install and rollback orders cannot drift
 * apart. The capability query is derived from the same rows, which is what
 * makes it truthful: a surface the platform rejected is not advertised.
 *
 * This replaces three hand-maintained lists (install sequence, uninstall
 * sequence, capability flags) that had to be edited in lockstep, plus the two
 * ad-hoc BOOLEAN flags that used to track process/image registration.
 */
/*
 * Index order is the install order, and shutdown walks it in reverse. Required
 * surfaces come first so that a platform refusal aborts before any optional
 * hardening has been installed, and optional surfaces are torn down first.
 */
typedef enum EVERBLOOM_ENFORCEMENT_SURFACE {
    EverbloomEnforcementProcessNotify = 0,
    EverbloomEnforcementFileFilter,
    EverbloomEnforcementNetworkWfp,
    EverbloomEnforcementImageNotify,
    EverbloomEnforcementRegistry,
    EverbloomEnforcementObjectHandle
} EVERBLOOM_ENFORCEMENT_SURFACE;

#define EVERBLOOM_ENFORCEMENT_SURFACE_COUNT 6u

/*
 * Bit `i` is set when surface `i` is currently installed. This is the
 * per-surface view; the capability query below is the user-mode-facing view.
 */
ULONG64 EverbloomKernelComponentsActiveSurfaces();

/*
 * Capability flags backed by the current registration state.
 *
 * Control-plane capabilities are unconditional: the control device and its
 * IOCTL ABI exist whenever the driver is loaded, and they are what
 * `is_compatible()` on the user-mode side checks. Enforcement capabilities are
 * derived from the installed surfaces, so a rejected callback is reported as
 * absent rather than assumed present.
 */
ULONG64 EverbloomKernelComponentsCapabilityFlags();
