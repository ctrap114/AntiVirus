/*
 * Minimal WDM control-plane driver.
 *
 * This file intentionally does not include the user-mode policy library. The
 * user-mode modules use STL and blocking synchronization primitives that are
 * not valid in kernel mode. The driver performs bounded request validation and
 * a small emergency deny check; the main protection service remains the owner
 * of multi-step behavioral correlation.
 */
#include <fltKernel.h>
#include <wdmsec.h>

#include "everbloom_driver_protocol.h"
#include "kernel_components.hpp"
#include "kernel_policy.hpp"

namespace {

PDEVICE_OBJECT g_device_object = nullptr;

// Stable class identifier used by IoCreateDeviceSecure.
const GUID kEverbloomAvDeviceClass = {
    0x6f5a1c2d,
    0x4b71,
    0x4a7f,
    {0x9b, 0x21, 0x4a, 0x3c, 0x67, 0x91, 0x55, 0x10}
};

ULONG ascii_length(const char* value) {
    ULONG length = 0;
    if (value == nullptr) {
        return 0;
    }
    while (length < 128 && value[length] != '\0') {
        ++length;
    }
    return length;
}

constexpr UCHAR kAsciiCaseBit = 0x20;

inline UCHAR ascii_lower(UCHAR value) {
    return (value >= 'A' && value <= 'Z')
        ? static_cast<UCHAR>(value + kAsciiCaseBit)
        : value;
}

inline UCHAR ascii_upper(UCHAR value) {
    return (value >= 'a' && value <= 'z')
        ? static_cast<UCHAR>(value - kAsciiCaseBit)
        : value;
}

/// True for bytes that can appear inside a word token.
inline BOOLEAN is_word_character(UCHAR value) {
    return (value >= 'a' && value <= 'z')
        || (value >= 'A' && value <= 'Z')
        || (value >= '0' && value <= '9')
        || value == '_';
}

/// Needles shorter than this must match on token boundaries.
///
/// A three-byte needle is not a meaningful indicator by itself. The emergency
/// gate used to look for `"rop"` as a plain substring, which matched "Europe",
/// "property", "drop", "proxy" and "appropriate", so ordinary payload text
/// could trip the kernel deny path. Short needles are therefore required to sit
/// between non-word bytes. Longer needles stay plain-substring matches, which
/// keeps `"powershell"` matching inside a path such as
/// `...\WindowsPowerShell\v1.0\powershell.exe`.
constexpr ULONG kMinUnboundedNeedleLength = 5;

/// Case-insensitive substring search, anchored on the first byte.
///
/// The previous implementation compared the whole needle at every offset, so a
/// five-byte needle over a 64 KiB payload cost roughly 320 K byte comparisons.
/// Anchoring rejects nearly every offset after a single comparison and runs the
/// full compare only on candidates. This is the same fix applied to the Rust
/// static-sandbox matcher.
BOOLEAN contains_ascii_case_insensitive(
    const UCHAR* buffer,
    ULONG buffer_length,
    const char* needle) {
    if (buffer == nullptr || needle == nullptr) {
        return FALSE;
    }
    const ULONG needle_length = ascii_length(needle);
    if (needle_length == 0 || needle_length > buffer_length) {
        return FALSE;
    }
    const BOOLEAN require_boundaries = needle_length < kMinUnboundedNeedleLength;
    const UCHAR first_lower = ascii_lower(static_cast<UCHAR>(needle[0]));
    const UCHAR first_upper = ascii_upper(static_cast<UCHAR>(needle[0]));
    const ULONG last_offset = buffer_length - needle_length;
    for (ULONG offset = 0; offset <= last_offset; ++offset) {
        const UCHAR head = buffer[offset];
        if (head != first_lower && head != first_upper) {
            continue;
        }
        if (require_boundaries) {
            if (offset > 0 && is_word_character(buffer[offset - 1])) {
                continue;
            }
            if (offset + needle_length < buffer_length
                && is_word_character(buffer[offset + needle_length])) {
                continue;
            }
        }
        BOOLEAN match = TRUE;
        for (ULONG index = 1; index < needle_length; ++index) {
            if (ascii_lower(buffer[offset + index])
                != ascii_lower(static_cast<UCHAR>(needle[index]))) {
                match = FALSE;
                break;
            }
        }
        if (match) {
            return TRUE;
        }
    }
    return FALSE;
}

BOOLEAN is_supported_operation(ULONG operation) {
    return operation == EVERBLOOM_IOCTL_AMSI_SCAN_BUFFER
        || operation == EVERBLOOM_IOCTL_SCAN_FILE
        || operation == EVERBLOOM_IOCTL_NET_INSPECT
        || operation == EVERBLOOM_IOCTL_BEHAVIOR_ANALYZE
        || operation == EVERBLOOM_IOCTL_POLICY_UPDATE
        || operation == EVERBLOOM_IOCTL_POLICY_CLEAR
        || operation == EVERBLOOM_IOCTL_PROTECTION_UPDATE
        || operation == EVERBLOOM_IOCTL_EVENT_READ
        || operation == EVERBLOOM_IOCTL_CAPABILITIES_QUERY;
}

UNICODE_STRING request_target(const EVERBLOOM_DRIVER_REQUEST* request) {
    UNICODE_STRING target = {};
    if (request == nullptr) {
        return target;
    }
    USHORT length = 0;
    while (length < EVERBLOOM_MAX_TARGET_CHARS && request->Target[length] != 0) {
        ++length;
    }
    target.Buffer = reinterpret_cast<PWCHAR>(const_cast<uint16_t*>(request->Target));
    target.Length = static_cast<USHORT>(length * sizeof(WCHAR));
    target.MaximumLength = target.Length;
    return target;
}

BOOLEAN request_target_is_terminated(const EVERBLOOM_DRIVER_REQUEST* request) {
    if (request == nullptr) {
        return FALSE;
    }
    for (ULONG index = 0; index < EVERBLOOM_MAX_TARGET_CHARS; ++index) {
        if (request->Target[index] == 0) {
            return TRUE;
        }
    }
    return FALSE;
}

BOOLEAN request_identity_is_valid(
    const EVERBLOOM_DRIVER_REQUEST* request,
    KPROCESSOR_MODE requestor_mode) {
    if (request == nullptr || request->RequestId == 0
        || !request_target_is_terminated(request)) {
        return FALSE;
    }

    // User-mode callers cannot choose an arbitrary PID. Kernel-originated
    // requests may leave CallerPid at zero, but user-mode requests must match
    // the process that issued the IRP. This prevents replaying a captured
    // policy packet from a different service process.
    if (requestor_mode != KernelMode
        && (request->CallerPid == 0
            || request->CallerPid != HandleToULong(PsGetCurrentProcessId()))) {
        return FALSE;
    }
    return TRUE;
}

NTSTATUS evaluate_request(
    const EVERBLOOM_DRIVER_REQUEST* request,
    EVERBLOOM_DRIVER_RESPONSE* response,
    KPROCESSOR_MODE requestor_mode) {
    if (request == nullptr || response == nullptr) {
        return STATUS_INVALID_PARAMETER;
    }
    if (request->Version != EVERBLOOM_DRIVER_PROTOCOL_VERSION
        || request->PayloadLength > EVERBLOOM_MAX_PAYLOAD
        || !is_supported_operation(request->Operation)) {
        return STATUS_INVALID_PARAMETER;
    }
    if (!request_identity_is_valid(request, requestor_mode)) {
        return STATUS_ACCESS_DENIED;
    }

    response->Version = EVERBLOOM_DRIVER_PROTOCOL_VERSION;
    response->RequestId = request->RequestId;
    response->Verdict = 0;
    response->Threat = 0;
    response->Action = 0;

    if (request->Operation == EVERBLOOM_IOCTL_POLICY_UPDATE
        || request->Operation == EVERBLOOM_IOCTL_POLICY_CLEAR) {
        if (request->PayloadLength != sizeof(EVERBLOOM_POLICY_COMMAND)) {
            return STATUS_INVALID_PARAMETER;
        }
        const auto* command = reinterpret_cast<const EVERBLOOM_POLICY_COMMAND*>(
            request->Payload);
        const UNICODE_STRING target = request_target(request);
        const BOOLEAN needs_target = command->Kind == EVERBLOOM_POLICY_KIND_PROCESS
            || command->Kind == EVERBLOOM_POLICY_KIND_FILE
            || command->Kind == EVERBLOOM_POLICY_KIND_REGISTRY
            || command->Kind == EVERBLOOM_POLICY_KIND_RAW_DISK;
        if (needs_target && target.Length == 0) {
            return STATUS_INVALID_PARAMETER;
        }

        NTSTATUS status = request->Operation == EVERBLOOM_IOCTL_POLICY_UPDATE
            ? EverbloomKernelPolicyUpdate(command, &target)
            : EverbloomKernelPolicyClear(command, &target);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        return STATUS_SUCCESS;
    }

    if (request->Operation == EVERBLOOM_IOCTL_PROTECTION_UPDATE) {
        if (request->PayloadLength != sizeof(EVERBLOOM_PROTECTION_COMMAND)) {
            return STATUS_INVALID_PARAMETER;
        }
        const auto* command = reinterpret_cast<const EVERBLOOM_PROTECTION_COMMAND*>(
            request->Payload);
        if (command->Version != EVERBLOOM_POLICY_VERSION
            || command->R3Enabled > 1
            || command->DriverEnabled > 1
            || command->Reserved != 0) {
            return STATUS_INVALID_PARAMETER;
        }
        return EverbloomKernelPolicySetProtection(
            command->R3Enabled != 0,
            command->DriverEnabled != 0);
    }

    if (request->Operation == EVERBLOOM_IOCTL_SCAN_FILE) {
        const UNICODE_STRING target = request_target(request);
        if (target.Length > 0 && EverbloomKernelPolicyIsFileBlocked(&target)) {
            EverbloomKernelPolicyRecordBlock(
                EVERBLOOM_EVENT_KIND_FILE,
                &target,
                L"kernel file policy denied user-mode scan target");
            response->Verdict = 1;
            response->Threat = 2;
            response->Action = 2;
            return STATUS_SUCCESS;
        }
    }

    const UCHAR* payload = request->Payload;
    const ULONG length = request->PayloadLength;
    const BOOLEAN emergency_indicator =
        contains_ascii_case_insensitive(payload, length, "shellcode")
        || contains_ascii_case_insensitive(payload, length, "rundll32")
        || contains_ascii_case_insensitive(payload, length, "powershell")
        || contains_ascii_case_insensitive(payload, length, "rop")
        || contains_ascii_case_insensitive(payload, length, "malicious")
        // Cookie events are generated only after the user-mode classifier
        // has correlated browser-store, credential/decryption and extraction
        // signals. Keep the kernel emergency gate narrow so an ordinary
        // browser notification cannot be denied merely for mentioning a
        // cookie.
        || (contains_ascii_case_insensitive(payload, length, "cookie")
            && (contains_ascii_case_insensitive(payload, length, "browser")
                || contains_ascii_case_insensitive(payload, length, "sqlite")
                || contains_ascii_case_insensitive(payload, length, "dpapi")));

    if (emergency_indicator) {
        const UNICODE_STRING target = request_target(request);
        EverbloomKernelPolicyRecordBlock(
            EVERBLOOM_EVENT_KIND_EMERGENCY,
            &target,
            L"kernel emergency indicator denied request");
        response->Verdict = 1;
        response->Threat = request->Operation == EVERBLOOM_IOCTL_BEHAVIOR_ANALYZE ? 3 : 2;
        response->Action = request->Operation == EVERBLOOM_IOCTL_BEHAVIOR_ANALYZE ? 4 : 2;
    }
    return STATUS_SUCCESS;
}

NTSTATUS complete_irp(PIRP irp, NTSTATUS status, ULONG_PTR information) {
    irp->IoStatus.Status = status;
    irp->IoStatus.Information = information;
    IoCompleteRequest(irp, IO_NO_INCREMENT);
    return status;
}

NTSTATUS query_capabilities(
    const EVERBLOOM_CAPABILITIES_QUERY* query,
    EVERBLOOM_CAPABILITIES_RESPONSE* response) {
    if (query == nullptr || response == nullptr
        || query->Version != EVERBLOOM_DRIVER_CAPABILITIES_VERSION
        || query->Reserved != 0) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(response, sizeof(*response));
    response->Version = EVERBLOOM_DRIVER_CAPABILITIES_VERSION;
    response->ProtocolVersion = EVERBLOOM_DRIVER_PROTOCOL_VERSION;
    response->PolicyVersion = EVERBLOOM_POLICY_VERSION;
    response->ProtectionProtocolVersion = EVERBLOOM_POLICY_VERSION;
    response->EventVersion = EVERBLOOM_DRIVER_EVENT_VERSION;
    response->MaxTargetChars = EVERBLOOM_MAX_TARGET_CHARS;
    response->MaxPayloadBytes = EVERBLOOM_MAX_PAYLOAD;
    response->MaxEventBatch = EVERBLOOM_EVENT_MAX_BATCH;
    // Derived from the enforcement matrix rather than asserted. This list used
    // to be hardcoded, so the driver advertised registry and network
    // enforcement even when those callbacks had been refused by the platform.
    // User mode uses these flags to decide what it can rely on, so a
    // capability that is not actually installed must be reported as absent.
    response->CapabilityFlags = EverbloomKernelComponentsCapabilityFlags();
    return STATUS_SUCCESS;
}

NTSTATUS dispatch_create_close(PDEVICE_OBJECT device_object, PIRP irp) {
    UNREFERENCED_PARAMETER(device_object);
    return complete_irp(irp, STATUS_SUCCESS, 0);
}

NTSTATUS dispatch_device_control(PDEVICE_OBJECT device_object, PIRP irp) {
    UNREFERENCED_PARAMETER(device_object);
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(irp);
    if (stack == nullptr || irp->AssociatedIrp.SystemBuffer == nullptr) {
        return complete_irp(irp, STATUS_INVALID_PARAMETER, 0);
    }

    const ULONG input_length = stack->Parameters.DeviceIoControl.InputBufferLength;
    const ULONG output_length = stack->Parameters.DeviceIoControl.OutputBufferLength;
    const ULONG ioctl_code = stack->Parameters.DeviceIoControl.IoControlCode;

    // Single source of truth. This previously re-listed every operation code
    // that `is_supported_operation` already knew about, so the two lists had to
    // be edited in lockstep. Adding an IOCTL to one and not the other silently
    // produced either an unreachable handler or an unvalidated one, and
    // `evaluate_request` validated against the other list.
    if (!is_supported_operation(ioctl_code)) {
        return complete_irp(irp, STATUS_INVALID_DEVICE_REQUEST, 0);
    }

    if (ioctl_code == EVERBLOOM_IOCTL_CAPABILITIES_QUERY) {
        if (input_length < sizeof(EVERBLOOM_CAPABILITIES_QUERY)
            || output_length < sizeof(EVERBLOOM_CAPABILITIES_RESPONSE)) {
            return complete_irp(irp, STATUS_BUFFER_TOO_SMALL, 0);
        }
        EVERBLOOM_CAPABILITIES_QUERY query = {};
        RtlCopyMemory(&query, irp->AssociatedIrp.SystemBuffer, sizeof(query));
        auto* capabilities = static_cast<EVERBLOOM_CAPABILITIES_RESPONSE*>(
            irp->AssociatedIrp.SystemBuffer);
        const NTSTATUS capability_status = query_capabilities(&query, capabilities);
        return complete_irp(
            irp,
            capability_status,
            NT_SUCCESS(capability_status)
                ? sizeof(EVERBLOOM_CAPABILITIES_RESPONSE)
                : 0);
    }

    if (ioctl_code == EVERBLOOM_IOCTL_EVENT_READ) {
        if (input_length < sizeof(EVERBLOOM_EVENT_QUERY)
            || output_length < sizeof(EVERBLOOM_EVENT_READ_RESPONSE)) {
            return complete_irp(irp, STATUS_BUFFER_TOO_SMALL, 0);
        }
        EVERBLOOM_EVENT_QUERY query = {};
        RtlCopyMemory(&query, irp->AssociatedIrp.SystemBuffer, sizeof(query));
        auto* event_response = static_cast<EVERBLOOM_EVENT_READ_RESPONSE*>(
            irp->AssociatedIrp.SystemBuffer);
        const NTSTATUS event_status = EverbloomKernelPolicyReadEvents(&query, event_response);
        return complete_irp(
            irp,
            event_status,
            NT_SUCCESS(event_status)
                ? sizeof(EVERBLOOM_EVENT_READ_RESPONSE)
                : 0);
    }
    if (input_length < sizeof(EVERBLOOM_DRIVER_REQUEST)
        || output_length < sizeof(EVERBLOOM_DRIVER_RESPONSE)) {
        return complete_irp(irp, STATUS_BUFFER_TOO_SMALL, 0);
    }

    const auto* request = static_cast<const EVERBLOOM_DRIVER_REQUEST*>(
        irp->AssociatedIrp.SystemBuffer);
    auto* response = static_cast<EVERBLOOM_DRIVER_RESPONSE*>(
        irp->AssociatedIrp.SystemBuffer);
    if (request->Operation != ioctl_code) {
        return complete_irp(irp, STATUS_INVALID_PARAMETER, 0);
    }

    EVERBLOOM_DRIVER_RESPONSE local_response = {};
    NTSTATUS status = evaluate_request(
        request,
        &local_response,
        irp->RequestorMode);
    if (!NT_SUCCESS(status)) {
        return complete_irp(irp, status, 0);
    }
    RtlCopyMemory(response, &local_response, sizeof(local_response));
    return complete_irp(irp, STATUS_SUCCESS, sizeof(local_response));
}

void driver_unload(PDRIVER_OBJECT driver_object) {
    EverbloomKernelComponentsShutdown();
    EverbloomKernelPolicyShutdown();
    UNICODE_STRING symbolic_link = RTL_CONSTANT_STRING(L"\\DosDevices\\EverbloomSecurity");
    IoDeleteSymbolicLink(&symbolic_link);
    if (driver_object->DeviceObject != nullptr) {
        IoDeleteDevice(driver_object->DeviceObject);
    }
    g_device_object = nullptr;
}

} // namespace

extern "C" NTSTATUS DriverEntry(
    PDRIVER_OBJECT driver_object,
    PUNICODE_STRING registry_path) {
    UNREFERENCED_PARAMETER(registry_path);

    UNICODE_STRING device_name = RTL_CONSTANT_STRING(L"\\Device\\EverbloomSecurity");
    UNICODE_STRING symbolic_link = RTL_CONSTANT_STRING(L"\\DosDevices\\EverbloomSecurity");
    NTSTATUS status = IoCreateDeviceSecure(
        driver_object,
        0,
        &device_name,
        FILE_DEVICE_UNKNOWN,
        FILE_DEVICE_SECURE_OPEN,
        FALSE,
        &SDDL_DEVOBJ_SYS_ALL_ADM_ALL,
        &kEverbloomAvDeviceClass,
        &g_device_object);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    g_device_object->Flags |= DO_BUFFERED_IO;
    status = IoCreateSymbolicLink(&symbolic_link, &device_name);
    if (!NT_SUCCESS(status)) {
        IoDeleteDevice(g_device_object);
        g_device_object = nullptr;
        return status;
    }

    driver_object->DriverUnload = driver_unload;
    for (ULONG index = 0; index <= IRP_MJ_MAXIMUM_FUNCTION; ++index) {
        driver_object->MajorFunction[index] = dispatch_create_close;
    }
    driver_object->MajorFunction[IRP_MJ_DEVICE_CONTROL] = dispatch_device_control;

    status = EverbloomKernelPolicyInitialize();
    if (!NT_SUCCESS(status)) {
        IoDeleteSymbolicLink(&symbolic_link);
        IoDeleteDevice(g_device_object);
        g_device_object = nullptr;
        return status;
    }
    status = EverbloomKernelComponentsInitialize(driver_object);
    if (!NT_SUCCESS(status)) {
        EverbloomKernelPolicyShutdown();
        IoDeleteSymbolicLink(&symbolic_link);
        IoDeleteDevice(g_device_object);
        g_device_object = nullptr;
        return status;
    }
    g_device_object->Flags &= ~DO_DEVICE_INITIALIZING;
    return STATUS_SUCCESS;
}
