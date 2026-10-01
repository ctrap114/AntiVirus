// fwpsk.h includes the generic NDIS declarations. NDIS requires a target
// contract macro for non-miniport kernel code; WFP callouts use the 6.30 ABI.
#ifndef NDIS630
#define NDIS630 1
#endif

#include "kernel_components.hpp"

#include <fltKernel.h>
#include <fwpmk.h>
#include <fwpsk.h>
#include <rpcdce.h>

#include "kernel_policy.hpp"
#include "everbloom_altitude.h"
#include "everbloom_kernel_model.h"

extern "C" PUCHAR PsGetProcessImageFileName(PEPROCESS process);

namespace {

PFLT_FILTER g_file_filter = nullptr;
HANDLE g_wfp_engine = nullptr;
UINT32 g_wfp_callout_id = 0;
UINT64 g_wfp_filter_id = 0;
BOOLEAN g_registry_callback_registered = FALSE;
LARGE_INTEGER g_registry_callback_cookie{};
PVOID g_object_callback_handle = nullptr;

// The ransomware burst tracker is deliberately a fixed-size table.  File
// callbacks can run at elevated IRQL, so this path must not allocate pool
// memory or take a pageable lock.  A bounded table is sufficient for early
// stopping; user-mode telemetry remains responsible for the full audit trail.
constexpr ULONG kRansomTrackerCount = 128;
constexpr ULONGLONG kRansomWindow100ns = 5ULL * 10ULL * 1000ULL * 1000ULL;
constexpr ULONGLONG kRansomSlowWindow100ns = 60ULL * 10ULL * 1000ULL * 1000ULL;
constexpr ULONG kRansomWriteThreshold = 200;
constexpr ULONG kRansomMixedDocumentThreshold = 32;
constexpr ULONG kRansomSlowDocumentThreshold = 24;
constexpr ULONG kRansomVerySlowDocumentThreshold = 48;

struct RansomTracker {
    HANDLE process_id;
    ULONGLONG fast_window_start;
    ULONG fast_write_count;
    ULONG fast_document_families;
    ULONGLONG slow_window_start;
    ULONG slow_document_count;
    ULONG slow_document_families;
};

KSPIN_LOCK g_ransom_tracker_lock;
RansomTracker g_ransom_trackers[kRansomTrackerCount]{};

const GUID kWfpCalloutKey = {
    0x4e6f9bb1,
    0x46b3,
    0x4b73,
    {0x8d, 0x51, 0x1b, 0x7c, 0x2a, 0x8c, 0x1a, 0x71}
};

const GUID kWfpProviderKey = {
    0xc4be4c7d,
    0xbcd7,
    0x4a46,
    {0x93, 0x2e, 0x31, 0x37, 0xf1, 0x7a, 0x45, 0x09}
};

const GUID kWfpSublayerKey = {
    0x0e7bbf41,
    0x7f48,
    0x4e3f,
    {0xa0, 0xc7, 0x1c, 0x23, 0x86, 0x19, 0x6c, 0x4a}
};

const GUID kWfpFilterKey = {
    0xa87f5f9e,
    0x3e37,
    0x4d3e,
    {0x9d, 0x9b, 0x4d, 0x9c, 0x21, 0xd3, 0x76, 0x0a}
};

BOOLEAN is_raw_disk_path(PCUNICODE_STRING name) {
    if (name == nullptr || name->Buffer == nullptr) {
        return FALSE;
    }
    UNICODE_STRING hard_disk = RTL_CONSTANT_STRING(L"\\Device\\Harddisk");
    UNICODE_STRING partition = RTL_CONSTANT_STRING(L"\\Device\\Partition");
    return RtlPrefixUnicodeString(&hard_disk, name, TRUE)
        || RtlPrefixUnicodeString(&partition, name, TRUE);
}

BOOLEAN contains_unicode_token(PCUNICODE_STRING value, PCUNICODE_STRING token) {
    if (value == nullptr || token == nullptr || value->Buffer == nullptr
        || token->Buffer == nullptr || token->Length == 0 || value->Length < token->Length) {
        return FALSE;
    }
    const USHORT value_chars = value->Length / sizeof(WCHAR);
    const USHORT token_chars = token->Length / sizeof(WCHAR);
    for (USHORT offset = 0; offset + token_chars <= value_chars; ++offset) {
        UNICODE_STRING candidate = *value;
        candidate.Buffer += offset;
        candidate.Length = token->Length;
        candidate.MaximumLength = candidate.Length;
        if (RtlEqualUnicodeString(&candidate, token, TRUE)) {
            return TRUE;
        }
    }
    return FALSE;
}

BOOLEAN is_browser_cookie_store_path(PCUNICODE_STRING name) {
    UNICODE_STRING chromium_store = RTL_CONSTANT_STRING(L"\\Network\\Cookies");
    UNICODE_STRING firefox_store = RTL_CONSTANT_STRING(L"\\cookies.sqlite");
    UNICODE_STRING firefox_wal = RTL_CONSTANT_STRING(L"\\cookies.sqlite-wal");
    UNICODE_STRING firefox_shm = RTL_CONSTANT_STRING(L"\\cookies.sqlite-shm");
    return contains_unicode_token(name, &chromium_store)
        || contains_unicode_token(name, &firefox_store)
        || contains_unicode_token(name, &firefox_wal)
        || contains_unicode_token(name, &firefox_shm);
}

BOOLEAN is_cookie_requestor_exempt() {
    const auto* image = reinterpret_cast<const CHAR*>(PsGetProcessImageFileName(PsGetCurrentProcess()));
    if (image == nullptr) {
        return FALSE;
    }
    ANSI_STRING image_name{};
    RtlInitAnsiString(&image_name, image);
    // Browser processes need their own stores. EverbloomSecurity and the Windows
    // Defender process are also exempt so scanning/health checks continue to
    // work. The minifilter remains the enforcement point for other readers.
    const char* exempt_names[] = {
        "chrome.exe",
        "msedge.exe",
        "firefox.exe",
        "brave.exe",
        "opera.exe",
        "vivaldi.exe",
        "chromium.exe",
        "iexplore.exe",
        "msedgewebview2",
        "everbloom_engine",
        "everbloom_gui",
        "everbloom_service",
        "MsMpEng.exe",
        "SecurityHealthService",
    };
    for (const auto* name : exempt_names) {
        ANSI_STRING candidate{};
        RtlInitAnsiString(&candidate, name);
        if (RtlEqualString(&image_name, &candidate, TRUE)) {
            return TRUE;
        }
    }
    return FALSE;
}

BOOLEAN is_cookie_store_read_open(PFLT_CALLBACK_DATA data) {
    if (data == nullptr || data->Iopb == nullptr
        || data->Iopb->MajorFunction != IRP_MJ_CREATE
        || data->Iopb->Parameters.Create.SecurityContext == nullptr) {
        return FALSE;
    }
    const ACCESS_MASK desired_access =
        data->Iopb->Parameters.Create.SecurityContext->DesiredAccess;
    // Generic read is expanded by the I/O manager to include FILE_READ_DATA;
    // checking the concrete data right avoids blocking metadata-only opens.
    return (desired_access & FILE_READ_DATA) != 0;
}

BOOLEAN is_protected_process(PEPROCESS process) {
    if (process == nullptr) {
        return FALSE;
    }
    const auto* image = reinterpret_cast<const CHAR*>(PsGetProcessImageFileName(process));
    if (image == nullptr) {
        return FALSE;
    }
    const char* protected_names[] = {
        // PsGetProcessImageFileName exposes the 15-character kernel image
        // name, so the suffix must omit ".exe" for these binaries.
        "everbloom_engine",
        "everbloom_gui",
        "everbloom_service",
    };
    ANSI_STRING image_name{};
    RtlInitAnsiString(&image_name, image);
    for (const auto* name : protected_names) {
        ANSI_STRING candidate{};
        RtlInitAnsiString(&candidate, name);
        if (RtlEqualString(&image_name, &candidate, TRUE)) {
            return TRUE;
        }
    }
    return FALSE;
}

BOOLEAN has_token(PCUNICODE_STRING value, PCWSTR token) {
    if (token == nullptr) {
        return FALSE;
    }
    UNICODE_STRING candidate{};
    RtlInitUnicodeString(&candidate, token);
    return contains_unicode_token(value, &candidate);
}

BOOLEAN is_dll_or_sys_path(PCUNICODE_STRING name) {
    if (name == nullptr || name->Buffer == nullptr) {
        return FALSE;
    }
    UNICODE_STRING dll_suffix = RTL_CONSTANT_STRING(L".dll");
    UNICODE_STRING sys_suffix = RTL_CONSTANT_STRING(L".sys");
    return RtlSuffixUnicodeString(&dll_suffix, name, TRUE)
        || RtlSuffixUnicodeString(&sys_suffix, name, TRUE);
}

BOOLEAN is_system_drivers_directory_path(PCUNICODE_STRING name) {
    if (name == nullptr || name->Buffer == nullptr) {
        return FALSE;
    }
    UNICODE_STRING system32_drivers = RTL_CONSTANT_STRING(L"\\System32\\drivers\\");
    UNICODE_STRING syswow64_drivers = RTL_CONSTANT_STRING(L"\\SysWOW64\\drivers\\");
    return contains_unicode_token(name, &system32_drivers)
        || contains_unicode_token(name, &syswow64_drivers);
}

BOOLEAN is_driver_directory_sensitive_module(PCUNICODE_STRING name) {
    return is_system_drivers_directory_path(name) && is_dll_or_sys_path(name);
}

BOOLEAN is_write_open_request(PFLT_CALLBACK_DATA data) {
    if (data == nullptr || data->Iopb == nullptr
        || data->Iopb->MajorFunction != IRP_MJ_CREATE
        || data->Iopb->Parameters.Create.SecurityContext == nullptr) {
        return FALSE;
    }
    const ACCESS_MASK desired_access =
        data->Iopb->Parameters.Create.SecurityContext->DesiredAccess;
    return (desired_access
            & (FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_WRITE_ATTRIBUTES
               | FILE_WRITE_EA | DELETE | GENERIC_WRITE))
        != 0;
}

BOOLEAN is_delete_or_rename_request(PFLT_CALLBACK_DATA data) {
    if (data == nullptr || data->Iopb == nullptr
        || data->Iopb->MajorFunction != IRP_MJ_SET_INFORMATION) {
        return FALSE;
    }
    const FILE_INFORMATION_CLASS info_class =
        data->Iopb->Parameters.SetFileInformation.FileInformationClass;
    return info_class == FileDispositionInformation
        || info_class == FileDispositionInformationEx
        || info_class == FileRenameInformation
        || info_class == FileRenameInformationEx;
}

BOOLEAN is_file_mutation_request(PFLT_CALLBACK_DATA data) {
    if (data == nullptr || data->Iopb == nullptr) {
        return FALSE;
    }
    return data->Iopb->MajorFunction == IRP_MJ_WRITE
        || is_write_open_request(data)
        || is_delete_or_rename_request(data);
}

BOOLEAN is_code_integrity_policy_path(PCUNICODE_STRING name) {
    if (name == nullptr || name->Buffer == nullptr) {
        return FALSE;
    }
    UNICODE_STRING code_integrity = RTL_CONSTANT_STRING(L"\\CodeIntegrity\\");
    UNICODE_STRING policy_suffix = RTL_CONSTANT_STRING(L".p7b");
    UNICODE_STRING binary_policy_suffix = RTL_CONSTANT_STRING(L".cip");
    return contains_unicode_token(name, &code_integrity)
        && (RtlSuffixUnicodeString(&policy_suffix, name, TRUE)
            || RtlSuffixUnicodeString(&binary_policy_suffix, name, TRUE));
}

BOOLEAN is_backup_destruction_command(
    PCUNICODE_STRING image_name,
    PCUNICODE_STRING command_line) {
    if (image_name == nullptr || command_line == nullptr
        || command_line->Buffer == nullptr) {
        return FALSE;
    }

    // Match executable + destructive verb + object.  Query/list operations
    // intentionally do not match, which avoids blocking legitimate backup
    // inventory tools.
    if (has_token(image_name, L"vssadmin.exe")
        && has_token(command_line, L"delete")
        && has_token(command_line, L"shadow")) {
        return TRUE;
    }
    if (has_token(image_name, L"wbadmin.exe")
        && has_token(command_line, L"delete")
        && (has_token(command_line, L"catalog")
            || has_token(command_line, L"systemstatebackup")
            || has_token(command_line, L"backup"))) {
        return TRUE;
    }
    if (has_token(image_name, L"diskshadow.exe")
        && (has_token(command_line, L"delete")
            || has_token(command_line, L"reset"))) {
        return TRUE;
    }
    if (has_token(image_name, L"wmic.exe")
        && has_token(command_line, L"shadowcopy")
        && has_token(command_line, L"delete")) {
        return TRUE;
    }
    if (has_token(image_name, L"bcdedit.exe")
        && has_token(command_line, L"recoveryenabled")
        && has_token(command_line, L"no")) {
        return TRUE;
    }
    return FALSE;
}

ULONG document_family_bit(PCUNICODE_STRING path) {
    if (path == nullptr || path->Buffer == nullptr) {
        return 0;
    }
    struct ExtensionFamily {
        PCWSTR extension;
        ULONG bit;
    };
    constexpr ExtensionFamily families[] = {
        {L".doc", 1u << 0}, {L".docx", 1u << 0},
        {L".xls", 1u << 1}, {L".xlsx", 1u << 1},
        {L".ppt", 1u << 2}, {L".pptx", 1u << 2},
        {L".pdf", 1u << 3}, {L".jpg", 1u << 3},
        {L".jpeg", 1u << 3}, {L".png", 1u << 3},
    };
    for (const auto& family : families) {
        UNICODE_STRING extension{};
        RtlInitUnicodeString(&extension, family.extension);
        if (RtlSuffixUnicodeString(&extension, path, TRUE)) {
            return family.bit;
        }
    }
    return 0;
}

ULONG record_ransomware_write(PCUNICODE_STRING path) {
    const HANDLE process_id = PsGetCurrentProcessId();
    ULONG64 qpc_timestamp = 0;
    const ULONGLONG now = KeQueryInterruptTimePrecise(&qpc_timestamp);
    const ULONG family_bit = document_family_bit(path);
    KIRQL old_irql = PASSIVE_LEVEL;
    KeAcquireSpinLock(&g_ransom_tracker_lock, &old_irql);

    ULONG selected = HandleToULong(process_id) % kRansomTrackerCount;
    ULONG oldest = selected;
    BOOLEAN found = FALSE;
    for (ULONG probe = 0; probe < kRansomTrackerCount; ++probe) {
        const ULONG index = (selected + probe) % kRansomTrackerCount;
        auto& entry = g_ransom_trackers[index];
        if (entry.process_id == nullptr || entry.process_id == process_id) {
            selected = index;
            found = TRUE;
            break;
        }
        if (entry.fast_window_start < g_ransom_trackers[oldest].fast_window_start) {
            oldest = index;
        }
    }
    if (!found) {
        selected = oldest;
    }

    auto& entry = g_ransom_trackers[selected];
    if (entry.process_id != process_id) {
        entry.process_id = process_id;
        entry.fast_window_start = now;
        entry.fast_write_count = 0;
        entry.fast_document_families = 0;
        entry.slow_window_start = now;
        entry.slow_document_count = 0;
        entry.slow_document_families = 0;
    } else if (now < entry.fast_window_start
        || now - entry.fast_window_start > kRansomWindow100ns) {
        // The fast window rolls independently; the slow window deliberately
        // survives gaps between writes up to its own 60-second horizon.
        entry.fast_window_start = now;
        entry.fast_write_count = 0;
        entry.fast_document_families = 0;
    }
    ++entry.fast_write_count;
    entry.fast_document_families |= family_bit;
    const ULONG family_count =
        ((entry.fast_document_families & (1u << 0)) != 0)
        + ((entry.fast_document_families & (1u << 1)) != 0)
        + ((entry.fast_document_families & (1u << 2)) != 0)
        + ((entry.fast_document_families & (1u << 3)) != 0);
    const BOOLEAN fast_suspicious = entry.fast_write_count >= kRansomWriteThreshold
        || (entry.fast_write_count >= kRansomMixedDocumentThreshold
            && family_count >= 3);
    if (family_bit != 0) {
        if (now < entry.slow_window_start
            || now - entry.slow_window_start > kRansomSlowWindow100ns) {
            entry.slow_window_start = now;
            entry.slow_document_count = 0;
            entry.slow_document_families = 0;
        }
        ++entry.slow_document_count;
        entry.slow_document_families |= family_bit;
    }
    const ULONG slow_family_count =
        ((entry.slow_document_families & (1u << 0)) != 0)
        + ((entry.slow_document_families & (1u << 1)) != 0)
        + ((entry.slow_document_families & (1u << 2)) != 0)
        + ((entry.slow_document_families & (1u << 3)) != 0);
    const BOOLEAN slow_suspicious =
        (entry.slow_document_count >= kRansomSlowDocumentThreshold
            && slow_family_count >= 4)
        || (entry.slow_document_count >= kRansomVerySlowDocumentThreshold
            && slow_family_count >= 3);
    if (fast_suspicious || slow_suspicious) {
        // Keep the fast entry hot so subsequent writes remain blocked without
        // growing any state; the slow signal has already been recorded in its
        // independent 60-second window.
        entry.fast_write_count = kRansomWriteThreshold;
    }
    KeReleaseSpinLock(&g_ransom_tracker_lock, old_irql);
    return fast_suspicious ? 1u : slow_suspicious ? 2u : 0u;
}

OB_PREOP_CALLBACK_STATUS EverbloomProcessHandlePreOperation(
    PVOID registration_context,
    POB_PRE_OPERATION_INFORMATION information) {
    UNREFERENCED_PARAMETER(registration_context);
    if (information == nullptr
        || information->ObjectType != *PsProcessType
        || !EverbloomKernelPolicyIsDriverEnabled()) {
        return OB_PREOP_SUCCESS;
    }

    constexpr ACCESS_MASK kBlockedProcessRights =
        0x0001 /* PROCESS_TERMINATE */
        | 0x0002 /* PROCESS_CREATE_THREAD */
        | 0x0008 /* PROCESS_VM_OPERATION */
        | 0x0020 /* PROCESS_VM_WRITE */
        | 0x0040 /* PROCESS_DUP_HANDLE */
        | 0x0200 /* PROCESS_SET_INFORMATION */
        | 0x0800 /* PROCESS_SUSPEND_RESUME */;
    const auto target_process = static_cast<PEPROCESS>(information->Object);
    const BOOLEAN target_is_protected = is_protected_process(target_process);
    if (target_is_protected && information->Operation == OB_OPERATION_HANDLE_CREATE) {
        information->Parameters->CreateHandleInformation.DesiredAccess
            &= ~kBlockedProcessRights;
    } else if (target_is_protected && information->Operation == OB_OPERATION_HANDLE_DUPLICATE) {
        information->Parameters->DuplicateHandleInformation.DesiredAccess
            &= ~kBlockedProcessRights;
    }

    // QueueUserAPC and PoolParty do not create a new process and are not
    // safely interceptable through a supported kernel callback. Observe the
    // common preparation step instead: a non-Everbloom process requesting remote
    // VM/thread/handle rights against another process. User mode correlates
    // this event with private RWX memory and API indicators before acting.
    if (!target_is_protected && !is_protected_process(PsGetCurrentProcess())
        && information->Operation == OB_OPERATION_HANDLE_CREATE) {
        const ACCESS_MASK desired_access =
            information->Parameters->CreateHandleInformation.DesiredAccess;
        constexpr ACCESS_MASK kInjectionPreparationRights =
            0x0002 /* PROCESS_CREATE_THREAD */
            | 0x0008 /* PROCESS_VM_OPERATION */
            | 0x0020 /* PROCESS_VM_WRITE */
            | 0x0040 /* PROCESS_DUP_HANDLE */;
        if ((desired_access & kInjectionPreparationRights) != 0
            && target_process != PsGetCurrentProcess()) {
            EverbloomKernelPolicyRecordEvent(
                EVERBLOOM_EVENT_KIND_PROCESS,
                nullptr,
                L"potential APC or thread-pool injection handle access observed",
                STATUS_SUCCESS);
        }
    }
    return OB_PREOP_SUCCESS;
}

NTSTATUS EverbloomRegistryNotify(PVOID callback_context, PVOID argument1, PVOID argument2) {
    UNREFERENCED_PARAMETER(callback_context);
    if (!EverbloomKernelPolicyIsDriverEnabled() || argument1 == nullptr || argument2 == nullptr) {
        return STATUS_SUCCESS;
    }

    const auto notify_class = static_cast<REG_NOTIFY_CLASS>(
        reinterpret_cast<ULONG_PTR>(argument1));
    PVOID key_object = nullptr;
    switch (notify_class) {
        case RegNtPreSetValueKey:
            key_object = static_cast<PREG_SET_VALUE_KEY_INFORMATION>(argument2)->Object;
            break;
        case RegNtPreDeleteValueKey:
            key_object = static_cast<PREG_DELETE_VALUE_KEY_INFORMATION>(argument2)->Object;
            break;
        case RegNtPreDeleteKey:
            key_object = static_cast<PREG_DELETE_KEY_INFORMATION>(argument2)->Object;
            break;
        case RegNtPreRenameKey:
            key_object = static_cast<PREG_RENAME_KEY_INFORMATION>(argument2)->Object;
            break;
        default:
            return STATUS_SUCCESS;
    }
    if (key_object == nullptr) {
        return STATUS_SUCCESS;
    }

    PCUNICODE_STRING key_name = nullptr;
    const NTSTATUS status = CmCallbackGetKeyObjectIDEx(
        &g_registry_callback_cookie,
        key_object,
        nullptr,
        &key_name,
        0);
    if (!NT_SUCCESS(status) || key_name == nullptr) {
        return STATUS_SUCCESS;
    }
    const BOOLEAN blocked = EverbloomKernelPolicyIsRegistryBlocked(key_name);
    if (blocked) {
        const BOOLEAN ctf_key = has_token(key_name, L"\\SOFTWARE\\MICROSOFT\\CTF")
            || has_token(key_name, L"\\CTF\\SYSTEMSHARED");
        const BOOLEAN typelib_key = has_token(key_name, L"\\TYPELIB");
        EverbloomKernelPolicyRecordBlock(
            EVERBLOOM_EVENT_KIND_REGISTRY,
            key_name,
            ctf_key
                ? L"CTF hijack registry operation blocked"
                : typelib_key
                ? L"TypeLib hijack registry operation blocked"
                : L"kernel registry policy blocked operation");
    }
    CmCallbackReleaseKeyObjectIDEx(key_name);
    return blocked ? STATUS_ACCESS_DENIED : STATUS_SUCCESS;
}

NTSTATUS register_registry_callback(PDRIVER_OBJECT driver_object) {
    UNICODE_STRING altitude = RTL_CONSTANT_STRING(L"370100");
    const NTSTATUS status = CmRegisterCallbackEx(
        EverbloomRegistryNotify,
        &altitude,
        driver_object,
        nullptr,
        &g_registry_callback_cookie,
        nullptr);
    g_registry_callback_registered = NT_SUCCESS(status);
    return status;
}

void unregister_registry_callback() {
    if (g_registry_callback_registered) {
        CmUnRegisterCallback(g_registry_callback_cookie);
        g_registry_callback_registered = FALSE;
        RtlZeroMemory(&g_registry_callback_cookie, sizeof(g_registry_callback_cookie));
    }
}

/*
 * Starting altitude for the object-callback registration.
 *
 * Deliberately one below the minifilter's EVERBLOOM_ALTITUDE_SHIPPED (the
 * Altitude string in package/everbloom_driver.inf): the two registrations must
 * not share a value, because an altitude collision is reported against the
 * altitude string and a self-collision would make the handle-protection
 * surface fail on every machine. Sitting one below the ceiling also leaves the
 * full EVERBLOOM_ALTITUDE_RETRY_LIMIT of headroom to step down into when
 * another driver already holds the value.
 */
constexpr uint32_t EVERBLOOM_OBJECT_CALLBACK_ALTITUDE = EVERBLOOM_ALTITUDE_SHIPPED - 1u;

NTSTATUS register_object_callbacks() {
    static OB_OPERATION_REGISTRATION operations[1] = {};
    operations[0].ObjectType = PsProcessType;
    operations[0].Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
    operations[0].PreOperation = EverbloomProcessHandlePreOperation;

    static OB_CALLBACK_REGISTRATION registration = {};
    registration.Version = OB_FLT_REGISTRATION_VERSION;
    registration.OperationRegistrationCount = 1;
    registration.RegistrationContext = nullptr;
    registration.OperationRegistration = operations;

    // The altitude string has to outlive the call, so both the text buffer and
    // the UNICODE_STRING that points at it are static.
    static WCHAR altitude_text[EVERBLOOM_ALTITUDE_MAX_DIGITS];
    static UNICODE_STRING altitude;

    // ObRegisterCallbacks reports STATUS_FLT_INSTANCE_ALTITUDE_COLLISION when
    // the altitude is already taken. Stepping down and retrying keeps an
    // unrelated collision from silently costing this machine its handle
    // protection - the surface is optional, so a failure here would otherwise
    // degrade with no user-visible signal.
    uint32_t candidate = EVERBLOOM_OBJECT_CALLBACK_ALTITUDE;
    for (uint32_t attempt = 0; attempt <= EVERBLOOM_ALTITUDE_RETRY_LIMIT; ++attempt) {
        const uint32_t length = everbloom_altitude_format(
            candidate, reinterpret_cast<uint16_t*>(altitude_text), EVERBLOOM_ALTITUDE_MAX_DIGITS);
        if (length == 0) {
            return STATUS_INVALID_PARAMETER;
        }
        altitude.Buffer = altitude_text;
        altitude.Length = (USHORT)(length * sizeof(WCHAR));
        altitude.MaximumLength = altitude.Length;
        registration.Altitude = altitude;

        const NTSTATUS status = ObRegisterCallbacks(&registration, &g_object_callback_handle);
        if (NT_SUCCESS(status)) {
            return status;
        }
        if (status != STATUS_FLT_INSTANCE_ALTITUDE_COLLISION) {
            return status;
        }
        uint32_t next = 0;
        if (everbloom_altitude_step_down(candidate, &next) != 0) {
            // Out of candidates inside the group: report the collision rather
            // than wander to an altitude this filter was not allocated.
            return status;
        }
        candidate = next;
    }
    return STATUS_FLT_INSTANCE_ALTITUDE_COLLISION;
}

void unregister_object_callbacks() {
    if (g_object_callback_handle != nullptr) {
        ObUnRegisterCallbacks(g_object_callback_handle);
        g_object_callback_handle = nullptr;
    }
}

FLT_PREOP_CALLBACK_STATUS FLTAPI EverbloomFilePreOperation(
    PFLT_CALLBACK_DATA data,
    PCFLT_RELATED_OBJECTS flt_objects,
    PVOID* completion_context) {
    UNREFERENCED_PARAMETER(flt_objects);
    UNREFERENCED_PARAMETER(completion_context);

    if (data == nullptr || data->Iopb == nullptr
        || FlagOn(data->Iopb->IrpFlags, IRP_PAGING_IO)) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    PFLT_FILE_NAME_INFORMATION name_information = nullptr;
    NTSTATUS status = FltGetFileNameInformation(
        data,
        FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT,
        &name_information);
    if (!NT_SUCCESS(status) || name_information == nullptr) {
        // A name lookup failure is not a reason to deny unrelated I/O. The
        // user-mode service can still observe the operation through ETW.
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    status = FltParseFileNameInformation(name_information);
    const BOOLEAN cookie_store_read = NT_SUCCESS(status)
        && EverbloomKernelPolicyIsDriverEnabled()
        && is_browser_cookie_store_path(&name_information->Name)
        && is_cookie_store_read_open(data)
        && !is_cookie_requestor_exempt();
    const BOOLEAN drivers_directory_module = NT_SUCCESS(status)
        && EverbloomKernelPolicyIsDriverEnabled()
        && is_driver_directory_sensitive_module(&name_information->Name);
    const BOOLEAN drivers_directory_write = drivers_directory_module
        && is_write_open_request(data);
    const BOOLEAN drivers_directory_delete_or_rename = drivers_directory_module
        && is_delete_or_rename_request(data);
    const BOOLEAN code_integrity_policy = NT_SUCCESS(status)
        && EverbloomKernelPolicyIsDriverEnabled()
        && is_code_integrity_policy_path(&name_information->Name);
    const BOOLEAN code_integrity_policy_mutation = code_integrity_policy
        && is_file_mutation_request(data);
    const BOOLEAN raw_disk = NT_SUCCESS(status) && is_raw_disk_path(&name_information->Name);
    const BOOLEAN mbr_write = raw_disk
        && data->Iopb->MajorFunction == IRP_MJ_WRITE
        && data->Iopb->Parameters.Write.ByteOffset.QuadPart >= 0
        && static_cast<ULONGLONG>(data->Iopb->Parameters.Write.ByteOffset.QuadPart)
            < 1024ULL * 1024ULL;
    const BOOLEAN raw_disk_open = raw_disk
        && data->Iopb->MajorFunction == IRP_MJ_CREATE
        && data->Iopb->Parameters.Create.SecurityContext != nullptr
        && (data->Iopb->Parameters.Create.SecurityContext->DesiredAccess
            & (FILE_WRITE_DATA | FILE_APPEND_DATA | DELETE)) != 0;
    const BOOLEAN vulnerable_driver = NT_SUCCESS(status)
        && EverbloomKernelPolicyIsDriverEnabled()
        && EverbloomKernelPolicyIsVulnerableDriverPath(&name_information->Name);
    const ULONG ransomware_write_signal = NT_SUCCESS(status)
        && EverbloomKernelPolicyIsDriverEnabled()
        && data->Iopb->MajorFunction == IRP_MJ_WRITE
        && record_ransomware_write(&name_information->Name);
    const BOOLEAN blocked = vulnerable_driver || cookie_store_read
        || code_integrity_policy_mutation
        || ransomware_write_signal != 0
        || ((mbr_write || raw_disk_open)
            && EverbloomKernelPolicyIsRawDiskBlocked(&name_information->Name));
    const BOOLEAN policy_blocked = NT_SUCCESS(status)
        && EverbloomKernelPolicyIsFileBlocked(&name_information->Name);
    const ULONG block_kind = vulnerable_driver
        ? EVERBLOOM_EVENT_KIND_FILE
        : cookie_store_read
        ? EVERBLOOM_EVENT_KIND_FILE
        : (mbr_write || raw_disk_open) ? EVERBLOOM_EVENT_KIND_RAW_DISK
                                       : EVERBLOOM_EVENT_KIND_FILE;
    const PCWSTR block_reason = vulnerable_driver
        ? L"known vulnerable driver image blocked before load"
        : cookie_store_read
        ? L"browser cookie store read blocked"
        : code_integrity_policy_mutation
        ? L"WDAC CodeIntegrity policy write or replacement blocked"
        : ransomware_write_signal == 2
            ? L"kernel slow ransomware document-write pattern blocked"
        : ransomware_write_signal == 1
            ? L"kernel ransomware write burst blocked"
        : (mbr_write || raw_disk_open)
            ? L"raw disk or MBR write blocked"
            : L"kernel file policy blocked operation";
    if (blocked || policy_blocked) {
        EverbloomKernelPolicyRecordBlock(block_kind, &name_information->Name, block_reason);
    } else if (drivers_directory_write || drivers_directory_delete_or_rename) {
        EverbloomKernelPolicyRecordEvent(
            EVERBLOOM_EVENT_KIND_FILE,
            &name_information->Name,
            drivers_directory_delete_or_rename
                ? L"suspicious drivers directory module self-delete or rename observed"
                : L"suspicious drivers directory module write observed",
            STATUS_SUCCESS);
    }
    FltReleaseFileNameInformation(name_information);

    if (!blocked && !policy_blocked) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    data->IoStatus.Status = STATUS_ACCESS_DENIED;
    data->IoStatus.Information = 0;
    return FLT_PREOP_COMPLETE;
}

NTSTATUS FLTAPI EverbloomFilterUnload(FLT_FILTER_UNLOAD_FLAGS flags) {
    UNREFERENCED_PARAMETER(flags);
    return STATUS_SUCCESS;
}

const FLT_OPERATION_REGISTRATION kFileOperations[] = {
    {IRP_MJ_CREATE, 0, EverbloomFilePreOperation, nullptr},
    {IRP_MJ_WRITE, 0, EverbloomFilePreOperation, nullptr},
    {IRP_MJ_SET_INFORMATION, 0, EverbloomFilePreOperation, nullptr},
    {IRP_MJ_OPERATION_END}
};

const FLT_REGISTRATION kFilterRegistration = {
    sizeof(FLT_REGISTRATION),
    FLT_REGISTRATION_VERSION,
    0,
    nullptr,
    kFileOperations,
    EverbloomFilterUnload
};

/*
 * Advisory kernel model score for one process creation.
 *
 * This path never vetoes. The model sees only the image path and the command
 * line - not the file's bytes, its signature, or what the user-mode engine has
 * correlated - so its output is a triage hint and the user-mode engine remains
 * the authority on behaviour. Only a launch that crosses the model's own
 * advisory threshold is recorded, which keeps the bounded event ring from
 * filling with ordinary process creations.
 *
 * The score travels in the event's Status field rather than in the reason
 * string; see the comment on EVERBLOOM_EVENT_KIND_MODEL_SCORE in
 * everbloom_driver_protocol.h for why.
 */
VOID record_advisory_model_score(PPS_CREATE_NOTIFY_INFO create_info) {
    if (create_info == nullptr
        || create_info->ImageFileName == nullptr
        || !EverbloomKernelPolicyIsDriverEnabled()) {
        return;
    }

    // A build with no model linked in reports no capability and produces no
    // score events, so there is nothing to record.
    const EVERBLOOM_MATRIX_MODEL* model = EverbloomKernelModelGet();
    if (model == nullptr) {
        return;
    }

    const auto* image_name = reinterpret_cast<const uint16_t*>(
        create_info->ImageFileName->Buffer);
    const uint32_t image_name_length =
        create_info->ImageFileName->Length / sizeof(WCHAR);

    const uint16_t* command_line = nullptr;
    uint32_t command_line_length = 0;
    if (create_info->CommandLine != nullptr) {
        command_line = reinterpret_cast<const uint16_t*>(
            create_info->CommandLine->Buffer);
        command_line_length = create_info->CommandLine->Length / sizeof(WCHAR);
    }

    int32_t score = 0;
    if (!everbloom_kernel_model_score_launch(
            image_name,
            image_name_length,
            command_line,
            command_line_length,
            &score)) {
        return;
    }
    if (score < model->output_threshold) {
        return;
    }

    EverbloomKernelPolicyRecordEvent(
        EVERBLOOM_EVENT_KIND_MODEL_SCORE,
        create_info->ImageFileName,
        L"kernel model flagged process launch (advisory)",
        static_cast<NTSTATUS>(score));
}

VOID NTAPI EverbloomProcessNotify(
    PEPROCESS process,
    HANDLE process_id,
    PPS_CREATE_NOTIFY_INFO create_info) {
    UNREFERENCED_PARAMETER(process);
    UNREFERENCED_PARAMETER(process_id);

    if (create_info == nullptr || create_info->ImageFileName == nullptr) {
        return;
    }

    // The policy matcher canonicalizes DOS/device namespaces and 8.3
    // components. When the file object is available, also ask Filter Manager
    // for its normalized name so a reparse-point/symlink presentation cannot
    // become a policy blind spot.
    const BOOLEAN backup_destruction = EverbloomKernelPolicyIsDriverEnabled()
        && is_backup_destruction_command(
            create_info->ImageFileName,
            create_info->CommandLine);
    BOOLEAN blocked = backup_destruction
        || EverbloomKernelPolicyIsProcessBlocked(create_info->ImageFileName);
    PFLT_FILE_NAME_INFORMATION normalized_name = nullptr;
    if (!blocked && create_info->FileObject != nullptr
        && NT_SUCCESS(FltGetFileNameInformationUnsafe(
            create_info->FileObject,
            nullptr,
            FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT,
            &normalized_name))
        && normalized_name != nullptr) {
        blocked = EverbloomKernelPolicyIsProcessBlocked(&normalized_name->Name);
        FltReleaseFileNameInformation(normalized_name);
    }
    if (blocked) {
        EverbloomKernelPolicyRecordBlock(
            EVERBLOOM_EVENT_KIND_PROCESS,
            create_info->ImageFileName,
            backup_destruction
                ? L"destructive backup or recovery command blocked"
                : L"kernel process policy blocked process creation");
        // PS_CREATE_NOTIFY_INFO is explicitly in/out. Setting CreationStatus
        // vetoes this process creation before the initial thread is exposed.
        create_info->CreationStatus = STATUS_ACCESS_DENIED;
        // This launch already produced a PROCESS event, so scoring it as well
        // would emit two events for one creation.
        return;
    }

    record_advisory_model_score(create_info);
}

VOID NTAPI EverbloomImageNotify(
    PUNICODE_STRING full_image_name,
    HANDLE process_id,
    PIMAGE_INFO image_info) {
    // Image-load notifications cannot veto a load. They still detect a
    // known vulnerable driver that was present before EverbloomSecurity started. New
    // opens are denied by the file minifilter before the loader can use them.
    if (!EverbloomKernelPolicyIsDriverEnabled()
        || process_id != nullptr
        || image_info == nullptr
        || !image_info->SystemModeImage
        || full_image_name == nullptr
        || !EverbloomKernelPolicyIsVulnerableDriverPath(full_image_name)) {
        return;
    }
    EverbloomKernelPolicyRecordBlock(
        EVERBLOOM_EVENT_KIND_FILE,
        full_image_name,
        L"known vulnerable driver was already loaded before policy enforcement");
}

VOID NTAPI EverbloomWfpClassify(
    const FWPS_INCOMING_VALUES0* fixed_values,
    const FWPS_INCOMING_METADATA_VALUES0* metadata_values,
    VOID* layer_data,
    const VOID* classify_context,
    const FWPS_FILTER2* filter,
    UINT64 flow_context,
    FWPS_CLASSIFY_OUT0* classify_out) {
    UNREFERENCED_PARAMETER(metadata_values);
    UNREFERENCED_PARAMETER(layer_data);
    UNREFERENCED_PARAMETER(classify_context);
    UNREFERENCED_PARAMETER(filter);
    UNREFERENCED_PARAMETER(flow_context);

    constexpr UINT32 kRemotePortField =
        FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_REMOTE_PORT;
    if (fixed_values == nullptr || fixed_values->incomingValue == nullptr
        || fixed_values->valueCount <= kRemotePortField
        || classify_out == nullptr
        || (classify_out->rights & FWPS_RIGHT_ACTION_WRITE) == 0) {
        return;
    }

    if (fixed_values->layerId != FWPS_LAYER_ALE_AUTH_CONNECT_V4) {
        classify_out->actionType = FWP_ACTION_CONTINUE;
        return;
    }

    const auto& remote_address = fixed_values->incomingValue[
        FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_REMOTE_ADDRESS];
    const auto& remote_port = fixed_values->incomingValue[
        FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_REMOTE_PORT];
    if (remote_address.value.type == FWP_UINT32
        && remote_port.value.type == FWP_UINT16
        && EverbloomKernelPolicyIsNetworkBlocked(
            remote_address.value.uint32,
            remote_port.value.uint16)) {
        EverbloomKernelPolicyRecordBlock(
            EVERBLOOM_EVENT_KIND_NETWORK,
            nullptr,
            L"kernel network policy blocked connection");
        classify_out->actionType = FWP_ACTION_BLOCK;
        // A terminating block must retain its decision against lower-priority
        // callouts, as required by the WFP classify contract.
        classify_out->rights &= ~FWPS_RIGHT_ACTION_WRITE;
        return;
    }

    classify_out->actionType = FWP_ACTION_CONTINUE;
}

NTSTATUS NTAPI EverbloomWfpNotify(
    FWPS_CALLOUT_NOTIFY_TYPE notify_type,
    const GUID* filter_key,
    FWPS_FILTER2* filter) {
    UNREFERENCED_PARAMETER(notify_type);
    UNREFERENCED_PARAMETER(filter_key);
    UNREFERENCED_PARAMETER(filter);
    return STATUS_SUCCESS;
}

VOID remove_wfp_filter();

NTSTATUS add_wfp_filter() {
    FWPM_SESSION0 session = {};
    session.displayData.name = const_cast<wchar_t*>(L"EverbloomSecurity dynamic policy");
    session.flags = FWPM_SESSION_FLAG_DYNAMIC;

    NTSTATUS status = FwpmEngineOpen0(
        nullptr,
        RPC_C_AUTHN_WINNT,
        nullptr,
        &session,
        &g_wfp_engine);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    FWPM_SUBLAYER0 sublayer = {};
    sublayer.subLayerKey = kWfpSublayerKey;
    sublayer.displayData.name = const_cast<wchar_t*>(L"EverbloomSecurity policy sublayer");
    sublayer.weight = 0x8000;
    status = FwpmSubLayerAdd0(g_wfp_engine, &sublayer, nullptr);
    if (!NT_SUCCESS(status)) {
        remove_wfp_filter();
        return status;
    }

    FWPS_CALLOUT2 runtime_callout = {};
    runtime_callout.calloutKey = kWfpCalloutKey;
    runtime_callout.classifyFn = EverbloomWfpClassify;
    runtime_callout.notifyFn = EverbloomWfpNotify;
    status = FwpsCalloutRegister2(nullptr, &runtime_callout, &g_wfp_callout_id);
    if (!NT_SUCCESS(status)) {
        remove_wfp_filter();
        return status;
    }

    FWPM_CALLOUT0 management_callout = {};
    management_callout.calloutKey = kWfpCalloutKey;
    management_callout.displayData.name = const_cast<wchar_t*>(L"EverbloomSecurity network block callout");
    management_callout.applicableLayer = FWPM_LAYER_ALE_AUTH_CONNECT_V4;
    status = FwpmCalloutAdd0(g_wfp_engine, &management_callout, nullptr, nullptr);
    if (!NT_SUCCESS(status)) {
        remove_wfp_filter();
        return status;
    }

    FWPM_FILTER0 filter = {};
    filter.filterKey = kWfpFilterKey;
    filter.displayData.name = const_cast<wchar_t*>(L"EverbloomSecurity IPv4 connection policy");
    filter.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V4;
    filter.subLayerKey = kWfpSublayerKey;
    filter.weight.type = FWP_UINT8;
    filter.weight.uint8 = 0xf0;
    filter.action.type = FWP_ACTION_CALLOUT_TERMINATING;
    filter.action.calloutKey = kWfpCalloutKey;
    status = FwpmFilterAdd0(g_wfp_engine, &filter, nullptr, &g_wfp_filter_id);
    if (!NT_SUCCESS(status)) {
        remove_wfp_filter();
    }
    return status;
}

VOID remove_wfp_filter() {
    if (g_wfp_engine == nullptr) {
        return;
    }
    if (g_wfp_filter_id != 0) {
        FwpmFilterDeleteById0(g_wfp_engine, g_wfp_filter_id);
        g_wfp_filter_id = 0;
    }
    FwpmCalloutDeleteByKey0(g_wfp_engine, &kWfpCalloutKey);
    FwpmSubLayerDeleteByKey0(g_wfp_engine, &kWfpSublayerKey);
    FwpmEngineClose0(g_wfp_engine);
    g_wfp_engine = nullptr;
    if (g_wfp_callout_id != 0) {
        FwpsCalloutUnregisterById0(g_wfp_callout_id);
        g_wfp_callout_id = 0;
    }
}

// --- optional altitude override (debug only) -------------------------------
//
// FltStartFiltering attaches instances using the altitude recorded in the
// service's Instances key. A test deployment that cannot wait for a Microsoft
// altitude allocation, or that collides with a vendor already holding the
// value, can instead attach at a chosen altitude with FltAttachVolumeAtAltitude.
//
// Microsoft documents that routine as debugging support that a retail
// minifilter must not call, so it is opt-in and additive here:
//
//   * it runs only when the service key carries AltitudeOverride (REG_SZ);
//   * it runs after the normal attach, so the default path is untouched;
//   * it never fails the file-filter surface - the normal attach already
//     happened, and a debug override that cannot be satisfied must not cost
//     the machine its file protection.
//
//   HKLM\SYSTEM\CurrentControlSet\Services\<service>\AltitudeOverride = "329000"
//
// On STATUS_FLT_INSTANCE_ALTITUDE_COLLISION the altitude is stepped down and
// retried a bounded number of times (everbloom_altitude.h owns that
// arithmetic, and is verified by everbloom_kernel_altitude_tests).

const WCHAR kAltitudeOverrideValue[] = L"AltitudeOverride";
const WCHAR kDriverNamePrefix[] = L"\\Driver\\";
const ULONG kDriverNamePrefixChars = 8;
constexpr ULONG kAltitudePoolTag = 'tAlA';

struct AltitudeOverrideBuffer {
    uint16_t text[EVERBLOOM_ALTITUDE_MAX_DIGITS];
    uint32_t length;
};

NTSTATUS NTAPI altitude_override_query(
    PWSTR value_name,
    ULONG value_type,
    PVOID value_data,
    ULONG value_length,
    PVOID context,
    PVOID entry_context) {
    UNREFERENCED_PARAMETER(value_name);
    UNREFERENCED_PARAMETER(context);

    AltitudeOverrideBuffer* out = static_cast<AltitudeOverrideBuffer*>(entry_context);
    if (out == nullptr || value_data == nullptr) {
        return STATUS_INVALID_PARAMETER;
    }
    // Only REG_SZ carries an altitude here. Accepting REG_MULTI_SZ would mean
    // guessing which of several strings was meant, so it is rejected instead.
    if (value_type != REG_SZ) {
        return STATUS_INVALID_PARAMETER;
    }
    uint32_t characters = value_length / sizeof(WCHAR);
    const WCHAR* text = static_cast<const WCHAR*>(value_data);
    // REG_SZ includes its terminator in the reported length.
    while (characters > 0 && text[characters - 1] == L'\0') {
        --characters;
    }
    if (characters == 0 || characters > EVERBLOOM_ALTITUDE_MAX_DIGITS) {
        return STATUS_INVALID_PARAMETER;
    }
    for (uint32_t index = 0; index < characters; ++index) {
        out->text[index] = (uint16_t)text[index];
    }
    out->length = characters;
    return STATUS_SUCCESS;
}

NTSTATUS read_altitude_override(PDRIVER_OBJECT driver_object, AltitudeOverrideBuffer* out) {
    out->length = 0;
    if (driver_object == nullptr) {
        return STATUS_INVALID_PARAMETER;
    }
    // DriverName is an embedded UNICODE_STRING, not a pointer, and it holds
    // the object name (\Driver\<service>) rather than a registry path.
    const UNICODE_STRING& driver_name = driver_object->DriverName;
    if (driver_name.Buffer == nullptr) {
        return STATUS_INVALID_PARAMETER;
    }
    const uint32_t name_characters = driver_name.Length / sizeof(WCHAR);
    if (name_characters <= kDriverNamePrefixChars) {
        return STATUS_INVALID_PARAMETER;
    }

    // \Driver\<service> -> <service>, which is the key name under Services.
    WCHAR service[64];
    const uint32_t service_characters = name_characters - kDriverNamePrefixChars;
    const uint32_t service_capacity = (uint32_t)(sizeof(service) / sizeof(service[0]));
    if (service_characters >= service_capacity) {
        return STATUS_NAME_TOO_LONG;
    }
    for (uint32_t index = 0; index < service_characters; ++index) {
        service[index] = driver_name.Buffer[kDriverNamePrefixChars + index];
    }
    service[service_characters] = L'\0';

    RTL_QUERY_REGISTRY_TABLE table[2] = {};
    table[0].QueryRoutine = altitude_override_query;
    // Required: a missing value must fail, because absence is how the caller
    // learns that no override was configured.
    table[0].Flags = RTL_QUERY_REGISTRY_REQUIRED;
    table[0].Name = const_cast<PWSTR>(kAltitudeOverrideValue);
    table[0].EntryContext = out;

    return RtlQueryRegistryValues(RTL_REGISTRY_SERVICES, service, table, nullptr, nullptr);
}

NTSTATUS attach_volumes_at_override_altitude(PDRIVER_OBJECT driver_object, PFLT_FILTER filter) {
    AltitudeOverrideBuffer override_buffer{};
    NTSTATUS status = read_altitude_override(driver_object, &override_buffer);
    if (!NT_SUCCESS(status) || override_buffer.length == 0) {
        return STATUS_NOT_FOUND;
    }

    uint32_t altitude = 0;
    if (everbloom_altitude_parse(override_buffer.text, override_buffer.length, &altitude) != 0) {
        return STATUS_INVALID_PARAMETER;
    }

    ULONG volume_count = 0;
    status = FltEnumerateVolumes(filter, nullptr, 0, &volume_count);
    if (volume_count == 0) {
        return STATUS_NOT_FOUND;
    }
    if (status != STATUS_BUFFER_TOO_SMALL && !NT_SUCCESS(status)) {
        return status;
    }

    PFLT_VOLUME* volumes = static_cast<PFLT_VOLUME*>(
        ExAllocatePool2(POOL_FLAG_NON_PAGED, (SIZE_T)volume_count * sizeof(PFLT_VOLUME), kAltitudePoolTag));
    if (volumes == nullptr) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    ULONG returned = 0;
    status = FltEnumerateVolumes(filter, volumes, volume_count, &returned);
    if (!NT_SUCCESS(status)) {
        ExFreePoolWithTag(volumes, kAltitudePoolTag);
        return status;
    }

    uint32_t attached = 0;
    for (ULONG index = 0; index < returned; ++index) {
        uint32_t candidate = altitude;
        for (uint32_t attempt = 0; attempt <= EVERBLOOM_ALTITUDE_RETRY_LIMIT; ++attempt) {
            uint16_t text[EVERBLOOM_ALTITUDE_MAX_DIGITS];
            const uint32_t length =
                everbloom_altitude_format(candidate, text, EVERBLOOM_ALTITUDE_MAX_DIGITS);
            if (length == 0) {
                break;
            }
            UNICODE_STRING altitude_string;
            altitude_string.Buffer = reinterpret_cast<PWSTR>(text);
            altitude_string.Length = (USHORT)(length * sizeof(WCHAR));
            altitude_string.MaximumLength = altitude_string.Length;

            PFLT_INSTANCE instance = nullptr;
            const NTSTATUS attach_status = FltAttachVolumeAtAltitude(
                filter, volumes[index], &altitude_string, nullptr, &instance);
            if (NT_SUCCESS(attach_status)) {
                if (instance != nullptr) {
                    // A successful attach adds a rundown reference.
                    FltObjectDereference(instance);
                }
                ++attached;
                break;
            }
            if (attach_status != STATUS_FLT_INSTANCE_ALTITUDE_COLLISION) {
                break;
            }
            uint32_t next = 0;
            if (everbloom_altitude_step_down(candidate, &next) != 0) {
                break;
            }
            candidate = next;
        }
        FltObjectDereference(volumes[index]);
    }

    ExFreePoolWithTag(volumes, kAltitudePoolTag);
    return (attached > 0) ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
}

// --- enforcement matrix ----------------------------------------------------
//
// One row per enforcement surface. `required` rows abort initialization when
// the platform refuses them; optional rows degrade. The table is walked
// forward to install and backward to remove, so rollback can never fall out of
// step with installation, and `capability_flags` records what the surface
// actually backs (0 means the surface is internal and has no user-mode bit).
//
// Before this table existed, the install sequence, the uninstall sequence and
// the capability flags were three separate hand-written lists, and the file
// filter's two-step registration (FltRegisterFilter then FltStartFiltering)
// was spread across the caller.

struct EnforcementRow {
    const char* name;
    BOOLEAN required;
    ULONG64 capability_flags;
    NTSTATUS (*install)(PDRIVER_OBJECT driver_object);
    VOID (*remove)();
    volatile LONG installed;
};

NTSTATUS install_process_notify(PDRIVER_OBJECT driver_object) {
    UNREFERENCED_PARAMETER(driver_object);
    return PsSetCreateProcessNotifyRoutineEx(EverbloomProcessNotify, FALSE);
}

VOID remove_process_notify() {
    (void)PsSetCreateProcessNotifyRoutineEx(EverbloomProcessNotify, TRUE);
}

NTSTATUS install_file_filter(PDRIVER_OBJECT driver_object) {
    NTSTATUS status = FltRegisterFilter(driver_object, &kFilterRegistration, &g_file_filter);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    status = FltStartFiltering(g_file_filter);
    if (!NT_SUCCESS(status)) {
        // A registered-but-not-started filter is still owned by the Filter
        // Manager. Undo it here so the row's remove path stays symmetric and
        // shutdown never sees a half-installed surface.
        FltUnregisterFilter(g_file_filter);
        g_file_filter = nullptr;
        return status;
    }
    // Debug-only and deliberately non-fatal: the normal attach has already
    // happened, so a failed override must not tear the surface back down.
    (void)attach_volumes_at_override_altitude(driver_object, g_file_filter);
    return STATUS_SUCCESS;
}

VOID remove_file_filter() {
    if (g_file_filter != nullptr) {
        FltUnregisterFilter(g_file_filter);
        g_file_filter = nullptr;
    }
}

NTSTATUS install_network_wfp(PDRIVER_OBJECT driver_object) {
    UNREFERENCED_PARAMETER(driver_object);
    return add_wfp_filter();
}

VOID remove_network_wfp() {
    remove_wfp_filter();
}

// Observation only: Windows exposes no supported veto from the image-load
// notification path, so this surface never blocks and is optional.
NTSTATUS install_image_notify(PDRIVER_OBJECT driver_object) {
    UNREFERENCED_PARAMETER(driver_object);
    return PsSetLoadImageNotifyRoutine(EverbloomImageNotify);
}

VOID remove_image_notify() {
    (void)PsRemoveLoadImageNotifyRoutine(EverbloomImageNotify);
}

NTSTATUS install_registry(PDRIVER_OBJECT driver_object) {
    return register_registry_callback(driver_object);
}

VOID remove_registry() {
    unregister_registry_callback();
}

NTSTATUS install_object_handle(PDRIVER_OBJECT driver_object) {
    UNREFERENCED_PARAMETER(driver_object);
    return register_object_callbacks();
}

VOID remove_object_handle() {
    unregister_object_callbacks();
}

EnforcementRow g_enforcement_matrix[EVERBLOOM_ENFORCEMENT_SURFACE_COUNT] = {
    { "process_notify", TRUE, 0,
      install_process_notify, remove_process_notify, 0 },
    { "file_filter", TRUE, EVERBLOOM_CAPABILITY_RAW_DISK_POLICY,
      install_file_filter, remove_file_filter, 0 },
    { "network_wfp", TRUE, EVERBLOOM_CAPABILITY_NETWORK_POLICY,
      install_network_wfp, remove_network_wfp, 0 },
    { "image_notify", FALSE, 0,
      install_image_notify, remove_image_notify, 0 },
    { "registry", FALSE, EVERBLOOM_CAPABILITY_REGISTRY_POLICY,
      install_registry, remove_registry, 0 },
    { "object_handle", FALSE, 0,
      install_object_handle, remove_object_handle, 0 },
};

// The row index is the surface index: `EverbloomKernelComponentsActiveSurfaces`
// reports bit `i` for row `i`, and `EverbloomEnforcement*` enumerators are what
// callers use to name those bits. A row added or removed without updating the
// header would silently shift every surface id, so the count is pinned here.
static_assert(
    sizeof(g_enforcement_matrix) / sizeof(g_enforcement_matrix[0])
        == EVERBLOOM_ENFORCEMENT_SURFACE_COUNT,
    "enforcement matrix must have exactly one row per declared surface");

BOOLEAN surface_is_installed(const EnforcementRow& row) {
    return InterlockedCompareExchange(
               const_cast<volatile LONG*>(&row.installed), 0, 0) != 0;
}

} // namespace

ULONG64 EverbloomKernelComponentsActiveSurfaces() {
    ULONG64 active = 0;
    for (ULONG index = 0; index < EVERBLOOM_ENFORCEMENT_SURFACE_COUNT; ++index) {
        if (surface_is_installed(g_enforcement_matrix[index])) {
            active |= (1ULL << index);
        }
    }
    return active;
}

ULONG64 EverbloomKernelComponentsCapabilityFlags() {
    // The control plane exists whenever the driver is loaded: the control
    // device, its IOCTL ABI and the nonpaged event ring do not depend on any
    // callback being accepted by the platform. `EVERBLOOM_CAPABILITY_SCAN_FILE`
    // is served by `dispatch_device_control`, not by the minifilter, so it
    // stays unconditional and `is_compatible()` on the user-mode side keeps
    // its meaning.
    ULONG64 flags = EVERBLOOM_CAPABILITY_SCAN_FILE
        | EVERBLOOM_CAPABILITY_BEHAVIOR_ANALYZE
        | EVERBLOOM_CAPABILITY_POLICY_UPDATE
        | EVERBLOOM_CAPABILITY_PROTECTION_UPDATE
        | EVERBLOOM_CAPABILITY_EVENT_READ;

    // Enforcement capabilities are derived, not asserted. Previously all eight
    // flags were reported unconditionally while the registry and object
    // callbacks were installed with `(void)`, so the driver advertised registry
    // and network enforcement that the platform may have refused.
    for (ULONG index = 0; index < EVERBLOOM_ENFORCEMENT_SURFACE_COUNT; ++index) {
        if (surface_is_installed(g_enforcement_matrix[index])) {
            flags |= g_enforcement_matrix[index].capability_flags;
        }
    }

    // The inference model is advertised only when one is actually linked in, so
    // user mode does not wait for MODEL_SCORE events a build without a model can
    // never emit. Process creation is a required surface, so any driver that
    // gets this far is able to emit them.
    if (EverbloomKernelModelGet() != nullptr) {
        flags |= EVERBLOOM_CAPABILITY_KERNEL_MODEL;
    }
    return flags;
}

NTSTATUS EverbloomKernelComponentsInitialize(PDRIVER_OBJECT driver_object) {
    if (driver_object == nullptr) {
        return STATUS_INVALID_PARAMETER;
    }

    KeInitializeSpinLock(&g_ransom_tracker_lock);
    RtlZeroMemory(g_ransom_trackers, sizeof(g_ransom_trackers));
    for (ULONG index = 0; index < EVERBLOOM_ENFORCEMENT_SURFACE_COUNT; ++index) {
        InterlockedExchange(
            const_cast<volatile LONG*>(&g_enforcement_matrix[index].installed), 0);
    }

    for (ULONG index = 0; index < EVERBLOOM_ENFORCEMENT_SURFACE_COUNT; ++index) {
        EnforcementRow& row = g_enforcement_matrix[index];
        const NTSTATUS status = row.install(driver_object);
        if (NT_SUCCESS(status)) {
            InterlockedExchange(const_cast<volatile LONG*>(&row.installed), 1);
            continue;
        }
        if (row.required) {
            // Roll back everything already installed by walking the same table
            // backward. There is no separate rollback list to keep in sync.
            EverbloomKernelComponentsShutdown();
            return status;
        }
        // Optional hardening surfaces may be refused for signing or altitude
        // reasons. The remaining enforcement stays available and the capability
        // query simply stops advertising this one.
    }
    return STATUS_SUCCESS;
}

VOID EverbloomKernelComponentsShutdown() {
    for (ULONG index = EVERBLOOM_ENFORCEMENT_SURFACE_COUNT; index > 0; --index) {
        EnforcementRow& row = g_enforcement_matrix[index - 1];
        // Exchange to 0 first: a surface is only torn down once even if
        // shutdown is reached twice (for example through the rollback path
        // followed by DriverUnload).
        if (InterlockedExchange(const_cast<volatile LONG*>(&row.installed), 0) != 0) {
            row.remove();
        }
    }
    KIRQL old_irql = PASSIVE_LEVEL;
    KeAcquireSpinLock(&g_ransom_tracker_lock, &old_irql);
    RtlZeroMemory(g_ransom_trackers, sizeof(g_ransom_trackers));
    KeReleaseSpinLock(&g_ransom_tracker_lock, old_irql);
}
