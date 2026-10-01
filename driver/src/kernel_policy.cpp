#include "kernel_policy.hpp"

namespace {

constexpr ULONG kMaximumRules = 64;
constexpr ULONG kMaximumEvents = 128;
constexpr USHORT kMaximumRuleBytes = EVERBLOOM_MAX_TARGET_CHARS * sizeof(WCHAR);
constexpr ULONG kPoolTag = 'pHyH';

struct OwnedUnicodeRule {
    UNICODE_STRING value;
};

struct NetworkRule {
    ULONG ipv4_address;
    USHORT port;
};

struct KernelPolicyState {
    // WFP classify callbacks may execute at DISPATCH_LEVEL. A spin lock keeps
    // all policy lookups valid at that IRQL; rules are bounded and the lock is
    // held only for a short linear scan.
    KSPIN_LOCK lock;
    ULONG process_count;
    ULONG file_count;
    ULONG registry_count;
    ULONG raw_disk_count;
    ULONG network_count;
    BOOLEAN r3_enabled;
    BOOLEAN driver_enabled;
    OwnedUnicodeRule processes[kMaximumRules];
    OwnedUnicodeRule files[kMaximumRules];
    OwnedUnicodeRule registry[kMaximumRules];
    OwnedUnicodeRule raw_disks[kMaximumRules];
    NetworkRule networks[kMaximumRules];
    KSPIN_LOCK event_lock;
    ULONG event_head;
    ULONG event_count;
    ULONG event_dropped;
    ULONGLONG next_event_sequence;
    EVERBLOOM_DRIVER_EVENT events[kMaximumEvents];
};

KernelPolicyState g_policy = {};

struct PathParts {
    WCHAR buffer[EVERBLOOM_MAX_TARGET_CHARS + 1];
    USHORT length;
};

BOOLEAN is_ascii_digit(WCHAR value) {
    return value >= L'0' && value <= L'9';
}

BOOLEAN equal_component(
    PCWSTR left,
    USHORT left_length,
    PCWSTR right,
    USHORT right_length) {
    if (left == nullptr || right == nullptr) {
        return FALSE;
    }
    if (left_length == right_length
        && RtlCompareMemory(left, right, left_length * sizeof(WCHAR))
            == left_length * sizeof(WCHAR)) {
        return TRUE;
    }

    // 8.3 aliases are not resolved at DISPATCH_LEVEL. Treat a syntactically
    // valid alias as equivalent to the long component so a short-name path
    // cannot evade a path rule. This is intentionally conservative and only
    // applies when the non-alias component has the same extension.
    auto alias_matches_long = [](PCWSTR alias, USHORT alias_length,
                                 PCWSTR long_name, USHORT long_length) -> BOOLEAN {
        USHORT tilde = 0xffff;
        USHORT dot = 0xffff;
        for (USHORT index = 0; index < alias_length; ++index) {
            if (alias[index] == L'~' && tilde == 0xffff) {
                tilde = index;
            } else if (alias[index] == L'.' && dot == 0xffff) {
                dot = index;
            }
        }
        if (tilde == 0xffff || tilde == 0 || tilde > 8
            || tilde + 1 >= alias_length) {
            return FALSE;
        }
        const USHORT alias_extension_start = dot == 0xffff ? alias_length : dot;
        for (USHORT index = tilde + 1; index < alias_extension_start; ++index) {
            if (!is_ascii_digit(alias[index])) {
                return FALSE;
            }
        }
        USHORT long_dot = 0xffff;
        for (USHORT index = 0; index < long_length; ++index) {
            if (long_name[index] == L'.') {
                long_dot = index;
                break;
            }
        }
        const USHORT long_extension_start = long_dot == 0xffff ? long_length : long_dot;
        const USHORT alias_extension_length = alias_length - alias_extension_start;
        const USHORT long_extension_length = long_length - long_extension_start;
        if (alias_extension_length != long_extension_length
            || alias_extension_length > 0
                && RtlCompareMemory(
                    alias + alias_extension_start,
                    long_name + long_extension_start,
                    alias_extension_length * sizeof(WCHAR))
                    != alias_extension_length * sizeof(WCHAR)) {
            return FALSE;
        }
        if (long_extension_start < tilde) {
            return FALSE;
        }
        return RtlCompareMemory(
                   alias,
                   long_name,
                   tilde * sizeof(WCHAR))
            == tilde * sizeof(WCHAR);
    };

    return alias_matches_long(left, left_length, right, right_length)
        || alias_matches_long(right, right_length, left, left_length);
}

BOOLEAN normalize_path(PCUNICODE_STRING source, PathParts* destination) {
    if (source == nullptr || destination == nullptr || source->Buffer == nullptr
        || (source->Length % sizeof(WCHAR)) != 0) {
        return FALSE;
    }
    const USHORT source_length = source->Length / sizeof(WCHAR);
    if (source_length == 0) {
        return FALSE;
    }

    USHORT start = 0;
    if (source_length > EVERBLOOM_MAX_TARGET_CHARS) {
        // Rules are bounded by the control-plane ABI, but normalized kernel
        // names can be longer. Keep only a complete suffix component; policy
        // matching is suffix-based for volume aliases.
        start = static_cast<USHORT>(source_length - EVERBLOOM_MAX_TARGET_CHARS);
        while (start < source_length
               && source->Buffer[start] != L'\\'
               && source->Buffer[start] != L'/') {
            ++start;
        }
        if (start < source_length) {
            ++start;
        }
    }
    if (start == 0 && source_length >= 4
        && source->Buffer[0] == L'\\' && source->Buffer[1] == L'\\'
        && source->Buffer[2] == L'?' && source->Buffer[3] == L'\\') {
        start = 4; // \\?\C:\...
    } else if (start == 0 && source_length >= 4
               && source->Buffer[0] == L'\\' && source->Buffer[1] == L'?'
               && source->Buffer[2] == L'?' && source->Buffer[3] == L'\\') {
        start = 4; // \??\C:\...
    } else if (start == 0 && source_length >= 12
               && RtlCompareMemory(source->Buffer, L"\\DosDevices\\", 12 * sizeof(WCHAR))
                   == 12 * sizeof(WCHAR)) {
        start = 12;
    }

    USHORT segment_starts[64] = {};
    ULONG segment_count = 0;
    USHORT output_length = 0;
    while (start < source_length) {
        while (start < source_length
               && (source->Buffer[start] == L'\\' || source->Buffer[start] == L'/')) {
            ++start;
        }
        if (start >= source_length) {
            break;
        }
        USHORT end = start;
        while (end < source_length
               && source->Buffer[end] != L'\\' && source->Buffer[end] != L'/') {
            ++end;
        }
        const USHORT component_length = end - start;
        const BOOLEAN dot = component_length == 1 && source->Buffer[start] == L'.';
        const BOOLEAN dot_dot = component_length == 2
            && source->Buffer[start] == L'.' && source->Buffer[start + 1] == L'.';
        if (dot) {
            start = end;
            continue;
        }
        if (dot_dot) {
            if (segment_count > 0) {
                output_length = segment_starts[--segment_count];
                if (output_length > 0 && destination->buffer[output_length - 1] == L'\\') {
                    --output_length;
                }
            }
            start = end;
            continue;
        }
        if (segment_count >= RTL_NUMBER_OF(segment_starts)
            || output_length + component_length + 1 > RTL_NUMBER_OF(destination->buffer)) {
            return FALSE;
        }
        if (output_length > 0 && destination->buffer[output_length - 1] != L'\\') {
            destination->buffer[output_length++] = L'\\';
        }
        segment_starts[segment_count++] = output_length;
        for (USHORT index = 0; index < component_length; ++index) {
            WCHAR value = source->Buffer[start + index];
            if (value >= L'a' && value <= L'z') {
                value = static_cast<WCHAR>(value - (L'a' - L'A'));
            }
            destination->buffer[output_length++] = value == L'/' ? L'\\' : value;
        }
        start = end;
    }
    destination->buffer[output_length] = L'\0';
    destination->length = output_length;
    return output_length != 0;
}

ULONG split_components(const PathParts* path, USHORT* starts, USHORT* lengths, ULONG capacity) {
    if (path == nullptr || starts == nullptr || lengths == nullptr) {
        return 0;
    }
    ULONG count = 0;
    USHORT offset = 0;
    while (offset < path->length && count < capacity) {
        while (offset < path->length && path->buffer[offset] == L'\\') {
            ++offset;
        }
        if (offset >= path->length) {
            break;
        }
        const USHORT begin = offset;
        while (offset < path->length && path->buffer[offset] != L'\\') {
            ++offset;
        }
        starts[count] = begin;
        lengths[count] = offset - begin;
        ++count;
    }
    return count;
}

BOOLEAN is_known_vulnerable_driver_basename(PCWSTR value, USHORT length) {
    if (value == nullptr || length == 0) {
        return FALSE;
    }
    static const PCWSTR kNames[] = {
        L"BDAPIUTIL64.SYS",
        L"ZAM64.SYS",
        L"BOOTREPAIR.SYS",
        L"ENPORTV.SYS",
        L"WSFTPRM.SYS",
        L"TRUESIGHTKILLER.SYS",
        L"LLAMA.SYS",
        L"OLLAMA.SYS",
    };
    for (const auto* name : kNames) {
        const USHORT name_length = static_cast<USHORT>(wcslen(name));
        if (name_length == length
            && RtlCompareMemory(value, name, length * sizeof(WCHAR))
                == length * sizeof(WCHAR)) {
            return TRUE;
        }
    }
    return FALSE;
}

VOID free_rule(OwnedUnicodeRule* rule) {
    if (rule == nullptr || rule->value.Buffer == nullptr) {
        return;
    }
    ExFreePoolWithTag(rule->value.Buffer, kPoolTag);
    RtlZeroMemory(&rule->value, sizeof(rule->value));
}

NTSTATUS copy_rule(OwnedUnicodeRule* destination, PCUNICODE_STRING source) {
    if (destination == nullptr || source == nullptr || source->Buffer == nullptr
        || source->Length == 0 || source->Length > kMaximumRuleBytes
        || (source->Length % sizeof(WCHAR)) != 0) {
        return STATUS_INVALID_PARAMETER;
    }

    const SIZE_T allocation_size = source->Length + sizeof(WCHAR);
    auto* buffer = static_cast<PWCHAR>(
        ExAllocatePool2(POOL_FLAG_NON_PAGED, allocation_size, kPoolTag));
    if (buffer == nullptr) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlCopyMemory(buffer, source->Buffer, source->Length);
    buffer[source->Length / sizeof(WCHAR)] = L'\0';
    destination->value.Buffer = buffer;
    destination->value.Length = source->Length;
    destination->value.MaximumLength = static_cast<USHORT>(allocation_size);
    return STATUS_SUCCESS;
}

BOOLEAN rule_equals(PCUNICODE_STRING left, PCUNICODE_STRING right) {
    return left != nullptr && right != nullptr
        && RtlEqualUnicodeString(left, right, TRUE);
}

BOOLEAN unicode_contains_token(PCUNICODE_STRING value, PCWSTR token_text) {
    if (value == nullptr || value->Buffer == nullptr || token_text == nullptr) {
        return FALSE;
    }
    UNICODE_STRING token{};
    RtlInitUnicodeString(&token, token_text);
    if (token.Length == 0 || value->Length < token.Length) {
        return FALSE;
    }
    const USHORT value_chars = value->Length / sizeof(WCHAR);
    const USHORT token_chars = token.Length / sizeof(WCHAR);
    for (USHORT offset = 0; offset + token_chars <= value_chars; ++offset) {
        UNICODE_STRING candidate = *value;
        candidate.Buffer += offset;
        candidate.Length = token.Length;
        candidate.MaximumLength = candidate.Length;
        if (RtlEqualUnicodeString(&candidate, &token, TRUE)) {
            return TRUE;
        }
    }
    return FALSE;
}

BOOLEAN dos_path_suffix_matches(PCUNICODE_STRING rule, PCUNICODE_STRING actual) {
    if (rule == nullptr || actual == nullptr || rule->Buffer == nullptr
        || actual->Buffer == nullptr || rule->Length < 4) {
        return FALSE;
    }

    PathParts normalized_rule{};
    PathParts normalized_actual{};
    if (!normalize_path(rule, &normalized_rule)
        || !normalize_path(actual, &normalized_actual)) {
        return FALSE;
    }

    USHORT rule_starts[64] = {};
    USHORT rule_lengths[64] = {};
    USHORT actual_starts[64] = {};
    USHORT actual_lengths[64] = {};
    const ULONG rule_count = split_components(
        &normalized_rule, rule_starts, rule_lengths, RTL_NUMBER_OF(rule_starts));
    const ULONG actual_count = split_components(
        &normalized_actual, actual_starts, actual_lengths, RTL_NUMBER_OF(actual_starts));
    if (rule_count == 0 || actual_count < rule_count) {
        return FALSE;
    }

    // A DOS drive is a volume alias. Ignore its first component and compare
    // the remaining path components against the normalized NT/device path.
    ULONG first_rule_component = 0;
    if (rule_count > 0 && rule_lengths[0] == 2
        && normalized_rule.buffer[rule_starts[0] + 1] == L':') {
        first_rule_component = 1;
    }
    const ULONG suffix_count = rule_count - first_rule_component;
    if (suffix_count == 0 || actual_count < suffix_count) {
        return FALSE;
    }
    const ULONG actual_offset = actual_count - suffix_count;
    for (ULONG index = 0; index < suffix_count; ++index) {
        if (!equal_component(
                normalized_rule.buffer + rule_starts[first_rule_component + index],
                rule_lengths[first_rule_component + index],
                normalized_actual.buffer + actual_starts[actual_offset + index],
                actual_lengths[actual_offset + index])) {
            return FALSE;
        }
    }
    return TRUE;
}

#ifndef EVERBLOOM_KERNEL_POLICY_PATH_TEST
BOOLEAN process_rule_matches(PCUNICODE_STRING rule, PCUNICODE_STRING image_name) {
    if (rule_equals(rule, image_name)
        || dos_path_suffix_matches(rule, image_name)) {
        return TRUE;
    }
    if (rule == nullptr || image_name == nullptr || rule->Length >= image_name->Length) {
        return FALSE;
    }

    // Allow a basename policy (for example `powershell.exe`) to match the
    // fully-qualified image path supplied by PS_CREATE_NOTIFY_INFO. File
    // rules remain exact matches to avoid broad filesystem denial.
    for (USHORT offset = 0;
         offset + rule->Length <= image_name->Length;
         offset += sizeof(WCHAR)) {
        const BOOLEAN begins_component = offset == 0
            || image_name->Buffer[(offset / sizeof(WCHAR)) - 1] == L'\\'
            || image_name->Buffer[(offset / sizeof(WCHAR)) - 1] == L'/';
        if (!begins_component || offset + rule->Length != image_name->Length) {
            continue;
        }
        UNICODE_STRING suffix = *image_name;
        suffix.Buffer += offset / sizeof(WCHAR);
        suffix.Length = rule->Length;
        suffix.MaximumLength = rule->Length;
        if (rule_equals(rule, &suffix)) {
            return TRUE;
        }
    }
    return FALSE;
}

BOOLEAN file_rule_matches(PCUNICODE_STRING rule, PCUNICODE_STRING file_name) {
    return rule_equals(rule, file_name)
        || dos_path_suffix_matches(rule, file_name);
}

BOOLEAN registry_rule_matches(PCUNICODE_STRING rule, PCUNICODE_STRING key_name) {
    if (rule_equals(rule, key_name)) {
        return TRUE;
    }
    if (rule == nullptr || key_name == nullptr || rule->Length >= key_name->Length) {
        return FALSE;
    }
    UNICODE_STRING prefix = *key_name;
    prefix.Length = rule->Length;
    prefix.MaximumLength = prefix.Length;
    if (!rule_equals(rule, &prefix)) {
        return FALSE;
    }
    const USHORT separator_offset = static_cast<USHORT>(rule->Length / sizeof(WCHAR));
    return separator_offset < key_name->Length / sizeof(WCHAR)
        && key_name->Buffer[separator_offset] == L'\\';
}

PCWSTR builtin_registry_hijack_reason(PCUNICODE_STRING key_name) {
    if (key_name == nullptr || key_name->Buffer == nullptr) {
        return nullptr;
    }
    // SilverFox-style CTF hijacks modify HKCU/HKLM CTF keys such as
    // ...\Software\Microsoft\CTF\ and ...\CTF\SystemShared\.  The object
    // manager presents these as \Registry\User\... or \Registry\Machine\...
    // paths, so match stable suffix tokens rather than hive aliases.
    if (unicode_contains_token(key_name, L"\\SOFTWARE\\MICROSOFT\\CTF")
        || unicode_contains_token(key_name, L"\\CTF\\SYSTEMSHARED")) {
        return L"CTF hijack registry operation blocked";
    }
    // TypeLib hijacking redirects COM activation through a user-controlled
    // InprocServer32/LocalServer32 value. The registry callback sees both
    // HKCU and HKLM as object-manager paths, so a stable TypeLib component
    // match covers both hives without relying on a DOS alias.
    if (unicode_contains_token(key_name, L"\\TYPELIB")) {
        return L"TypeLib hijack registry operation blocked";
    }
    return nullptr;
}

BOOLEAN builtin_sensitive_registry_rule_matches(PCUNICODE_STRING key_name) {
    return builtin_registry_hijack_reason(key_name) != nullptr;
}

BOOLEAN has_network_rule(ULONG ipv4_address, USHORT port, ULONG* index) {
    for (ULONG current = 0; current < g_policy.network_count; ++current) {
        const auto& rule = g_policy.networks[current];
        if (rule.ipv4_address == ipv4_address
            && (rule.port == 0 || port == 0 || rule.port == port)) {
            if (index != nullptr) {
                *index = current;
            }
            return TRUE;
        }
    }
    return FALSE;
}

BOOLEAN network_rule_equals(ULONG ipv4_address, USHORT port, ULONG* index) {
    for (ULONG current = 0; current < g_policy.network_count; ++current) {
        const auto& rule = g_policy.networks[current];
        if (rule.ipv4_address == ipv4_address && rule.port == port) {
            if (index != nullptr) {
                *index = current;
            }
            return TRUE;
        }
    }
    return FALSE;
}

NTSTATUS update_prepared_unicode_rule(
    OwnedUnicodeRule* rules,
    ULONG* count,
    OwnedUnicodeRule* prepared) {
    if (rules == nullptr || count == nullptr || prepared == nullptr
        || prepared->value.Buffer == nullptr) {
        return STATUS_INVALID_PARAMETER;
    }
    for (ULONG index = 0; index < *count; ++index) {
        if (rule_equals(&rules[index].value, &prepared->value)) {
            return STATUS_SUCCESS;
        }
    }
    if (*count >= kMaximumRules) {
        return STATUS_QUOTA_EXCEEDED;
    }
    rules[*count] = *prepared;
    RtlZeroMemory(prepared, sizeof(*prepared));
    ++(*count);
    return STATUS_SUCCESS;
}

NTSTATUS clear_unicode_rule(
    OwnedUnicodeRule* rules,
    ULONG* count,
    PCUNICODE_STRING target,
    OwnedUnicodeRule* removed) {
    if (rules == nullptr || count == nullptr || target == nullptr) {
        return STATUS_INVALID_PARAMETER;
    }
    for (ULONG index = 0; index < *count; ++index) {
        if (!rule_equals(&rules[index].value, target)) {
            continue;
        }
        if (removed != nullptr) {
            *removed = rules[index];
        }
        if (index + 1 < *count) {
            RtlMoveMemory(&rules[index], &rules[index + 1],
                          (*count - index - 1) * sizeof(OwnedUnicodeRule));
        }
        RtlZeroMemory(&rules[*count - 1], sizeof(OwnedUnicodeRule));
        --(*count);
        return STATUS_SUCCESS;
    }
    return STATUS_NOT_FOUND;
}

VOID copy_event_text(
    PUSHORT destination,
    ULONG capacity,
    PCUNICODE_STRING source,
    PCWSTR fallback) {
    if (destination == nullptr || capacity == 0) {
        return;
    }
    ULONG length = 0;
    if (source != nullptr && source->Buffer != nullptr) {
        length = min(
            static_cast<ULONG>(source->Length / sizeof(WCHAR)),
            capacity - 1);
        if (length > 0) {
            RtlCopyMemory(destination, source->Buffer, length * sizeof(WCHAR));
        }
    } else if (fallback != nullptr) {
        while (length + 1 < capacity && fallback[length] != L'\0') {
            destination[length] = static_cast<USHORT>(fallback[length]);
            ++length;
        }
    }
    destination[length] = 0;
}

} // namespace

BOOLEAN EverbloomKernelPolicyIsVulnerableDriverPath(PCUNICODE_STRING path) {
    if (path == nullptr || path->Buffer == nullptr) {
        return FALSE;
    }
    PathParts normalized{};
    if (!normalize_path(path, &normalized)) {
        return FALSE;
    }
    USHORT starts[64] = {};
    USHORT lengths[64] = {};
    const ULONG count = split_components(
        &normalized, starts, lengths, RTL_NUMBER_OF(starts));
    if (count == 0) {
        return FALSE;
    }
    return is_known_vulnerable_driver_basename(
        normalized.buffer + starts[count - 1],
        lengths[count - 1]);
}

NTSTATUS EverbloomKernelPolicyInitialize() {
    RtlZeroMemory(&g_policy, sizeof(g_policy));
    KeInitializeSpinLock(&g_policy.lock);
    KeInitializeSpinLock(&g_policy.event_lock);
    // R3 is the user/admin layer and is available by default. Kernel
    // enforcement is opt-in because it requires a signed, loaded driver.
    g_policy.r3_enabled = TRUE;
    g_policy.driver_enabled = FALSE;
    return STATUS_SUCCESS;
}

VOID EverbloomKernelPolicyShutdown() {
    OwnedUnicodeRule retired[kMaximumRules * 4] = {};
    ULONG retired_count = 0;
    KIRQL old_irql = PASSIVE_LEVEL;
    KeAcquireSpinLock(&g_policy.lock, &old_irql);
    for (ULONG index = 0; index < g_policy.process_count; ++index) {
        retired[retired_count++] = g_policy.processes[index];
        RtlZeroMemory(&g_policy.processes[index], sizeof(OwnedUnicodeRule));
    }
    for (ULONG index = 0; index < g_policy.file_count; ++index) {
        retired[retired_count++] = g_policy.files[index];
        RtlZeroMemory(&g_policy.files[index], sizeof(OwnedUnicodeRule));
    }
    for (ULONG index = 0; index < g_policy.registry_count; ++index) {
        retired[retired_count++] = g_policy.registry[index];
        RtlZeroMemory(&g_policy.registry[index], sizeof(OwnedUnicodeRule));
    }
    for (ULONG index = 0; index < g_policy.raw_disk_count; ++index) {
        retired[retired_count++] = g_policy.raw_disks[index];
        RtlZeroMemory(&g_policy.raw_disks[index], sizeof(OwnedUnicodeRule));
    }
    g_policy.process_count = 0;
    g_policy.file_count = 0;
    g_policy.registry_count = 0;
    g_policy.raw_disk_count = 0;
    g_policy.network_count = 0;
    g_policy.r3_enabled = FALSE;
    g_policy.driver_enabled = FALSE;
    KeReleaseSpinLock(&g_policy.lock, old_irql);
    for (ULONG index = 0; index < retired_count; ++index) {
        free_rule(&retired[index]);
    }
}

NTSTATUS EverbloomKernelPolicySetProtection(BOOLEAN r3_enabled, BOOLEAN driver_enabled) {
    KIRQL old_irql = PASSIVE_LEVEL;
    KeAcquireSpinLock(&g_policy.lock, &old_irql);
    g_policy.r3_enabled = r3_enabled ? TRUE : FALSE;
    g_policy.driver_enabled = driver_enabled ? TRUE : FALSE;
    KeReleaseSpinLock(&g_policy.lock, old_irql);
    return STATUS_SUCCESS;
}

BOOLEAN EverbloomKernelPolicyIsR3Enabled() {
    KIRQL old_irql = PASSIVE_LEVEL;
    KeAcquireSpinLock(&g_policy.lock, &old_irql);
    const BOOLEAN enabled = g_policy.r3_enabled;
    KeReleaseSpinLock(&g_policy.lock, old_irql);
    return enabled;
}

BOOLEAN EverbloomKernelPolicyIsDriverEnabled() {
    KIRQL old_irql = PASSIVE_LEVEL;
    KeAcquireSpinLock(&g_policy.lock, &old_irql);
    const BOOLEAN enabled = g_policy.driver_enabled;
    KeReleaseSpinLock(&g_policy.lock, old_irql);
    return enabled;
}

NTSTATUS EverbloomKernelPolicyUpdate(
    const EVERBLOOM_POLICY_COMMAND* command,
    PCUNICODE_STRING target) {
    if (command == nullptr || command->Version != EVERBLOOM_POLICY_VERSION
        || command->Action != EVERBLOOM_POLICY_ACTION_BLOCK
        || command->Reserved != 0) {
        return STATUS_INVALID_PARAMETER;
    }

    OwnedUnicodeRule prepared{};
    const BOOLEAN unicode_kind = command->Kind == EVERBLOOM_POLICY_KIND_PROCESS
        || command->Kind == EVERBLOOM_POLICY_KIND_FILE
        || command->Kind == EVERBLOOM_POLICY_KIND_REGISTRY
        || command->Kind == EVERBLOOM_POLICY_KIND_RAW_DISK;
    if (unicode_kind) {
        // Pool allocation and copying happen before the spin lock. The lock
        // is also used by DISPATCH_LEVEL classify callbacks, so no pageable
        // or potentially expensive operation may run while it is held.
        const NTSTATUS copy_status = copy_rule(&prepared, target);
        if (!NT_SUCCESS(copy_status)) {
            return copy_status;
        }
    }

    KIRQL old_irql = PASSIVE_LEVEL;
    KeAcquireSpinLock(&g_policy.lock, &old_irql);
    NTSTATUS status = STATUS_INVALID_PARAMETER;
    switch (command->Kind) {
        case EVERBLOOM_POLICY_KIND_PROCESS:
            status = update_prepared_unicode_rule(
                g_policy.processes, &g_policy.process_count, &prepared);
            break;
        case EVERBLOOM_POLICY_KIND_FILE:
            status = update_prepared_unicode_rule(
                g_policy.files, &g_policy.file_count, &prepared);
            break;
        case EVERBLOOM_POLICY_KIND_REGISTRY:
            status = update_prepared_unicode_rule(
                g_policy.registry, &g_policy.registry_count, &prepared);
            break;
        case EVERBLOOM_POLICY_KIND_RAW_DISK:
            status = update_prepared_unicode_rule(
                g_policy.raw_disks, &g_policy.raw_disk_count, &prepared);
            break;
        case EVERBLOOM_POLICY_KIND_NETWORK:
            if (command->Ipv4Address == 0) {
                status = STATUS_INVALID_PARAMETER;
                break;
            }
            if (network_rule_equals(command->Ipv4Address, command->Port, nullptr)) {
                status = STATUS_SUCCESS;
                break;
            }
            if (g_policy.network_count >= kMaximumRules) {
                status = STATUS_QUOTA_EXCEEDED;
                break;
            }
            g_policy.networks[g_policy.network_count++] = {
                command->Ipv4Address,
                command->Port};
            status = STATUS_SUCCESS;
            break;
        default:
            break;
    }
    KeReleaseSpinLock(&g_policy.lock, old_irql);
    free_rule(&prepared);
    return status;
}

NTSTATUS EverbloomKernelPolicyClear(
    const EVERBLOOM_POLICY_COMMAND* command,
    PCUNICODE_STRING target) {
    if (command == nullptr || command->Version != EVERBLOOM_POLICY_VERSION
        || command->Action != EVERBLOOM_POLICY_ACTION_BLOCK
        || command->Reserved != 0) {
        return STATUS_INVALID_PARAMETER;
    }

    OwnedUnicodeRule removed{};
    KIRQL old_irql = PASSIVE_LEVEL;
    KeAcquireSpinLock(&g_policy.lock, &old_irql);
    NTSTATUS status = STATUS_INVALID_PARAMETER;
    switch (command->Kind) {
        case EVERBLOOM_POLICY_KIND_PROCESS:
            status = clear_unicode_rule(
                g_policy.processes, &g_policy.process_count, target, &removed);
            break;
        case EVERBLOOM_POLICY_KIND_FILE:
            status = clear_unicode_rule(
                g_policy.files, &g_policy.file_count, target, &removed);
            break;
        case EVERBLOOM_POLICY_KIND_REGISTRY:
            status = clear_unicode_rule(
                g_policy.registry, &g_policy.registry_count, target, &removed);
            break;
        case EVERBLOOM_POLICY_KIND_RAW_DISK:
            status = clear_unicode_rule(
                g_policy.raw_disks, &g_policy.raw_disk_count, target, &removed);
            break;
        case EVERBLOOM_POLICY_KIND_NETWORK: {
            ULONG index = 0;
            if (command->Ipv4Address == 0) {
                status = STATUS_INVALID_PARAMETER;
            } else if (network_rule_equals(command->Ipv4Address, command->Port, &index)) {
                if (index + 1 < g_policy.network_count) {
                    RtlMoveMemory(&g_policy.networks[index], &g_policy.networks[index + 1],
                                  (g_policy.network_count - index - 1) * sizeof(NetworkRule));
                }
                RtlZeroMemory(&g_policy.networks[g_policy.network_count - 1],
                              sizeof(NetworkRule));
                --g_policy.network_count;
                status = STATUS_SUCCESS;
            } else {
                status = STATUS_NOT_FOUND;
            }
            break;
        }
        default:
            break;
    }
    KeReleaseSpinLock(&g_policy.lock, old_irql);
    free_rule(&removed);
    return status;
}

BOOLEAN EverbloomKernelPolicyIsProcessBlocked(PCUNICODE_STRING image_name) {
    BOOLEAN blocked = FALSE;
    KIRQL old_irql = PASSIVE_LEVEL;
    KeAcquireSpinLock(&g_policy.lock, &old_irql);
    if (!g_policy.driver_enabled) {
        KeReleaseSpinLock(&g_policy.lock, old_irql);
        return FALSE;
    }
    for (ULONG index = 0; index < g_policy.process_count; ++index) {
        if (process_rule_matches(&g_policy.processes[index].value, image_name)) {
            blocked = TRUE;
            break;
        }
    }
    KeReleaseSpinLock(&g_policy.lock, old_irql);
    return blocked;
}

BOOLEAN EverbloomKernelPolicyIsFileBlocked(PCUNICODE_STRING file_name) {
    BOOLEAN blocked = FALSE;
    KIRQL old_irql = PASSIVE_LEVEL;
    KeAcquireSpinLock(&g_policy.lock, &old_irql);
    if (!g_policy.driver_enabled) {
        KeReleaseSpinLock(&g_policy.lock, old_irql);
        return FALSE;
    }
    for (ULONG index = 0; index < g_policy.file_count; ++index) {
        if (file_rule_matches(&g_policy.files[index].value, file_name)) {
            blocked = TRUE;
            break;
        }
    }
    KeReleaseSpinLock(&g_policy.lock, old_irql);
    return blocked;
}

BOOLEAN EverbloomKernelPolicyIsRegistryBlocked(PCUNICODE_STRING key_name) {
    KIRQL old_irql = PASSIVE_LEVEL;
    KeAcquireSpinLock(&g_policy.lock, &old_irql);
    BOOLEAN blocked = FALSE;
    if (g_policy.driver_enabled) {
        blocked = builtin_sensitive_registry_rule_matches(key_name);
        for (ULONG index = 0; index < g_policy.registry_count; ++index) {
            if (blocked
                || registry_rule_matches(&g_policy.registry[index].value, key_name)) {
                blocked = TRUE;
                break;
            }
        }
    }
    KeReleaseSpinLock(&g_policy.lock, old_irql);
    return blocked;
}

BOOLEAN EverbloomKernelPolicyIsRawDiskBlocked(PCUNICODE_STRING device_name) {
    KIRQL old_irql = PASSIVE_LEVEL;
    KeAcquireSpinLock(&g_policy.lock, &old_irql);
    BOOLEAN blocked = FALSE;
    if (g_policy.driver_enabled) {
        // The first megabyte check in the minifilter is the MBR guard. With
        // driver protection enabled it is active for all physical disks;
        // explicit raw-disk rules can additionally cover other devices.
        blocked = g_policy.raw_disk_count == 0;
        for (ULONG index = 0; !blocked && index < g_policy.raw_disk_count; ++index) {
            if (file_rule_matches(&g_policy.raw_disks[index].value, device_name)) {
                blocked = TRUE;
            }
        }
    }
    KeReleaseSpinLock(&g_policy.lock, old_irql);
    return blocked;
}

BOOLEAN EverbloomKernelPolicyIsNetworkBlocked(ULONG ipv4_address, USHORT port) {
    BOOLEAN blocked = FALSE;
    KIRQL old_irql = PASSIVE_LEVEL;
    KeAcquireSpinLock(&g_policy.lock, &old_irql);
    if (!g_policy.driver_enabled) {
        KeReleaseSpinLock(&g_policy.lock, old_irql);
        return FALSE;
    }
    blocked = has_network_rule(ipv4_address, port, nullptr);
    KeReleaseSpinLock(&g_policy.lock, old_irql);
    return blocked;
}

VOID EverbloomKernelPolicyRecordBlock(
    ULONG kind,
    PCUNICODE_STRING target,
    PCWSTR reason) {
    EverbloomKernelPolicyRecordEvent(kind, target, reason, STATUS_ACCESS_DENIED);
}

VOID EverbloomKernelPolicyRecordEvent(
    ULONG kind,
    PCUNICODE_STRING target,
    PCWSTR reason,
    NTSTATUS status) {
    KIRQL old_irql = PASSIVE_LEVEL;
    KeAcquireSpinLock(&g_policy.event_lock, &old_irql);
    if (g_policy.event_count >= kMaximumEvents) {
        g_policy.event_head = (g_policy.event_head + 1) % kMaximumEvents;
        --g_policy.event_count;
        ++g_policy.event_dropped;
    }
    const ULONG index = (g_policy.event_head + g_policy.event_count) % kMaximumEvents;
    auto* event = &g_policy.events[index];
    RtlZeroMemory(event, sizeof(*event));
    event->Version = EVERBLOOM_DRIVER_EVENT_VERSION;
    event->Kind = kind;
    event->Status = status;
    event->CallerPid = HandleToULong(PsGetCurrentProcessId());
    event->Sequence = ++g_policy.next_event_sequence;
    // Sequence is the portable ordering source for the audit ring. Leave the
    // optional wall-clock field zero because this driver build deliberately
    // avoids importing a timing routine into the minimal kernel image.
    event->Timestamp = 0;
    copy_event_text(
        event->Target,
        EVERBLOOM_MAX_TARGET_CHARS,
        target,
        nullptr);
    copy_event_text(
        event->Reason,
        EVERBLOOM_MAX_EVENT_REASON_CHARS,
        nullptr,
        reason == nullptr ? L"kernel policy blocked operation" : reason);
    ++g_policy.event_count;
    KeReleaseSpinLock(&g_policy.event_lock, old_irql);
}

NTSTATUS EverbloomKernelPolicyReadEvents(
    const EVERBLOOM_EVENT_QUERY* query,
    EVERBLOOM_EVENT_READ_RESPONSE* response) {
    if (query == nullptr || response == nullptr
        || query->Version != EVERBLOOM_DRIVER_EVENT_VERSION
        || query->Reserved != 0 || query->MaxEvents == 0) {
        return STATUS_INVALID_PARAMETER;
    }
    const ULONG requested = min(query->MaxEvents, EVERBLOOM_EVENT_MAX_BATCH);
    RtlZeroMemory(response, sizeof(*response));
    response->Version = EVERBLOOM_DRIVER_EVENT_VERSION;
    KIRQL old_irql = PASSIVE_LEVEL;
    KeAcquireSpinLock(&g_policy.event_lock, &old_irql);
    response->Dropped = g_policy.event_dropped;
    g_policy.event_dropped = 0;
    while (response->Count < requested && g_policy.event_count > 0) {
        RtlCopyMemory(
            &response->Events[response->Count],
            &g_policy.events[g_policy.event_head],
            sizeof(EVERBLOOM_DRIVER_EVENT));
        RtlZeroMemory(&g_policy.events[g_policy.event_head], sizeof(EVERBLOOM_DRIVER_EVENT));
        g_policy.event_head = (g_policy.event_head + 1) % kMaximumEvents;
        --g_policy.event_count;
        ++response->Count;
    }
    KeReleaseSpinLock(&g_policy.event_lock, old_irql);
    return STATUS_SUCCESS;
}
#else
} // namespace
#endif
