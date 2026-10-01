#pragma once

#include <ntifs.h>

#include "everbloom_driver_protocol.h"

NTSTATUS EverbloomKernelPolicyInitialize();
VOID EverbloomKernelPolicyShutdown();

NTSTATUS EverbloomKernelPolicySetProtection(BOOLEAN r3_enabled, BOOLEAN driver_enabled);
BOOLEAN EverbloomKernelPolicyIsR3Enabled();
BOOLEAN EverbloomKernelPolicyIsDriverEnabled();

NTSTATUS EverbloomKernelPolicyUpdate(
    const EVERBLOOM_POLICY_COMMAND* command,
    PCUNICODE_STRING target);

NTSTATUS EverbloomKernelPolicyClear(
    const EVERBLOOM_POLICY_COMMAND* command,
    PCUNICODE_STRING target);

BOOLEAN EverbloomKernelPolicyIsProcessBlocked(PCUNICODE_STRING image_name);
BOOLEAN EverbloomKernelPolicyIsFileBlocked(PCUNICODE_STRING file_name);
BOOLEAN EverbloomKernelPolicyIsRegistryBlocked(PCUNICODE_STRING key_name);
BOOLEAN EverbloomKernelPolicyIsRawDiskBlocked(PCUNICODE_STRING device_name);
BOOLEAN EverbloomKernelPolicyIsNetworkBlocked(ULONG ipv4_address, USHORT port);
BOOLEAN EverbloomKernelPolicyIsVulnerableDriverPath(PCUNICODE_STRING path);

// Fixed-size nonpaged audit ring used to bridge kernel enforcement decisions
// to the user-mode event/log pipeline without allocating in callbacks.
VOID EverbloomKernelPolicyRecordBlock(
    ULONG kind,
    PCUNICODE_STRING target,
    PCWSTR reason);
VOID EverbloomKernelPolicyRecordEvent(
    ULONG kind,
    PCUNICODE_STRING target,
    PCWSTR reason,
    NTSTATUS status);
NTSTATUS EverbloomKernelPolicyReadEvents(
    const EVERBLOOM_EVENT_QUERY* query,
    EVERBLOOM_EVENT_READ_RESPONSE* response);
