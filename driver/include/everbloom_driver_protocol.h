#pragma once

/*
 * Stable user/kernel control-plane ABI.
 *
 * The kernel driver must only consume these fixed-width fields. It must never
 * receive C++ std::string/std::vector objects or pointers from user mode.
 */
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define EVERBLOOM_DRIVER_PROTOCOL_VERSION 1u
#define EVERBLOOM_MAX_TARGET_CHARS 260u
#define EVERBLOOM_MAX_PAYLOAD 4096u

#define EVERBLOOM_IOCTL_AMSI_SCAN_BUFFER 0x80002010u
#define EVERBLOOM_IOCTL_SCAN_FILE 0x80002020u
#define EVERBLOOM_IOCTL_NET_INSPECT 0x80003010u
#define EVERBLOOM_IOCTL_BEHAVIOR_ANALYZE 0x80004010u
#define EVERBLOOM_IOCTL_POLICY_UPDATE 0x80005010u
#define EVERBLOOM_IOCTL_POLICY_CLEAR 0x80005020u
#define EVERBLOOM_IOCTL_PROTECTION_UPDATE 0x80005030u
#define EVERBLOOM_IOCTL_EVENT_READ 0x80006010u
#define EVERBLOOM_IOCTL_CAPABILITIES_QUERY 0x80006020u

#define EVERBLOOM_POLICY_VERSION 1u
#define EVERBLOOM_POLICY_KIND_PROCESS 1u
#define EVERBLOOM_POLICY_KIND_FILE 2u
#define EVERBLOOM_POLICY_KIND_NETWORK 3u
#define EVERBLOOM_POLICY_KIND_REGISTRY 4u
#define EVERBLOOM_POLICY_KIND_RAW_DISK 5u
#define EVERBLOOM_POLICY_ACTION_BLOCK 1u

typedef struct EVERBLOOM_DRIVER_REQUEST {
    uint32_t Version;
    uint32_t Operation;
    uint64_t RequestId;
    uint32_t CallerPid;
    uint32_t PayloadLength;
    uint16_t Target[EVERBLOOM_MAX_TARGET_CHARS];
    uint8_t Payload[EVERBLOOM_MAX_PAYLOAD];
} EVERBLOOM_DRIVER_REQUEST;

typedef struct EVERBLOOM_DRIVER_RESPONSE {
    uint32_t Version;
    uint32_t Verdict; /* 0 = allow/observe, 1 = block */
    uint32_t Threat;  /* 0 = low, 1 = medium, 2 = high, 3 = critical */
    uint32_t Action;  /* 0 = log, 1 = notify, 2 = block, 3 = isolate, 4 = terminate */
    uint64_t RequestId;
} EVERBLOOM_DRIVER_RESPONSE;

/*
 * Payload for EVERBLOOM_IOCTL_POLICY_UPDATE/CLEAR.
 *
 * Process and file rules use the request Target field as a UTF-16 path. A
 * network rule uses Ipv4Address and Port in the host byte order expected by
 * WFP's FWPS_INCOMING_VALUES; Port == 0 means every TCP/UDP port for that
 * address.
 */
typedef struct EVERBLOOM_POLICY_COMMAND {
    uint32_t Version;
    uint32_t Kind;
    uint32_t Action;
    uint32_t Ipv4Address;
    uint16_t Port;
    uint16_t Reserved;
} EVERBLOOM_POLICY_COMMAND;

/* Runtime protection layers. R3 is the user/admin layer; DriverEnabled
 * controls enforcement in the kernel callbacks. */
typedef struct EVERBLOOM_PROTECTION_COMMAND {
    uint32_t Version;
    uint32_t R3Enabled;
    uint32_t DriverEnabled;
    uint32_t Reserved;
} EVERBLOOM_PROTECTION_COMMAND;

/* Kernel enforcement telemetry. Events are copied from a bounded nonpaged
 * ring; no user pointer is ever retained by the driver. */
#define EVERBLOOM_DRIVER_EVENT_VERSION 1u
#define EVERBLOOM_EVENT_MAX_BATCH 32u
#define EVERBLOOM_EVENT_KIND_PROCESS 1u
#define EVERBLOOM_EVENT_KIND_FILE 2u
#define EVERBLOOM_EVENT_KIND_REGISTRY 3u
#define EVERBLOOM_EVENT_KIND_RAW_DISK 4u
#define EVERBLOOM_EVENT_KIND_NETWORK 5u
#define EVERBLOOM_EVENT_KIND_EMERGENCY 6u
/*
 * Advisory score from the kernel inference core.
 *
 * For this kind only, the event's Status field carries the score instead of an
 * NTSTATUS. Status is the only spare numeric field in EVERBLOOM_DRIVER_EVENT, so
 * giving it a per-kind meaning lets user mode read the number directly rather
 * than parsing prose out of Reason, and it avoids adding a field to a struct
 * that driver_bridge.rs mirrors in Rust for what is only an advisory signal.
 *
 * A MODEL_SCORE event never vetoes anything: the model sees only the image path
 * and the command line, not the file's bytes, its signature or what the
 * user-mode engine has correlated. Treat the score as triage, not a verdict.
 */
#define EVERBLOOM_EVENT_KIND_MODEL_SCORE 7u
#define EVERBLOOM_MAX_EVENT_REASON_CHARS 128u

typedef struct EVERBLOOM_EVENT_QUERY {
    uint32_t Version;
    uint32_t MaxEvents;
    uint64_t Reserved;
} EVERBLOOM_EVENT_QUERY;

typedef struct EVERBLOOM_DRIVER_EVENT {
    uint32_t Version;
    uint32_t Kind;
    uint32_t Status;
    uint32_t CallerPid;
    uint64_t Sequence;
    int64_t Timestamp;
    uint16_t Target[EVERBLOOM_MAX_TARGET_CHARS];
    uint16_t Reason[EVERBLOOM_MAX_EVENT_REASON_CHARS];
} EVERBLOOM_DRIVER_EVENT;

typedef struct EVERBLOOM_EVENT_READ_RESPONSE {
    uint32_t Version;
    uint32_t Count;
    uint64_t Dropped;
    EVERBLOOM_DRIVER_EVENT Events[EVERBLOOM_EVENT_MAX_BATCH];
} EVERBLOOM_EVENT_READ_RESPONSE;

/* Read-only user/kernel negotiation. Older drivers do not implement this
 * IOCTL; user mode must treat that as a degraded legacy bridge and continue
 * scanning in fail-open mode instead of blocking the Rust pipeline. */
#define EVERBLOOM_DRIVER_CAPABILITIES_VERSION 1u
#define EVERBLOOM_CAPABILITY_SCAN_FILE 0x00000001ull
#define EVERBLOOM_CAPABILITY_BEHAVIOR_ANALYZE 0x00000002ull
#define EVERBLOOM_CAPABILITY_POLICY_UPDATE 0x00000004ull
#define EVERBLOOM_CAPABILITY_PROTECTION_UPDATE 0x00000008ull
#define EVERBLOOM_CAPABILITY_EVENT_READ 0x00000010ull
#define EVERBLOOM_CAPABILITY_REGISTRY_POLICY 0x00000020ull
#define EVERBLOOM_CAPABILITY_RAW_DISK_POLICY 0x00000040ull
#define EVERBLOOM_CAPABILITY_NETWORK_POLICY 0x00000080ull
/*
 * Set when an inference model is linked into the driver, i.e. when
 * EVERBLOOM_EVENT_KIND_MODEL_SCORE events can actually be emitted. A build
 * without a model never sets it, so user mode does not sit waiting for scores
 * that cannot arrive.
 */
#define EVERBLOOM_CAPABILITY_KERNEL_MODEL 0x00000100ull

typedef struct EVERBLOOM_CAPABILITIES_QUERY {
    uint32_t Version;
    uint32_t Reserved;
} EVERBLOOM_CAPABILITIES_QUERY;

typedef struct EVERBLOOM_CAPABILITIES_RESPONSE {
    uint32_t Version;
    uint32_t ProtocolVersion;
    uint32_t PolicyVersion;
    uint32_t ProtectionProtocolVersion;
    uint32_t EventVersion;
    uint32_t MaxTargetChars;
    uint32_t MaxPayloadBytes;
    uint32_t MaxEventBatch;
    uint64_t CapabilityFlags;
} EVERBLOOM_CAPABILITIES_RESPONSE;

#ifdef __cplusplus
}
#endif
