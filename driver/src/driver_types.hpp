#pragma once

#include "everbloom_driver_protocol.h"

#include <cstdint>
#include <optional>
#include <string>

namespace everbloom::driver {

enum class ThreatLevel {
    Low,
    Medium,
    High,
    Critical
};

constexpr int threatRank(ThreatLevel level) noexcept {
    switch (level) {
        case ThreatLevel::Low: return 0;
        case ThreatLevel::Medium: return 1;
        case ThreatLevel::High: return 2;
        case ThreatLevel::Critical: return 3;
    }
    return 0;
}

inline bool operator>(ThreatLevel left, ThreatLevel right) noexcept {
    return threatRank(left) > threatRank(right);
}

inline bool operator>=(ThreatLevel left, ThreatLevel right) noexcept {
    return threatRank(left) >= threatRank(right);
}

inline bool operator<(ThreatLevel left, ThreatLevel right) noexcept {
    return threatRank(left) < threatRank(right);
}

inline bool operator<=(ThreatLevel left, ThreatLevel right) noexcept {
    return threatRank(left) <= threatRank(right);
}

enum class ResponseAction {
    Log,
    Notify,
    Block,
    Isolate,
    Terminate
};

constexpr int responseRank(ResponseAction action) noexcept {
    switch (action) {
        case ResponseAction::Log: return 0;
        case ResponseAction::Notify: return 1;
        case ResponseAction::Block: return 2;
        case ResponseAction::Isolate: return 3;
        case ResponseAction::Terminate: return 4;
    }
    return 0;
}

inline bool operator>(ResponseAction left, ResponseAction right) noexcept {
    return responseRank(left) > responseRank(right);
}

struct EventContext {
    std::string source;
    std::string module;
    std::string target;
    std::string detail;
    ThreatLevel level{ThreatLevel::Low};
    uint64_t request_id{0};
};

enum class EventType {
    Generic,
    Ioctl,
    Policy,
    DriverResponse,
};

enum class EventSeverity {
    Info,
    Warning,
    Error,
    Critical
};

struct IRP {
    uint32_t IoControlCode;
    std::string Caller;
    std::string Target;
    std::string Payload;
    uint64_t request_id{0};
};

struct Event {
    EventType type{EventType::Generic};
    std::string source;
    std::string module;
    std::string message;
    std::optional<IRP> irp;
    ThreatLevel threat{ThreatLevel::Low};
    EventSeverity severity{EventSeverity::Info};
    uint64_t request_id{0};
};

struct IoctlResult {
    bool handled{false};
    ThreatLevel threat{ThreatLevel::Low};
    ResponseAction action{ResponseAction::Log};
    std::string reason;
    bool stopProcessing{false};
    uint64_t request_id{0};
};

struct PolicyDecision {
    ResponseAction action{ResponseAction::Log};
    ThreatLevel level{ThreatLevel::Low};
    std::string reason;
    std::string matched_source;
    std::string matched_module;
    uint64_t request_id{0};
};

inline std::string toString(ThreatLevel level) {
    switch (level) {
        case ThreatLevel::Low: return "Low";
        case ThreatLevel::Medium: return "Medium";
        case ThreatLevel::High: return "High";
        case ThreatLevel::Critical: return "Critical";
    }
    return "Unknown";
}

inline std::string toString(ResponseAction action) {
    switch (action) {
        case ResponseAction::Log: return "Log";
        case ResponseAction::Notify: return "Notify";
        case ResponseAction::Block: return "Block";
        case ResponseAction::Isolate: return "Isolate";
        case ResponseAction::Terminate: return "Terminate";
    }
    return "Unknown";
}

namespace IoctlCodes {
    // Keep the C++ core and the Rust/kernel bridge on one ABI contract.
    constexpr uint32_t IOCTL_AMSI_SCAN_BUFFER = EVERBLOOM_IOCTL_AMSI_SCAN_BUFFER;
    constexpr uint32_t IOCTL_SCAN_FILE = EVERBLOOM_IOCTL_SCAN_FILE;
    constexpr uint32_t IOCTL_NET_INSPECT = EVERBLOOM_IOCTL_NET_INSPECT;
    constexpr uint32_t IOCTL_BEHAVIOR_ANALYZE = EVERBLOOM_IOCTL_BEHAVIOR_ANALYZE;
    constexpr uint32_t IOCTL_POLICY_UPDATE = EVERBLOOM_IOCTL_POLICY_UPDATE;
    constexpr uint32_t IOCTL_POLICY_CLEAR = EVERBLOOM_IOCTL_POLICY_CLEAR;
    constexpr uint32_t IOCTL_PROTECTION_UPDATE = EVERBLOOM_IOCTL_PROTECTION_UPDATE;
    constexpr uint32_t IOCTL_EVENT_READ = EVERBLOOM_IOCTL_EVENT_READ;
    constexpr uint32_t IOCTL_CAPABILITIES_QUERY = EVERBLOOM_IOCTL_CAPABILITIES_QUERY;
}

} // namespace everbloom::driver
