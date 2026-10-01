#include "network_firewall.hpp"
#include "irp_utils.hpp"

namespace everbloom::driver {

NetworkFirewallModule::NetworkFirewallModule(EventBus& bus, Logger& logger)
    : event_bus_(bus), logger_(logger) {
}

void NetworkFirewallModule::initialize() {
    logger_.log(LogLevel::Info, "Network firewall initialized");
    // Network requests are owned by IrpDispatcher; this module is a pure
    // inspection stage and does not consume its own telemetry.
    Event pub{EventType::Generic, "network_firewall", "network_firewall", "Network filtering enabled", std::nullopt, ThreatLevel::Low, EventSeverity::Info};
    event_bus_.publish(pub);
}

void NetworkFirewallModule::shutdown() {
    logger_.log(LogLevel::Info, "Network firewall shutdown");
}

IoctlResult NetworkFirewallModule::handleIoctl(const IRP& irp) {
    const bool suspicious = !inspectConnection(irp.Target) || !inspectPayload(irp.Payload);
    const ThreatLevel threat = suspicious ? ThreatLevel::High : ThreatLevel::Medium;
    const ResponseAction action = suspicious ? ResponseAction::Block : ResponseAction::Notify;
    logger_.log(suspicious ? LogLevel::Warning : LogLevel::Info,
                "Network firewall processed IOCTL for " + irp.Target);
    Event pub{EventType::Policy, "network_firewall", "network_firewall", "followup:" + irp.Target, irp, threat, suspicious ? EventSeverity::Warning : EventSeverity::Info};
    event_bus_.publish(pub);
    return {true, threat, action, "Network inspection result", suspicious};
}

bool NetworkFirewallModule::inspectConnection(const std::string& remote) const {
    return remote.find("malicious") == std::string::npos;
}

bool NetworkFirewallModule::inspectPayload(const std::string& payload) const {
    return payload.find("http") != std::string::npos;
}

} // namespace everbloom::driver
