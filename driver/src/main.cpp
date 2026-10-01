#include "core_protection.hpp"
#include "event_bus.hpp"
#include "file_protection.hpp"
#include "logger.hpp"
#include "amsi.hpp"
#include "realtime_scan.hpp"
#include "self_protection.hpp"
#include "network_firewall.hpp"
#include "advanced_threat.hpp"
#include "irp_dispatcher.hpp"

#include <iostream>

int main() {
    using namespace everbloom::driver;

    Logger logger;
    EventBus event_bus;

    logger.initialize();
    event_bus.subscribe([&logger](const Event& evt) {
        logger.log(LogLevel::Info, "Event published [" + evt.module + "]: " + evt.message);
    });

    CoreProtectionEngine engine(event_bus, logger);
    engine.initialize();
    engine.registerModule("self_protection");
    engine.registerModule("file_protection");
    engine.registerModule("amsi");
    engine.registerModule("realtime_scan");
    engine.registerModule("network_firewall");
    engine.registerModule("advanced_threat");
    engine.setModuleRisk("self_protection", ThreatLevel::Critical);
    engine.setModuleRisk("file_protection", ThreatLevel::High);
    engine.setModuleRisk("network_firewall", ThreatLevel::Medium);
    engine.setModuleRisk("advanced_threat", ThreatLevel::High);

    engine.addPolicyRule({"file_protection", "file_protection", "", 20, ThreatLevel::High, ResponseAction::Block, "Block high-risk file operations"});
    engine.addPolicyRule({"network_firewall", "network_firewall", "", 10, ThreatLevel::Medium, ResponseAction::Notify, "Notify on suspicious network activity"});
    engine.addPolicyRule({"advanced_threat", "advanced_threat", "", 15, ThreatLevel::High, ResponseAction::Terminate, "Terminate on advanced threat patterns"});
    engine.addPolicyRule({"self_protection", "self_protection", "", 30, ThreatLevel::Critical, ResponseAction::Terminate, "Terminate on self-protection bypass attempts"});

    SelfProtectionModule self_protection(event_bus, logger);
    FileProtectionModule file_protection(event_bus, logger);
    AmsiModule amsi(event_bus, logger);
    RealtimeScanModule realtime_scan(event_bus, logger);
    NetworkFirewallModule network_firewall(event_bus, logger);
    AdvancedThreatModule advanced_threat(event_bus, logger);

    self_protection.initialize();
    file_protection.initialize();
    amsi.initialize();
    realtime_scan.initialize();
    network_firewall.initialize();
    advanced_threat.initialize();

    IrpDispatcher dispatcher(event_bus, logger, engine);
    dispatcher.registerHandler("self_protection", 100, [&self_protection](const IRP& irp) { return self_protection.handleIoctl(irp); });
    dispatcher.registerHandler("file_protection", {IoctlCodes::IOCTL_SCAN_FILE}, 80, [&file_protection](const IRP& irp) { return file_protection.handleIoctl(irp); });
    dispatcher.registerHandler("realtime_scan", {IoctlCodes::IOCTL_SCAN_FILE}, 70, [&realtime_scan](const IRP& irp) { return realtime_scan.handleIoctl(irp); });
    dispatcher.registerHandler("network_firewall", {IoctlCodes::IOCTL_NET_INSPECT}, 60, [&network_firewall](const IRP& irp) { return network_firewall.handleIoctl(irp); });
    dispatcher.registerHandler("amsi", {IoctlCodes::IOCTL_AMSI_SCAN_BUFFER}, 50, [&amsi](const IRP& irp) { return amsi.handleIoctl(irp); });
    dispatcher.registerHandler("advanced_threat", {IoctlCodes::IOCTL_BEHAVIOR_ANALYZE}, 40, [&advanced_threat](const IRP& irp) { return advanced_threat.handleIoctl(irp); });

    self_protection.inspectControlRequest("IOCTL_EVERBLOOM_QUERY", "trusted");
    self_protection.inspectControlRequest("IOCTL_UNKNOWN_OPERATION", "untrusted");
    self_protection.inspectUnloadRequest("untrusted");
    self_protection.validateDeviceAccess("\\Device\\EverbloomSecurityControl");

    dispatcher.dispatch(IRP{IoctlCodes::IOCTL_AMSI_SCAN_BUFFER, "service", "powershell.exe", "powershell -enc ..."});
    dispatcher.dispatch(IRP{IoctlCodes::IOCTL_SCAN_FILE, "service", "C:/Users/test/evil.exe", "write"});
    dispatcher.dispatch(IRP{IoctlCodes::IOCTL_NET_INSPECT, "service", "malicious.example", "http"});
    dispatcher.dispatch(IRP{IoctlCodes::IOCTL_BEHAVIOR_ANALYZE, "service", "exploit", "shellcode"});

    EventContext ctx{"system", "custom_module", "process", "suspicious process execution", ThreatLevel::High};
    auto decision = engine.evaluate(ctx);

    std::cout << "decision=" << static_cast<int>(decision.action) << " level=" << static_cast<int>(decision.level) << " reason=" << decision.reason << "\n";

    self_protection.shutdown();
    file_protection.shutdown();
    amsi.shutdown();
    realtime_scan.shutdown();
    network_firewall.shutdown();
    advanced_threat.shutdown();
    engine.shutdown();
    logger.shutdown();
    return 0;
}
