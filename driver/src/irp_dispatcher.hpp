#pragma once

#include "core_protection.hpp"
#include "driver_types.hpp"
#include "event_bus.hpp"
#include "logger.hpp"

#include <functional>
#include <atomic>
#include <cstdint>
#include <string>
#include <vector>

namespace everbloom::driver {

struct IrpHandlerEntry {
    std::string module;
    std::vector<uint32_t> ioctl_codes;
    int priority{0};
    std::function<IoctlResult(const IRP&)> handler;
};

class IrpDispatcher {
public:
    IrpDispatcher(EventBus& bus, Logger& logger, CoreProtectionEngine& engine);
    void registerHandler(const std::string& module, int priority, std::function<IoctlResult(const IRP&)> handler);
    void registerHandler(const std::string& module,
                         const std::vector<uint32_t>& ioctl_codes,
                         int priority,
                         std::function<IoctlResult(const IRP&)> handler);
    IoctlResult dispatch(const IRP& irp);

private:
    EventBus& event_bus_;
    Logger& logger_;
    CoreProtectionEngine& engine_;
    std::vector<IrpHandlerEntry> handlers_;
    std::atomic<uint64_t> next_request_id_{1};
};

} // namespace everbloom::driver
