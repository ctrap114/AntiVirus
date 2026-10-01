#pragma once

#include "driver_types.hpp"

#include <functional>
#include <mutex>
#include <string>
#include <vector>

namespace everbloom::driver {

// Event is defined in driver_types.hpp to allow IRP payload inclusion and typed events.

using EventHandler = std::function<void(const Event&)>;

class EventBus {
public:
    void subscribe(EventHandler handler);
    void publish(const Event& event) const;

private:
    mutable std::mutex mutex_;
    std::vector<EventHandler> listeners_;
};

} // namespace everbloom::driver
