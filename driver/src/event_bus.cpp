#include "event_bus.hpp"

namespace everbloom::driver {

void EventBus::subscribe(EventHandler handler) {
    std::lock_guard<std::mutex> lock(mutex_);
    listeners_.push_back(std::move(handler));
}

void EventBus::publish(const Event& event) const {
    std::vector<EventHandler> listeners;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        listeners = listeners_;
    }
    // Callbacks may publish follow-up events. Invoke them outside the mutex so
    // event correlation cannot deadlock the protection pipeline.
    for (const auto& listener : listeners) {
        if (listener) {
            listener(event);
        }
    }
}

} // namespace everbloom::driver
