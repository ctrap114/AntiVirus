#pragma once

#include <atomic>
#include <functional>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include <windows.h>

namespace everbloom::gui {

class ProtectionMonitor final {
public:
    using EventHandler = std::function<void(const std::wstring&)>;

    ProtectionMonitor() = default;
    ~ProtectionMonitor();

    ProtectionMonitor(ProtectionMonitor const&) = delete;
    ProtectionMonitor& operator=(ProtectionMonitor const&) = delete;

    bool Start(std::vector<std::wstring> directories, EventHandler handler);
    void Stop();
    bool IsRunning() const;

private:
    void WorkerLoop(std::vector<std::wstring> directories, EventHandler handler);
    void MonitorDirectory(std::wstring directory, HANDLE handle, EventHandler handler);

    std::atomic<bool> m_stop{false};
    std::atomic<bool> m_running{false};
    std::thread m_worker;
    std::mutex m_handles_mutex;
    std::vector<HANDLE> m_handles;
};

} // namespace everbloom::gui
