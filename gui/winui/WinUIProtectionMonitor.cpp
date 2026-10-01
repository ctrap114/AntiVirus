#include "WinUIProtectionMonitor.h"

#include <algorithm>
#include <filesystem>

namespace everbloom::gui {

ProtectionMonitor::~ProtectionMonitor() {
    Stop();
}

bool ProtectionMonitor::Start(std::vector<std::wstring> directories, EventHandler handler) {
    Stop();
    directories.erase(
        std::remove_if(
            directories.begin(),
            directories.end(),
            [](const std::wstring& directory) {
                std::error_code error;
                return directory.empty() || !std::filesystem::is_directory(directory, error);
            }),
        directories.end());
    if (directories.empty()) {
        return false;
    }

    m_stop.store(false);
    m_running.store(true);
    m_worker = std::thread([this, directories = std::move(directories), handler = std::move(handler)]() mutable {
        WorkerLoop(std::move(directories), std::move(handler));
    });
    return true;
}

void ProtectionMonitor::Stop() {
    m_stop.store(true);
    {
        std::lock_guard lock(m_handles_mutex);
        for (HANDLE handle : m_handles) {
            if (handle != INVALID_HANDLE_VALUE) {
                CancelIoEx(handle, nullptr);
            }
        }
    }
    if (m_worker.joinable()) {
        m_worker.join();
    }
    m_running.store(false);
}

bool ProtectionMonitor::IsRunning() const {
    return m_running.load();
}

void ProtectionMonitor::WorkerLoop(std::vector<std::wstring> directories, EventHandler handler) {
    std::vector<std::wstring> active_directories;
    for (const std::wstring& directory : directories) {
        const HANDLE handle = CreateFileW(
            directory.c_str(),
            FILE_LIST_DIRECTORY,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            nullptr,
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS,
            nullptr);
        if (handle == INVALID_HANDLE_VALUE) {
            continue;
        }
        {
            std::lock_guard lock(m_handles_mutex);
            m_handles.push_back(handle);
        }
        active_directories.push_back(directory);
    }

    if (active_directories.empty()) {
        m_running.store(false);
        return;
    }

    std::vector<std::thread> watchers;
    watchers.reserve(active_directories.size());
    for (size_t index = 0; index < active_directories.size(); ++index) {
        HANDLE handle = INVALID_HANDLE_VALUE;
        {
            std::lock_guard lock(m_handles_mutex);
            if (index < m_handles.size()) {
                handle = m_handles[index];
            }
        }
        if (handle == INVALID_HANDLE_VALUE) {
            continue;
        }
        watchers.emplace_back(
            [this, directory = active_directories[index], handle, handler] {
                MonitorDirectory(directory, handle, handler);
            });
    }
    for (auto& watcher : watchers) {
        if (watcher.joinable()) {
            watcher.join();
        }
    }

    {
        std::lock_guard lock(m_handles_mutex);
        for (HANDLE handle : m_handles) {
            if (handle != INVALID_HANDLE_VALUE) {
                CloseHandle(handle);
            }
        }
        m_handles.clear();
    }
    m_running.store(false);
}

void ProtectionMonitor::MonitorDirectory(
    std::wstring directory,
    HANDLE handle,
    EventHandler handler) {
    std::vector<BYTE> buffer(64 * 1024);
    while (!m_stop.load()) {
        DWORD bytes_returned = 0;
        const BOOL changed = ReadDirectoryChangesW(
            handle,
            buffer.data(),
            static_cast<DWORD>(buffer.size()),
            TRUE,
            FILE_NOTIFY_CHANGE_FILE_NAME
                | FILE_NOTIFY_CHANGE_DIR_NAME
                | FILE_NOTIFY_CHANGE_LAST_WRITE
                | FILE_NOTIFY_CHANGE_SIZE,
            &bytes_returned,
            nullptr,
            nullptr);
        if (!changed || m_stop.load()) {
            break;
        }
        if (bytes_returned == 0) {
            continue;
        }

        DWORD offset = 0;
        while (offset + sizeof(FILE_NOTIFY_INFORMATION) <= bytes_returned) {
            const auto* notification = reinterpret_cast<const FILE_NOTIFY_INFORMATION*>(buffer.data() + offset);
            const std::wstring name(notification->FileName, notification->FileNameLength / sizeof(wchar_t));
            // Removed/renamed-old entries are no longer scannable and caused
            // avoidable IPC traffic. Only inspect new or modified files.
            const bool actionable = notification->Action == FILE_ACTION_ADDED
                || notification->Action == FILE_ACTION_MODIFIED
                || notification->Action == FILE_ACTION_RENAMED_NEW_NAME;
            if (handler && actionable && !name.empty()) {
                handler((std::filesystem::path(directory) / name).wstring());
            }
            if (notification->NextEntryOffset == 0) {
                break;
            }
            if (offset + notification->NextEntryOffset > bytes_returned) {
                break;
            }
            offset += notification->NextEntryOffset;
        }
    }
}

} // namespace everbloom::gui
