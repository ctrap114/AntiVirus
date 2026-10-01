#pragma once

#include <string>

#include <windows.h>

namespace everbloom::gui {

class EngineProcess final {
public:
    EngineProcess() = default;
    ~EngineProcess();

    EngineProcess(EngineProcess const&) = delete;
    EngineProcess& operator=(EngineProcess const&) = delete;

    // endpoint is retained for source compatibility with the old named-pipe
    // launcher.  The active transport is anonymous-pipe NDJSON on stdin/stdout.
    bool Start(std::wstring endpoint = {});
    void Stop();
    bool IsRunning() const;
    std::wstring LastError() const;

    HANDLE TakeStdinWriteHandle() noexcept;
    HANDLE TakeStdoutReadHandle() noexcept;

    // Shared helpers for sibling launchers (e.g. the AI training runner).
    static std::wstring ExeDirectory();
    static std::wstring Win32ErrorMessage(DWORD error);

private:
    static std::wstring ExecutableDirectory();
    static std::wstring FormatWin32Error(DWORD error);

    PROCESS_INFORMATION m_process{};
    HANDLE m_stdin_write{INVALID_HANDLE_VALUE};
    HANDLE m_stdout_read{INVALID_HANDLE_VALUE};
    std::wstring m_last_error;
};

} // namespace everbloom::gui
