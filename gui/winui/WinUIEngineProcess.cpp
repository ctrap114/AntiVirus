#include "WinUIEngineProcess.h"

#include <array>
#include <cwchar>
#include <filesystem>
#include <sstream>
#include <system_error>
#include <vector>

namespace everbloom::gui {

void NotifyWinUiStage(const std::wstring& stage);

namespace {

std::wstring QuoteCommandLineArgument(const std::wstring& value) {
    std::wstring quoted = L"\"";
    for (const wchar_t character : value) {
        if (character == L'\"') {
            quoted += L"\\\"";
        } else {
            quoted.push_back(character);
        }
    }
    quoted += L"\"";
    return quoted;
}

bool SetEnvironmentValue(const wchar_t* name, const std::wstring& value) {
    return SetEnvironmentVariableW(name, value.c_str()) != FALSE;
}

std::wstring FromNarrow(const char* value) {
    if (value == nullptr || value[0] == '\0') {
        return {};
    }
    int size = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, value, -1, nullptr, 0);
    UINT codepage = CP_UTF8;
    DWORD flags = MB_ERR_INVALID_CHARS;
    if (size <= 0) {
        codepage = CP_ACP;
        flags = 0;
        size = MultiByteToWideChar(codepage, flags, value, -1, nullptr, 0);
    }
    if (size <= 0) {
        return L"unprintable error";
    }
    std::wstring result(static_cast<size_t>(size), L'\0');
    MultiByteToWideChar(codepage, flags, value, -1, result.data(), size);
    if (!result.empty() && result.back() == L'\0') {
        result.pop_back();
    }
    return result;
}

std::wstring ErrorCodeMessage(const std::error_code& error) {
    return FromNarrow(error.message().c_str());
}

void LogStartStage(const std::wstring& stage) {
    NotifyWinUiStage(L"EngineProcess::Start: " + stage);
}

std::filesystem::path UserModelDirectory() {
    std::array<wchar_t, 32768> buffer{};
    const DWORD size = GetEnvironmentVariableW(
        L"LOCALAPPDATA", buffer.data(), static_cast<DWORD>(buffer.size()));
    if (size == 0 || size >= buffer.size()) {
        return {};
    }
    return std::filesystem::path(std::wstring(buffer.data(), size)) / L"EverbloomSecurity" / L"models";
}

} // namespace

EngineProcess::~EngineProcess() {
    Stop();
}

bool EngineProcess::Start(std::wstring endpoint) {
    (void)endpoint;
    try {
        LogStartStage(L"begin");
        Stop();
        m_last_error.clear();

        const std::wstring directory = ExecutableDirectory();
        if (directory.empty()) {
            m_last_error = L"Unable to determine the GUI executable directory.";
            LogStartStage(L"failed: " + m_last_error);
            return false;
        }
        LogStartStage(L"executable directory: " + directory);

        const std::filesystem::path engine_path =
            std::filesystem::path(directory) / L"everbloom_engine.exe";
        std::error_code engine_file_error;
        if (!std::filesystem::is_regular_file(engine_path, engine_file_error)) {
            m_last_error = L"The staged EverbloomSecurity engine was not found: " + engine_path.wstring();
            if (engine_file_error) {
                m_last_error += L" (" + ErrorCodeMessage(engine_file_error) + L")";
            }
            LogStartStage(L"failed: " + m_last_error);
            return false;
        }
        LogStartStage(L"engine executable found: " + engine_path.wstring());

        LogStartStage(L"setting NDJSON transport and parent PID");
        SetEnvironmentVariableW(L"EVERBLOOM_IPC_ENDPOINT", nullptr);
        if (!SetEnvironmentValue(
                L"EVERBLOOM_PARENT_PID", std::to_wstring(GetCurrentProcessId()))) {
            m_last_error = FormatWin32Error(GetLastError());
            LogStartStage(L"failed: " + m_last_error);
            return false;
        }

        const std::filesystem::path model_directory = UserModelDirectory();
        if (!model_directory.empty()) {
            LogStartStage(L"preparing model directory: " + model_directory.wstring());
            std::error_code model_error;
            std::filesystem::create_directories(model_directory, model_error);
            if (model_error) {
                LogStartStage(L"model directory unavailable: " + ErrorCodeMessage(model_error));
            } else if (!SetEnvironmentValue(L"EVERBLOOM_AI_MODEL_DIR", model_directory.wstring())
                || !SetEnvironmentValue(
                    L"EVERBLOOM_AI_MODELS_CONFIG",
                    (model_directory / L"models.json").wstring())) {
                m_last_error = FormatWin32Error(GetLastError());
                LogStartStage(L"failed: " + m_last_error);
                return false;
            }
        }

        const std::filesystem::path hash_db = std::filesystem::path(directory) / L"data" / L"local_hashes.sqlite";
        std::error_code hash_error;
        if (std::filesystem::is_regular_file(hash_db, hash_error)) {
            LogStartStage(L"hash database found: " + hash_db.wstring());
            if (!SetEnvironmentValue(L"EVERBLOOM_HASH_DB", hash_db.wstring())) {
                m_last_error = FormatWin32Error(GetLastError());
                LogStartStage(L"failed: " + m_last_error);
                return false;
            }
        } else {
            if (hash_error) {
                LogStartStage(L"hash database check failed: " + ErrorCodeMessage(hash_error));
            } else {
                LogStartStage(L"hash database not staged; clearing EVERBLOOM_HASH_DB");
            }
            SetEnvironmentVariableW(L"EVERBLOOM_HASH_DB", nullptr);
        }

        const std::filesystem::path rules_directory = std::filesystem::path(directory) / L"data" / L"rules";
        std::error_code rules_error;
        if (std::filesystem::is_directory(rules_directory, rules_error)) {
            LogStartStage(L"rules directory found: " + rules_directory.wstring());
            if (!SetEnvironmentValue(L"EVERBLOOM_RULES_DIR", rules_directory.wstring())) {
                m_last_error = FormatWin32Error(GetLastError());
                LogStartStage(L"failed: " + m_last_error);
                return false;
            }
        } else if (rules_error) {
            LogStartStage(L"rules directory check failed: " + ErrorCodeMessage(rules_error));
        }

        SECURITY_ATTRIBUTES security_attributes{};
        security_attributes.nLength = sizeof(security_attributes);
        security_attributes.bInheritHandle = TRUE;

        HANDLE child_stdin_read = INVALID_HANDLE_VALUE;
        HANDLE parent_stdin_write = INVALID_HANDLE_VALUE;
        HANDLE parent_stdout_read = INVALID_HANDLE_VALUE;
        HANDLE child_stdout_write = INVALID_HANDLE_VALUE;
        HANDLE child_stderr = INVALID_HANDLE_VALUE;
        auto close_local_handles = [&] {
            for (HANDLE* handle : {&child_stdin_read, &parent_stdin_write, &parent_stdout_read,
                                   &child_stdout_write, &child_stderr}) {
                if (*handle != INVALID_HANDLE_VALUE && *handle != nullptr) {
                    CloseHandle(*handle);
                    *handle = INVALID_HANDLE_VALUE;
                }
            }
        };

        LogStartStage(L"creating anonymous stdin/stdout pipes");
        if (!CreatePipe(
                &child_stdin_read,
                &parent_stdin_write,
                &security_attributes,
                0)
            || !SetHandleInformation(parent_stdin_write, HANDLE_FLAG_INHERIT, 0)
            || !CreatePipe(
                &parent_stdout_read,
                &child_stdout_write,
                &security_attributes,
                0)
            || !SetHandleInformation(parent_stdout_read, HANDLE_FLAG_INHERIT, 0)) {
            m_last_error = FormatWin32Error(GetLastError());
            close_local_handles();
            LogStartStage(L"failed creating anonymous pipes: " + m_last_error);
            return false;
        }

        child_stderr = CreateFileW(
            L"NUL",
            GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            &security_attributes,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            nullptr);
        if (child_stderr == INVALID_HANDLE_VALUE) {
            m_last_error = FormatWin32Error(GetLastError());
            close_local_handles();
            LogStartStage(L"failed creating child stderr sink: " + m_last_error);
            return false;
        }

        std::wstring command_line = QuoteCommandLineArgument(engine_path.wstring()) + L" --ndjson";
        std::vector<wchar_t> command_line_buffer(command_line.begin(), command_line.end());
        command_line_buffer.push_back(L'\0');
        STARTUPINFOW startup{};
        startup.cb = sizeof(startup);
        startup.dwFlags = STARTF_USESTDHANDLES;
        startup.hStdInput = child_stdin_read;
        startup.hStdOutput = child_stdout_write;
        startup.hStdError = child_stderr;
        PROCESS_INFORMATION process{};

        LogStartStage(L"creating engine process with NDJSON stdio");
        if (!CreateProcessW(
                engine_path.c_str(),
                command_line_buffer.data(),
                nullptr,
                nullptr,
                TRUE,
                CREATE_NO_WINDOW,
                nullptr,
                directory.c_str(),
                &startup,
                &process)) {
            m_last_error = FormatWin32Error(GetLastError());
            close_local_handles();
            LogStartStage(L"failed: " + m_last_error);
            return false;
        }

        CloseHandle(child_stdin_read);
        child_stdin_read = INVALID_HANDLE_VALUE;
        CloseHandle(child_stdout_write);
        child_stdout_write = INVALID_HANDLE_VALUE;
        CloseHandle(child_stderr);
        child_stderr = INVALID_HANDLE_VALUE;
        CloseHandle(process.hThread);
        m_process = process;
        m_stdin_write = parent_stdin_write;
        parent_stdin_write = INVALID_HANDLE_VALUE;
        m_stdout_read = parent_stdout_read;
        parent_stdout_read = INVALID_HANDLE_VALUE;
        LogStartStage(L"engine process created; pid=" + std::to_wstring(process.dwProcessId));
        return true;
    } catch (const std::filesystem::filesystem_error& error) {
        m_last_error = L"Filesystem exception while starting the engine: " + FromNarrow(error.what());
        LogStartStage(L"failed: " + m_last_error);
        return false;
    } catch (const std::exception& error) {
        m_last_error = L"Standard exception while starting the engine: " + FromNarrow(error.what());
        LogStartStage(L"failed: " + m_last_error);
        return false;
    } catch (...) {
        m_last_error = L"Unknown exception while starting the engine.";
        LogStartStage(L"failed: " + m_last_error);
        return false;
    }
}

void EngineProcess::Stop() {
    if (m_stdin_write != INVALID_HANDLE_VALUE) {
        CloseHandle(m_stdin_write);
        m_stdin_write = INVALID_HANDLE_VALUE;
    }
    if (m_stdout_read != INVALID_HANDLE_VALUE) {
        CloseHandle(m_stdout_read);
        m_stdout_read = INVALID_HANDLE_VALUE;
    }
    if (m_process.hProcess == nullptr) {
        return;
    }

    DWORD exit_code = STILL_ACTIVE;
    if (!GetExitCodeProcess(m_process.hProcess, &exit_code)) {
        LogStartStage(
            L"RUST_ENGINE_EXIT status=unknown win32=" + std::to_wstring(GetLastError()));
    } else if (exit_code == STILL_ACTIVE) {
        LogStartStage(L"RUST_ENGINE_TERMINATING reason=gui_stop");
        TerminateProcess(m_process.hProcess, 0);
        WaitForSingleObject(m_process.hProcess, 3000);
        if (GetExitCodeProcess(m_process.hProcess, &exit_code)) {
            LogStartStage(
                L"RUST_ENGINE_EXIT status=terminated_by_gui code="
                + std::to_wstring(exit_code));
        }
    } else {
        LogStartStage(
            L"RUST_ENGINE_EXIT status=observed code=" + std::to_wstring(exit_code));
    }
    CloseHandle(m_process.hProcess);
    m_process = {};
}

HANDLE EngineProcess::TakeStdinWriteHandle() noexcept {
    const HANDLE handle = m_stdin_write;
    m_stdin_write = INVALID_HANDLE_VALUE;
    return handle;
}

HANDLE EngineProcess::TakeStdoutReadHandle() noexcept {
    const HANDLE handle = m_stdout_read;
    m_stdout_read = INVALID_HANDLE_VALUE;
    return handle;
}

bool EngineProcess::IsRunning() const {
    if (m_process.hProcess == nullptr) {
        return false;
    }
    DWORD exit_code = 0;
    return GetExitCodeProcess(m_process.hProcess, &exit_code) != FALSE
        && exit_code == STILL_ACTIVE;
}

std::wstring EngineProcess::LastError() const {
    return m_last_error;
}

std::wstring EngineProcess::ExecutableDirectory() {
    std::array<wchar_t, 32768> buffer{};
    const DWORD size = GetModuleFileNameW(nullptr, buffer.data(), static_cast<DWORD>(buffer.size()));
    if (size == 0 || size >= buffer.size()) {
        return {};
    }
    std::filesystem::path path(std::wstring(buffer.data(), size));
    return path.parent_path().wstring();
}

std::wstring EngineProcess::ExeDirectory() {
    return ExecutableDirectory();
}

std::wstring EngineProcess::Win32ErrorMessage(DWORD error) {
    return FormatWin32Error(error);
}

std::wstring EngineProcess::FormatWin32Error(DWORD error) {
    if (error == ERROR_SUCCESS) {
        return L"Unknown Win32 error.";
    }
    LPWSTR buffer = nullptr;
    const DWORD size = FormatMessageW(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        nullptr,
        error,
        0,
        reinterpret_cast<LPWSTR>(&buffer),
        0,
        nullptr);
    std::wstring message = size > 0 && buffer != nullptr ? std::wstring(buffer, size)
                                                          : L"Win32 error " + std::to_wstring(error);
    if (buffer != nullptr) {
        LocalFree(buffer);
    }
    while (!message.empty() && (message.back() == L'\r' || message.back() == L'\n')) {
        message.pop_back();
    }
    return message;
}

} // namespace everbloom::gui
