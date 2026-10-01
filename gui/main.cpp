#include "WinUIApp.h"
#include "resource.h"

#include <windows.h>
#include <MddBootstrap.h>
#include <WindowsAppSDK-VersionInfo.h>
#include <winrt/Windows.Foundation.h>
#include <winrt/Microsoft.UI.Xaml.h>
#include <winrt/base.h>

#include <filesystem>
#include <fstream>
#include <mutex>
#include <algorithm>
#include <string>

using namespace winrt;
using namespace winrt::Microsoft::UI::Xaml;

namespace {

HWND g_startup_window = nullptr;
HWND g_startup_label = nullptr;
std::mutex g_startup_mutex;
winrt::com_ptr<everbloom::gui::App> g_app_instance;

std::filesystem::path StartupLogPath() {
    wchar_t buffer[32768]{};
    const DWORD length = GetTempPathW(static_cast<DWORD>(std::size(buffer)), buffer);
    if (length > 0 && length < std::size(buffer)) {
        return std::filesystem::path(buffer) / L"EverbloomSecurity-gui-startup.log";
    }
    return std::filesystem::path(L"EverbloomSecurity-gui-startup.log");
}

void StartupLog(const std::wstring& message) {
    std::lock_guard lock(g_startup_mutex);
    std::ofstream stream(StartupLogPath(), std::ios::app | std::ios::binary);
    if (stream) {
        SYSTEMTIME now{};
        GetLocalTime(&now);
        stream << now.wYear << '-' << now.wMonth << '-' << now.wDay
               << ' ' << now.wHour << ':' << now.wMinute << ':' << now.wSecond
               << " | ";
        if (!message.empty()) {
            const int size = WideCharToMultiByte(
                CP_UTF8,
                0,
                message.data(),
                static_cast<int>(message.size()),
                nullptr,
                0,
                nullptr,
                nullptr);
            std::string utf8(static_cast<size_t>(std::max(size, 0)), '\0');
            if (size > 0) {
                WideCharToMultiByte(
                    CP_UTF8,
                    0,
                    message.data(),
                    static_cast<int>(message.size()),
                    utf8.data(),
                    size,
                    nullptr,
                    nullptr);
            }
            stream << utf8;
        }
        stream << '\n';
    }
    OutputDebugStringW((L"EverbloomSecurity GUI: " + message + L"\n").c_str());
}

LRESULT CALLBACK StartupWindowProc(HWND window, UINT message, WPARAM wparam, LPARAM lparam) {
    switch (message) {
    case WM_CREATE:
        g_startup_label = CreateWindowExW(
            0,
            L"STATIC",
            L"EverbloomSecurity 正在启动 WinUI 3 图形界面…",
            WS_CHILD | WS_VISIBLE | SS_LEFT,
            28,
            28,
            640,
            52,
            window,
            nullptr,
            GetModuleHandleW(nullptr),
            nullptr);
        return 0;
    case WM_CLOSE:
        DestroyWindow(window);
        return 0;
    case WM_DESTROY:
        if (window == g_startup_window) {
            g_startup_window = nullptr;
            g_startup_label = nullptr;
        }
        return 0;
    default:
        return DefWindowProcW(window, message, wparam, lparam);
    }
}

void SetStartupStatus(const std::wstring& message) {
    StartupLog(message);
    if (g_startup_label != nullptr) {
        SetWindowTextW(g_startup_label, message.c_str());
    }
}

HWND ShowStartupWindow() {
    const wchar_t class_name[] = L"EverbloomSecurityStartupWindow";
    WNDCLASSW window_class{};
    window_class.lpfnWndProc = StartupWindowProc;
    window_class.hInstance = GetModuleHandleW(nullptr);
    window_class.hCursor = LoadCursorW(nullptr, MAKEINTRESOURCEW(32512));
    window_class.hIcon = LoadIconW(GetModuleHandleW(nullptr), MAKEINTRESOURCEW(IDI_EVERBLOOM_ICON));
    if (window_class.hIcon == nullptr) {
        window_class.hIcon = LoadIconW(nullptr, MAKEINTRESOURCEW(IDI_APPLICATION));
    }
    window_class.hbrBackground = reinterpret_cast<HBRUSH>(COLOR_WINDOW + 1);
    window_class.lpszClassName = class_name;
    RegisterClassW(&window_class);

    const HWND window = CreateWindowExW(
        0,
        class_name,
        L"EverbloomSecurity",
        WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX,
        CW_USEDEFAULT,
        CW_USEDEFAULT,
        720,
        180,
        nullptr,
        nullptr,
        GetModuleHandleW(nullptr),
        nullptr);
    if (window != nullptr) {
        g_startup_window = window;
        ShowWindow(window, SW_SHOW);
        UpdateWindow(window);
    }
    return window;
}

void HideStartupWindow() {
    if (g_startup_window != nullptr) {
        ShowWindow(g_startup_window, SW_HIDE);
    }
}

void RunStartupMessageLoop() {
    MSG message{};
    while (g_startup_window != nullptr && GetMessageW(&message, nullptr, 0, 0) > 0) {
        TranslateMessage(&message);
        DispatchMessageW(&message);
    }
}

std::wstring HResultText(HRESULT result) {
    wchar_t buffer[256]{};
    swprintf_s(buffer, L"0x%08X", static_cast<unsigned int>(result));
    return buffer;
}

void ShowStartupError(const wchar_t* stage, HRESULT result) {
    const std::wstring message =
        std::wstring(L"EverbloomSecurity could not start the WinUI runtime (") + stage +
        L").\nHRESULT: " + HResultText(result) +
        L"\nRun bin\\install_windows_app_runtime.cmd once, then try again.\nLog: "
        + StartupLogPath().wstring();
    SetStartupStatus(message);
}

} // namespace

int __stdcall wWinMain(HINSTANCE, HINSTANCE, PWSTR, int) {
    init_apartment(apartment_type::single_threaded);
    ShowStartupWindow();
    SetStartupStatus(L"正在初始化 Windows App SDK 运行时…");

    SetStartupStatus(L"Initializing the Windows App SDK runtime...");
    const HRESULT bootstrap_result = MddBootstrapInitialize2(
        WINDOWSAPPSDK_RELEASE_MAJORMINOR,
        WINDOWSAPPSDK_RELEASE_VERSION_TAG_W,
        PACKAGE_VERSION{WINDOWSAPPSDK_RUNTIME_VERSION_UINT64},
        // Do not ask the Windows App SDK bootstrapper to display its own
        // deployment UI. That dialog can be attached to a different desktop
        // and makes a failed startup look like a hung, invisible process.
        MddBootstrapInitializeOptions_None);
    if (FAILED(bootstrap_result)) {
        ShowStartupError(L"Windows App SDK Bootstrap", bootstrap_result);
        RunStartupMessageLoop();
        return static_cast<int>(bootstrap_result);
    }
    SetStartupStatus(L"Windows App SDK loaded; creating the main window...");
    SetStartupStatus(L"Windows App SDK 已加载，正在创建主界面…");

    int result = 0;

    try {
        Application::Start([](auto &&) {
            StartupLog(L"Application::Start callback entered");
            // Keep the implementation object alive explicitly.  A projected
            // Application interface stored globally has shown ABI teardown
            // issues in this runtime, but the implementation com_ptr avoids
            // the transient callback-local lifetime that can free App just
            // after OnLaunched returns.
            g_app_instance = winrt::make_self<everbloom::gui::App>();
            StartupLog(L"Application::Start callback completed");
        });
        StartupLog(L"Application::Start returned");
    } catch (const winrt::hresult_error& error) {
        ShowStartupError(L"WinUI Application", error.code());
        result = static_cast<int>(error.code());
    } catch (const std::exception&) {
        SetStartupStatus(L"WinUI Application failed with a standard C++ exception.\nLog: " + StartupLogPath().wstring());
        result = 1;
    } catch (...) {
        SetStartupStatus(L"WinUI Application failed with an unknown exception.\nLog: " + StartupLogPath().wstring());
        result = 1;
    }

    if (result != 0) {
        RunStartupMessageLoop();
    }
    if (g_startup_window != nullptr) {
        DestroyWindow(g_startup_window);
    }
    g_app_instance = nullptr;
    MddBootstrapShutdown();
    return result;
}

namespace everbloom::gui {

void NotifyWinUiLaunched() {
    StartupLog(L"App::OnLaunched entered");
}

void NotifyWinUiStage(const std::wstring& stage) {
    StartupLog(stage);
}

void NotifyWinUiWindowReady() {
    StartupLog(L"WinUI main window activated");
    HideStartupWindow();
}

} // namespace everbloom::gui
