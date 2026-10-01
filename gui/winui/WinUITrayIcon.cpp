#include "WinUITrayIcon.h"
#include "resource.h"

#include <shellapi.h>

#include <utility>

namespace everbloom::gui {
namespace {

constexpr UINT kTrayMessage = WM_APP + 0x51;
constexpr UINT kTrayIconId = 1;
constexpr UINT kShowCommand = 1001;
constexpr UINT kExitCommand = 1002;
constexpr wchar_t kMessageWindowClass[] = L"EverbloomSecurityTrayMessageWindow";
constexpr wchar_t kWindowProperty[] = L"EverbloomSecurity.TrayIcon.Context";

bool IsCloseCommand(WPARAM wparam) {
    return (wparam & 0xfff0U) == SC_CLOSE;
}

} // namespace

TrayIcon::~TrayIcon() {
    Remove();
}

bool TrayIcon::Install(HWND main_window, Callback show_callback, Callback exit_callback) {
    Remove();
    if (main_window == nullptr || !IsWindow(main_window)) {
        return false;
    }

    WNDCLASSW window_class{};
    window_class.lpfnWndProc = &TrayIcon::MessageWindowProc;
    window_class.hInstance = GetModuleHandleW(nullptr);
    window_class.lpszClassName = kMessageWindowClass;
    RegisterClassW(&window_class);

    m_main_window = main_window;
    m_show_callback = std::move(show_callback);
    m_exit_callback = std::move(exit_callback);
    m_message_window = CreateWindowExW(
        0,
        kMessageWindowClass,
        L"EverbloomSecurity tray",
        0,
        0,
        0,
        0,
        0,
        HWND_MESSAGE,
        nullptr,
        GetModuleHandleW(nullptr),
        this);
    if (m_message_window == nullptr) {
        m_main_window = nullptr;
        m_show_callback = {};
        m_exit_callback = {};
        return false;
    }

    SetPropW(m_main_window, kWindowProperty, this);
    SetLastError(ERROR_SUCCESS);
    m_original_main_proc = reinterpret_cast<WNDPROC>(SetWindowLongPtrW(
        m_main_window,
        GWLP_WNDPROC,
        reinterpret_cast<LONG_PTR>(&TrayIcon::MainWindowProc)));
    if (m_original_main_proc == nullptr && GetLastError() != ERROR_SUCCESS) {
        Remove();
        return false;
    }

    NOTIFYICONDATAW icon{};
    icon.cbSize = sizeof(icon);
    icon.hWnd = m_message_window;
    icon.uID = kTrayIconId;
    icon.uFlags = NIF_MESSAGE | NIF_ICON | NIF_TIP;
    icon.uCallbackMessage = kTrayMessage;
    icon.hIcon = LoadIconW(GetModuleHandleW(nullptr), MAKEINTRESOURCEW(IDI_EVERBLOOM_ICON));
    if (icon.hIcon == nullptr) {
        icon.hIcon = LoadIconW(nullptr, MAKEINTRESOURCEW(IDI_APPLICATION));
    }
    wcscpy_s(icon.szTip, L"EverbloomSecurity");
    if (!Shell_NotifyIconW(NIM_ADD, &icon)) {
        Remove();
        return false;
    }
    icon.uVersion = NOTIFYICON_VERSION_4;
    Shell_NotifyIconW(NIM_SETVERSION, &icon);
    m_installed = true;
    return true;
}

void TrayIcon::Remove() {
    if (m_message_window != nullptr) {
        NOTIFYICONDATAW icon{};
        icon.cbSize = sizeof(icon);
        icon.hWnd = m_message_window;
        icon.uID = kTrayIconId;
        Shell_NotifyIconW(NIM_DELETE, &icon);
    }
    if (m_main_window != nullptr && m_original_main_proc != nullptr) {
        SetWindowLongPtrW(
            m_main_window,
            GWLP_WNDPROC,
            reinterpret_cast<LONG_PTR>(m_original_main_proc));
        RemovePropW(m_main_window, kWindowProperty);
    }
    if (m_message_window != nullptr) {
        DestroyWindow(m_message_window);
    }
    m_main_window = nullptr;
    m_message_window = nullptr;
    m_original_main_proc = nullptr;
    m_allow_close = false;
    m_installed = false;
    m_show_callback = {};
    m_exit_callback = {};
}

void TrayIcon::AllowClose() {
    m_allow_close = true;
}

LRESULT CALLBACK TrayIcon::MessageWindowProc(
    HWND window,
    UINT message,
    WPARAM wparam,
    LPARAM lparam) {
    auto* self = reinterpret_cast<TrayIcon*>(GetWindowLongPtrW(window, GWLP_USERDATA));
    if (message == WM_NCCREATE) {
        const auto* create = reinterpret_cast<const CREATESTRUCTW*>(lparam);
        self = create == nullptr ? nullptr : static_cast<TrayIcon*>(create->lpCreateParams);
        SetWindowLongPtrW(window, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(self));
    }
    return self == nullptr
        ? DefWindowProcW(window, message, wparam, lparam)
        : self->HandleMessageWindow(window, message, wparam, lparam);
}

LRESULT CALLBACK TrayIcon::MainWindowProc(
    HWND window,
    UINT message,
    WPARAM wparam,
    LPARAM lparam) {
    auto* self = reinterpret_cast<TrayIcon*>(GetPropW(window, kWindowProperty));
    if (self != nullptr) {
        return self->HandleMainWindow(window, message, wparam, lparam);
    }
    return DefWindowProcW(window, message, wparam, lparam);
}

LRESULT TrayIcon::HandleMessageWindow(HWND window, UINT message, WPARAM wparam, LPARAM lparam) {
    if (message == kTrayMessage) {
        const UINT event = LOWORD(lparam);
        if (event == WM_LBUTTONDBLCLK || event == WM_LBUTTONUP) {
            ShowMainWindow();
        } else if (event == WM_RBUTTONUP) {
            ShowContextMenu();
        }
        return 0;
    }
    if (message == WM_COMMAND) {
        switch (LOWORD(wparam)) {
        case kShowCommand:
            ShowMainWindow();
            return 0;
        case kExitCommand:
            RequestExit();
            return 0;
        default:
            break;
        }
    }
    return DefWindowProcW(window, message, wparam, lparam);
}

LRESULT TrayIcon::HandleMainWindow(HWND window, UINT message, WPARAM wparam, LPARAM lparam) {
    if (!m_allow_close && (message == WM_CLOSE
        || (message == WM_SYSCOMMAND && IsCloseCommand(wparam)))) {
        ShowWindow(window, SW_HIDE);
        return 0;
    }
    if (message == WM_NCDESTROY) {
        auto original = m_original_main_proc;
        m_original_main_proc = nullptr;
        RemovePropW(window, kWindowProperty);
        if (original != nullptr) {
            SetWindowLongPtrW(window, GWLP_WNDPROC, reinterpret_cast<LONG_PTR>(original));
            return CallWindowProcW(original, window, message, wparam, lparam);
        }
    }
    return m_original_main_proc == nullptr
        ? DefWindowProcW(window, message, wparam, lparam)
        : CallWindowProcW(m_original_main_proc, window, message, wparam, lparam);
}

void TrayIcon::ShowContextMenu() {
    if (m_message_window == nullptr) {
        return;
    }
    POINT point{};
    GetCursorPos(&point);
    HMENU menu = CreatePopupMenu();
    if (menu == nullptr) {
        return;
    }
    AppendMenuW(menu, MF_STRING, kShowCommand, L"打开 EverbloomSecurity");
    AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
    AppendMenuW(menu, MF_STRING, kExitCommand, L"退出");
    SetForegroundWindow(m_message_window);
    TrackPopupMenu(menu, TPM_RIGHTBUTTON, point.x, point.y, 0, m_message_window, nullptr);
    PostMessageW(m_message_window, WM_NULL, 0, 0);
    DestroyMenu(menu);
}

void TrayIcon::ShowMainWindow() {
    if (m_show_callback) {
        m_show_callback();
        return;
    }
    if (m_main_window != nullptr) {
        ShowWindow(m_main_window, SW_SHOW);
        SetForegroundWindow(m_main_window);
    }
}

void TrayIcon::RequestExit() {
    if (m_exit_callback) {
        m_exit_callback();
    }
}

} // namespace everbloom::gui
