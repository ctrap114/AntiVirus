#pragma once

#include <functional>

#include <windows.h>

namespace everbloom::gui {

// Native tray integration for the unpackaged WinUI desktop process. Closing
// the main HWND hides it; only the tray Exit command allows the real close.
class TrayIcon final {
public:
    using Callback = std::function<void()>;

    TrayIcon() = default;
    ~TrayIcon();

    TrayIcon(TrayIcon const&) = delete;
    TrayIcon& operator=(TrayIcon const&) = delete;

    bool Install(HWND main_window, Callback show_callback, Callback exit_callback);
    void Remove();
    void AllowClose();
    bool IsInstalled() const noexcept { return m_installed; }

private:
    static LRESULT CALLBACK MessageWindowProc(HWND window, UINT message, WPARAM wparam, LPARAM lparam);
    static LRESULT CALLBACK MainWindowProc(HWND window, UINT message, WPARAM wparam, LPARAM lparam);
    LRESULT HandleMessageWindow(HWND window, UINT message, WPARAM wparam, LPARAM lparam);
    LRESULT HandleMainWindow(HWND window, UINT message, WPARAM wparam, LPARAM lparam);
    void ShowContextMenu();
    void ShowMainWindow();
    void RequestExit();

    HWND m_main_window{nullptr};
    HWND m_message_window{nullptr};
    WNDPROC m_original_main_proc{nullptr};
    bool m_allow_close{false};
    bool m_installed{false};
    Callback m_show_callback;
    Callback m_exit_callback;
};

} // namespace everbloom::gui
