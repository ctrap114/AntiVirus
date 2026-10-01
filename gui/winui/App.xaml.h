#pragma once
namespace winrt {
namespace EverbloomSecurity {
namespace GUI {
namespace WinUI {
class App : public winrt::Microsoft::UI::Xaml::ApplicationT<App> {
public:
    App();
    static winrt::Microsoft::UI::Xaml::DependencyProperty ThemeProperty();
};
} // WinUI
} // GUI
} // EverbloomSecurity
} // winrt
