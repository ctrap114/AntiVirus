#include "pch.h"
#include "EverbloomNavigationView.h"
#include "EverbloomNavigationView.g.cpp"

namespace EverbloomSecurity::GUI::WinUI::Controls::implementation
{
    using namespace winrt;
    using namespace Microsoft::UI::Xaml;
    using namespace Microsoft::UI::Xaml::Controls;
    using namespace Microsoft::UI::Xaml::Controls::Primitives;
    using namespace Microsoft::UI::Xaml::Media;
    using namespace Microsoft::UI::Xaml::Input;
    using namespace Microsoft::UI::Xaml::Media::Animation;
    using namespace Windows::UI;

    EverbloomNavigationView::EverbloomNavigationView()
    {
        DefaultStyleKey(winrt::box_value(L"EverbloomSecurity.GUI.WinUI.Controls.EverbloomNavigationView"));
        Loaded({ this, &EverbloomNavigationView::OnLoaded });
    }

    void EverbloomNavigationView::OnLoaded(IInspectable const& sender, RoutedEventArgs const& e)
    {
        UpdateVisualState();
    }

    void EverbloomNavigationView::UpdateVisualState()
    {
        // Update visual state based on current state
    }

    void EverbloomNavigationView::OnApplyTemplate()
    {
        NavigationView::OnApplyTemplate();

        // Find the selection indicator in the template
        m_selectionIndicator = GetTemplateChild(L"SelectionIndicator").try_as<Border>();
        
        if (m_selectionIndicator)
        {
            m_selectionIndicator.Width(3);
            m_selectionIndicator.Background(SolidColorBrush(Colors::Transparent()));
            m_selectionIndicator.HorizontalAlignment(HorizontalAlignment::Left);
            m_selectionIndicator.VerticalAlignment(VerticalAlignment::Stretch);
            m_selectionIndicator.Margin(Thickness(-3, 0, 0, 0));
            m_selectionIndicator.CornerRadius(CornerRadius(0, 4, 4, 0));
        }
    }

    void EverbloomNavigationView::OnSelectionChanged(NavigationView const& sender, NavigationViewSelectionChangedEventArgs const& args)
    {
        UpdateSelectionIndicator();
    }

    void EverbloomNavigationView::UpdateSelectionIndicator()
    {
        if (!m_selectionIndicator) return;

        auto selectedItem = SelectedItem().try_as<NavigationViewItem>();
        if (!selectedItem) return;

        // Animate indicator to selected item
        // This would typically use a storyboard or ConnectedAnimation
        // For now, just update position
    }

    // Dependency Property Definitions
    winrt::Microsoft::UI::Xaml::DependencyProperty EverbloomNavigationView::s_showSwordAccentProperty =
        DependencyProperty::Register(
            L"ShowSwordAccent",
            winrt::xaml_typename<bool>(),
            winrt::xaml_typename<EverbloomNavigationView>(),
            PropertyMetadata(winrt::box_value(true)));

    winrt::Microsoft::UI::Xaml::DependencyProperty EverbloomNavigationView::s_accentColorProperty =
        DependencyProperty::Register(
            L"AccentColor",
            winrt::xaml_typename<Brush>(),
            winrt::xaml_typename<EverbloomNavigationView>(),
            PropertyMetadata(nullptr));

    winrt::Microsoft::UI::Xaml::DependencyProperty EverbloomNavigationView::s_indicatorWidthProperty =
        DependencyProperty::Register(
            L"IndicatorWidth",
            winrt::xaml_typename<double>(),
            winrt::xaml_typename<EverbloomNavigationView>(),
            PropertyMetadata(winrt::box_value(3.0)));

    winrt::Microsoft::UI::Xaml::DependencyProperty EverbloomNavigationView::s_indicatorColorProperty =
        DependencyProperty::Register(
            L"IndicatorColor",
            winrt::xaml_typename<Brush>(),
            winrt::xaml_typename<EverbloomNavigationView>(),
            PropertyMetadata(nullptr));

    // Property Accessors
    bool EverbloomNavigationView::ShowSwordAccent()
    {
        return unbox_value<bool>(GetValue(s_showSwordAccentProperty));
    }

    void EverbloomNavigationView::ShowSwordAccent(bool value)
    {
        SetValue(s_showSwordAccentProperty, winrt::box_value(value));
    }

    Brush EverbloomNavigationView::AccentColor()
    {
        return GetValue(s_accentColorProperty).as<Brush>();
    }

    void EverbloomNavigationView::AccentColor(Brush value)
    {
        SetValue(s_accentColorProperty, value);
    }

    double EverbloomNavigationView::IndicatorWidth()
    {
        return unbox_value<double>(GetValue(s_indicatorWidthProperty));
    }

    void EverbloomNavigationView::IndicatorWidth(double value)
    {
        SetValue(s_indicatorWidthProperty, winrt::box_value(value));
    }

    Brush EverbloomNavigationView::IndicatorColor()
    {
        return GetValue(s_indicatorColorProperty).as<Brush>();
    }

    void EverbloomNavigationView::IndicatorColor(Brush value)
    {
        SetValue(s_indicatorColorProperty, value);
    }
}