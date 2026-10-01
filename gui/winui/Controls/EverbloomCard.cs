using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;
using Microsoft.UI.Xaml.Controls.Primitives;
using System;

namespace EverbloomSecurity.GUI.WinUI.Controls;

/// <summary>
/// Everbloom Card - Adaptive card with subtle border, hover states, and sword accent
/// Win10: 8px radius, 1px border | Win11: 12px radius, softer shadow
/// </summary>
public sealed class EverbloomCard : ContentControl
{
    public static readonly DependencyProperty CornerRadiusProperty =
        DependencyProperty.Register(
            nameof(CornerRadius),
            typeof(CornerRadius),
            typeof(EverbloomCard),
            new PropertyMetadata(new CornerRadius(8)));

    public static readonly DependencyProperty BorderBrushProperty =
        DependencyProperty.Register(
            nameof(BorderBrush),
            typeof(Brush),
            typeof(EverbloomCard),
            new PropertyMetadata(null));

    public static readonly DependencyProperty BorderThicknessProperty =
        DependencyProperty.Register(
            nameof(BorderThickness),
            typeof(Thickness),
            typeof(EverbloomCard),
            new PropertyMetadata(new Thickness(1)));

    public static readonly DependencyProperty BackgroundProperty =
        DependencyProperty.Register(
            nameof(Background),
            typeof(Brush),
            typeof(EverbloomCard),
            new PropertyMetadata(null));

    public static readonly DependencyProperty HoverBackgroundProperty =
        DependencyProperty.Register(
            nameof(HoverBackground),
            typeof(Brush),
            typeof(EverbloomCard),
            new PropertyMetadata(null));

    public static readonly DependencyProperty ShowSwordAccentProperty =
        DependencyProperty.Register(
            nameof(ShowSwordAccent),
            typeof(bool),
            typeof(EverbloomCard),
            new PropertyMetadata(false));

    public static readonly DependencyProperty IsInteractiveProperty =
        DependencyProperty.Register(
            nameof(IsInteractive),
            typeof(bool),
            typeof(EverbloomCard),
            new PropertyMetadata(false, OnInteractiveChanged));

    public CornerRadius CornerRadius
    {
        get => (CornerRadius)GetValue(CornerRadiusProperty);
        set => SetValue(CornerRadiusProperty, value);
    }

    public Brush BorderBrush
    {
        get => (Brush)GetValue(BorderBrushProperty);
        set => SetValue(BorderBrushProperty, value);
    }

    public Thickness BorderThickness
    {
        get => (Thickness)GetValue(BorderThicknessProperty);
        set => SetValue(BorderThicknessProperty, value);
    }

    public new Brush Background
    {
        get => (Brush)GetValue(BackgroundProperty);
        set => SetValue(BackgroundProperty, value);
    }

    public Brush HoverBackground
    {
        get => (Brush)GetValue(HoverBackgroundProperty);
        set => SetValue(HoverBackgroundProperty, value);
    }

    public bool ShowSwordAccent
    {
        get => (bool)GetValue(ShowSwordAccentProperty);
        set => SetValue(ShowSwordAccentProperty, value);
    }

    public bool IsInteractive
    {
        get => (bool)GetValue(IsInteractiveProperty);
        set => SetValue(IsInteractiveProperty, value);
    }

    private Border? _swordAccent;

    public EverbloomCard()
    {
        DefaultStyleKey = typeof(EverbloomCard);
        Loaded += OnLoaded;
        PointerEntered += OnPointerEntered;
        PointerExited += OnPointerExited;
        PointerPressed += OnPointerPressed;
        PointerReleased += OnPointerReleased;
        PointerCanceled += OnPointerCanceled;
    }

    private void OnLoaded(object sender, RoutedEventArgs e)
    {
        UpdateVisualState();
    }

    private void OnPointerEntered(object sender, Microsoft.UI.Xaml.Input.PointerRoutedEventArgs e)
    {
        if (IsInteractive)
            VisualStateManager.GoToState(this, "PointerOver", true);
    }

    private void OnPointerExited(object sender, Microsoft.UI.Xaml.Input.PointerRoutedEventArgs e)
    {
        VisualStateManager.GoToState(this, "Normal", true);
    }

    private void OnPointerPressed(object sender, Microsoft.UI.Xaml.Input.PointerRoutedEventArgs e)
    {
        VisualStateManager.GoToState(this, "Pressed", true);
    }

    private void OnPointerReleased(object sender, Microsoft.UI.Xaml.Input.PointerRoutedEventArgs e)
    {
        VisualStateManager.GoToState(this, "PointerOver", true);
    }

    private void OnPointerCanceled(object sender, Microsoft.UI.Xaml.Input.PointerRoutedEventArgs e)
    {
        VisualStateManager.GoToState(this, "Normal", true);
    }

    private void UpdateVisualState()
    {
        if (IsInteractive)
            VisualStateManager.GoToState(this, "Normal", false);
    }
}