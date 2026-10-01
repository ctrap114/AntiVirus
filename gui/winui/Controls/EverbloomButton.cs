using Microsoft.UI.Composition;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Controls.Primitives;
using Microsoft.UI.Xaml.Media;
using Microsoft.UI.Xaml.Shapes;
using System;
using System.Collections.Generic;
using System.Numerics;
using Windows.Foundation;
using Windows.UI;

namespace EverbloomSecurity.GUI.WinUI.Controls;

/// <summary>
/// Everbloom Button - Brand-styled button with Crimson accent
/// Supports: Primary, Secondary, Subtle, Ghost, Destructive variants
/// Win10/Win11 adaptive corner radius via Material Adapter
</summary>
public sealed class EverbloomButton : Button
{
    public enum ButtonVariant
    {
        Primary,       // Crimson fill, white text
        Secondary,     // Subtle crimson border, crimson text
        Subtle,        // No border, crimson text, hover background
        Ghost,         // Transparent, crimson text, hover background
        Destructive    // Red fill, white text (for dangerous actions)
    }

    public static readonly DependencyProperty VariantProperty =
        DependencyProperty.Register(
            nameof(Variant),
            typeof(ButtonVariant),
            typeof(EverbloomButton),
            new PropertyMetadata(ButtonVariant.Primary, OnVariantChanged));

    public static readonly DependencyProperty CornerRadiusProperty =
        DependencyProperty.Register(
            nameof(CornerRadius),
            typeof(CornerRadius),
            typeof(EverbloomButton),
            new PropertyMetadata(new CornerRadius(6)));

    public static readonly DependencyProperty SlashAngleProperty =
        DependencyProperty.Register(
            nameof(SlashAngle),
            typeof(double),
            typeof(EverbloomButton),
            new PropertyMetadata(15.0));

    public static readonly DependencyProperty ShowSwordAccentProperty =
        DependencyProperty.Register(
            nameof(ShowSwordAccent),
            typeof(bool),
            typeof(EverbloomButton),
            new PropertyMetadata(false));

    public ButtonVariant Variant
    {
        get => (ButtonVariant)GetValue(VariantProperty);
        set => SetValue(VariantProperty, value);
    }

    public CornerRadius CornerRadius
    {
        get => (CornerRadius)GetValue(CornerRadiusProperty);
        set => SetValue(CornerRadiusProperty, value);
    }

    public double SlashAngle
    {
        get => (double)GetValue(SlashAngleProperty);
        set => SetValue(SlashAngleProperty, value);
    }

    public bool ShowSwordAccent
    {
        get => (bool)GetValue(ShowSwordAccentProperty);
        set => SetValue(ShowSwordAccentProperty, value);
    }

    private Border? _slashBorder;

    public EverbloomButton()
    {
        DefaultStyleKey = typeof(EverbloomButton);
        Loaded += OnLoaded;
        Unloaded += OnUnloaded;
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

    private void OnUnloaded(object sender, RoutedEventArgs e)
    {
    }

    private void OnPointerEntered(object sender, Microsoft.UI.Xaml.Input.PointerRoutedEventArgs e)
    {
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

    private static void OnVariantChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
    {
        if (d is EverbloomButton btn)
        {
            btn.UpdateVisualState();
        }
    }

    protected override void OnApplyTemplate()
    {
        base.OnApplyTemplate();
        
        // Create sword accent slash if enabled
        if (ShowSwordAccent)
        {
            _slashBorder = new Border
            {
                Width = 2,
                Background = new SolidColorBrush(Microsoft.UI.Colors.Transparent),
                HorizontalAlignment = HorizontalAlignment.Right,
                VerticalAlignment = VerticalAlignment.Stretch,
                Margin = new Thickness(0, 0, -1, 0),
                RenderTransformOrigin = new Point(1, 0.5),
                RenderTransform = new SkewTransform { AngleX = -15 }
            };
            
            if (GetTemplateChild("ContentPresenter") is ContentPresenter presenter)
            {
                if (presenter.ContentTemplateRoot is Grid grid)
                {
                    grid.Children.Add(_slashBorder);
                }
            }
        }
        
        UpdateVisualState();
    }

    private void UpdateVisualState()
    {
        VisualStateManager.GoToState(this, Variant.ToString(), false);
    }
}