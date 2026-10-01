using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;
using Microsoft.UI.Xaml.Controls.Primitives;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;

namespace EverbloomSecurity.GUI.WinUI.Controls;

/// <summary>
/// Everbloom NavigationView - Custom NavigationView with Everbloom styling
/// Features: Crimson accent indicator, petal particles on hover, sword accent
/// </summary>
public sealed class EverbloomNavigationView : NavigationView
{
    public static readonly DependencyProperty ShowSwordAccentProperty =
        DependencyProperty.Register(
            nameof(ShowSwordAccent),
            typeof(bool),
            typeof(EverbloomNavigationView),
            new PropertyMetadata(true));

    public static readonly DependencyProperty AccentColorProperty =
        DependencyProperty.Register(
            nameof(AccentColor),
            typeof(Brush),
            typeof(EverbloomNavigationView),
            new PropertyMetadata(null));

    public static readonly DependencyProperty IndicatorWidthProperty =
        DependencyProperty.Register(
            nameof(IndicatorWidth),
            typeof(double),
            typeof(EverbloomNavigationView),
            new PropertyMetadata(3.0));

    public static readonly DependencyProperty IndicatorColorProperty =
        DependencyProperty.Register(
            nameof(IndicatorColor),
            typeof(Brush),
            typeof(EverbloomNavigationView),
            new PropertyMetadata(null));

    public bool ShowSwordAccent
    {
        get => (bool)GetValue(ShowSwordAccentProperty);
        set => SetValue(ShowSwordAccentProperty, value);
    }

    public Brush AccentColor
    {
        get => (Brush)GetValue(AccentColorProperty);
        set => SetValue(AccentColorProperty, value);
    }

    public double IndicatorWidth
    {
        get => (double)GetValue(IndicatorWidthProperty);
        set => SetValue(IndicatorWidthProperty, value);
    }

    public Brush IndicatorColor
    {
        get => (Brush)GetValue(IndicatorColorProperty);
        set => SetValue(IndicatorColorProperty, value);
    }

    private Border? _selectionIndicator;

    public EverbloomNavigationView()
    {
        DefaultStyleKey = typeof(EverbloomNavigationView);
        Loaded += OnLoaded;
    }

    private void OnLoaded(object sender, RoutedEventArgs e)
    {
        // Apply custom template if needed
        UpdateVisualState();
    }

    private void UpdateVisualState()
    {
        // Custom visual state updates
    }

    protected override void OnApplyTemplate()
    {
        base.OnApplyTemplate();

        // Find the selection indicator in the template
        _selectionIndicator = GetTemplateChild("SelectionIndicator") as Border;
        
        if (_selectionIndicator != null)
        {
            _selectionIndicator.Width = 3;
            _selectionIndicator.Background = new SolidColorBrush(Microsoft.UI.Colors.Transparent);
            _selectionIndicator.HorizontalAlignment = HorizontalAlignment.Left;
            _selectionIndicator.VerticalAlignment = VerticalAlignment.Stretch;
            _selectionIndicator.Margin = new Thickness(-3, 0, 0, 0);
            _selectionIndicator.CornerRadius = new CornerRadius(0, 4, 4, 0);
        }
    }

    protected override void OnApplyTemplate()
    {
        base.OnApplyTemplate();
        
        // Hook into selection changes
        SelectionChanged += OnSelectionChanged;
    }

    private void OnSelectionChanged(NavigationView sender, NavigationViewSelectionChangedEventArgs args)
    {
        UpdateSelectionIndicator();
    }

    private void UpdateSelectionIndicator()
    {
        if (_selectionIndicator == null) return;

        var selectedItem = SelectedItem as NavigationViewItem;
        if (selectedItem == null) return;

        // Animate indicator to selected item
        var itemContainer = ContainerFromMenuItem(selectedItem) as NavigationViewItem;
        if (itemContainer != null)
        {
            var transform = itemContainer.TransformToVisual(this);
            var itemRect = transform.TransformBounds(new Rect(0, 0, itemContainer.ActualWidth, itemContainer.ActualHeight));
            
            // Animate indicator to item position
            // This would typically use a storyboard or ConnectedAnimation
        }
    }

    protected override void OnApplyTemplate()
    {
        base.OnApplyTemplate();
    }
}