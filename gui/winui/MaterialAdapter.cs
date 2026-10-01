using Microsoft.UI.Composition;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Media;
using System;
using System.Runtime.InteropServices;

namespace EverbloomSecurity.GUI.WinUI;

/// <summary>
/// Material Adapter - Runtime detection & application of system materials
/// Supports: Mica (Win11), Desktop Acrylic (Win10 1809+), Solid fallback
/// </summary>
public sealed class MaterialAdapter : DependencyObject
{
    private static MaterialAdapter? _current;
    private CompositionController? _controller;
    private bool _initialized;

    public static MaterialAdapter Current
    {
        get
        {
            if (_current == null)
            {
                _current = new MaterialAdapter();
                _current.Initialize();
            }
            return _current;
        }
    }

    public MaterialAdapter()
    {
    }

    /// <summary>
    /// Initialize material detection and apply to current window
    /// </summary>
    public void Initialize()
    {
        if (_initialized) return;
        
        if (Window.Current is not null)
        {
            TryApplyMaterial();
            _initialized = true;
        }
        else
        {
            Window.Current.Activated += OnWindowActivated;
        }
    }

    private void OnWindowActivated(object sender, WindowActivatedEventArgs args)
    {
        if (args.WindowActivationState != WindowActivationState.Deactivated)
        {
            Window.Current.Activated -= OnWindowActivated;
            TryApplyMaterial();
            _initialized = true;
        }
    }

    private void TryApplyMaterial()
    {
        try
        {
            var window = Window.Current;
            if (window?.Content is not FrameworkElement root) return;

            // Detect OS version & API support
            var version = Environment.OSVersion.Version;
            bool isWin11 = version.Major >= 10 && version.Build >= 22000;
            bool isWin10_1809Plus = version.Major >= 10 && version.Build >= 17763;

            // Try Mica first (Win11+)
            if (isWin11 && TrySetMica())
            {
                System.Diagnostics.Debug.WriteLine("[MaterialAdapter] Applied Mica");
                return;
            }

            // Fallback: Desktop Acrylic (Win10 1809+)
            if (isWin10_1809Plus && TrySetDesktopAcrylic())
            {
                System.Diagnostics.Debug.WriteLine("[MaterialAdapter] Applied Desktop Acrylic");
                return;
            }

            // Fallback: Solid background
            ApplySolidFallback();
            System.Diagnostics.Debug.WriteLine("[MaterialAdapter] Applied Solid fallback");
        }
        catch (Exception ex)
        {
            System.Diagnostics.Debug.WriteLine($"[MaterialAdapter] Error: {ex.Message}");
            ApplySolidFallback();
        }
    }

    private bool TrySetMica()
    {
        try
        {
            var window = Window.Current;
            if (window is null) return false;

            // Try Mica (Win11+)
            var micaController = MicaController.CreateForDispatcherQueue(
                DispatcherQueue.GetForCurrentThread());
            micaController.Kind = MicaKind.Base; // Base for light, BaseAlt for dark
            micaController.IsInputActive = true;
            micaController.SetTarget(window);
            
            _controller = micaController;
            return true;
        }
        catch
        {
            return false;
        }
    }

    private bool TrySetDesktopAcrylic()
    {
        try
        {
            var window = Window.Current;
            if (window is null) return false;

            // Use DesktopAcrylicController (Win10 1809+)
            var acrylicController = DesktopAcrylicController.CreateForDispatcherQueue(
                DispatcherQueue.GetForCurrentThread());
            
            acrylicController.TintColor = (Color)App.Current.Resources["AcrylicTintWin10"];
            acrylicController.TintOpacity = 0.85;
            acrylicController.LuminosityOpacity = 0.45;
            acrylicController.FallbackColor = (Color)Application.Current.Resources["ColorBackground"];
            
            acrylicController.IsInputActive = true;
            acrylicController.SetTarget(Window.Current);
            
            _controller = acrylicController;
            return true;
        }
        catch
        {
            return false;
        }
    }

    private void ApplySolidFallback()
    {
        try
        {
            if (Window.Current?.Content is FrameworkElement root)
            {
                var fallbackBrush = (SolidColorBrush)Application.Current.Resources["FallbackBackground"];
                root.Background = fallbackBrush;
            }
        }
        catch { }
    }

    /// <summary>
    /// Switch material at runtime (e.g., user theme change)
    /// </summary>
    public void SwitchMaterial(MaterialKind kind)
    {
        _controller?.Dispose();
        _controller = null;

        switch (kind)
        {
            case MaterialKind.Mica:
                TrySetMica();
                break;
            case MaterialKind.DesktopAcrylic:
                TrySetDesktopAcrylic();
                break;
            default:
                ApplySolidFallback();
                break;
        }
    }

    public enum MaterialKind
    {
        Auto,
        Mica,
        DesktopAcrylic,
        Solid
    }
}

/// <summary>
/// Extension for easy access from XAML
/// </summary>
public static class MaterialAdapterExtensions
{
    public static void ApplyMaterial(this Window window, MaterialAdapter.MaterialKind kind = MaterialAdapter.MaterialKind.Auto)
    {
        MaterialAdapter.Current.SwitchMaterial(kind);
    }
}

/// <summary>
/// Attached property for easy XAML usage
/// </summary>
public class Material
{
    public static MaterialKind GetMaterialKind(DependencyObject obj)
        => (MaterialAdapter.MaterialKind)obj.GetValue(MaterialKindProperty);

    public static void SetMaterialKind(DependencyObject obj, MaterialAdapter.MaterialKind value)
        => obj.SetValue(MaterialKindProperty, value);

    public static readonly DependencyProperty MaterialKindProperty =
        DependencyProperty.RegisterAttached(
            "MaterialKind",
            typeof(MaterialAdapter.MaterialKind),
            typeof(Material),
            new PropertyMetadata(MaterialAdapter.MaterialKind.Auto, OnMaterialKindChanged));

    private static void OnMaterialKindChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
    {
        if (d is FrameworkElement fe && e.NewValue is MaterialAdapter.MaterialKind kind)
        {
            if (Window.Current != null)
            {
                MaterialAdapter.Current.SwitchMaterial(kind);
            }
            else
            {
                // Defer until window is available
                Window.Current.Activated += (s, e) => 
                {
                    if (e.WindowActivationState != WindowActivationState.Deactivated)
                    {
                        MaterialAdapter.Current.SwitchMaterial(kind);
                    }
                };
            }
        }
    }
}