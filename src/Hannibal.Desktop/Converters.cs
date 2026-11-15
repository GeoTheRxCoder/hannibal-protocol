using System.Collections;
using System.Globalization;
using System.Windows;
using System.Windows.Data;
using System.Windows.Media;

namespace Hannibal.Desktop;

/// <summary>Maps the backend's state words onto the brand guide's four status levels.</summary>
internal static class StatusLevel
{
    public static string Of(object? value) => (value as string ?? "").ToLowerInvariant() switch
    {
        "healthy" or "watched" or "resolved" or "rolled_back" => "Healthy",
        "degraded" or "review" or "unwatched" or "investigating" or "open" or "failed" or "expired" => "Review",
        "high" or "offline" or "tripped" or "contained" => "High",
        _ => "Info"
    };
}

public sealed class StatusBrushConverter : IValueConverter
{
    public object Convert(object? value, Type t, object? p, CultureInfo c) =>
        Application.Current.TryFindResource("Status" + StatusLevel.Of(value)) as Brush ?? Brushes.Gray;
    public object ConvertBack(object? v, Type t, object? p, CultureInfo c) => throw new NotSupportedException();
}

/// <summary>A distinct shape per level, so status never depends on color alone.</summary>
public sealed class StatusGlyphConverter : IValueConverter
{
    public object Convert(object? value, Type t, object? p, CultureInfo c) => StatusLevel.Of(value) switch
    {
        "Healthy" => "●", "Review" => "▲", "High" => "■", _ => "◆"
    };
    public object ConvertBack(object? v, Type t, object? p, CultureInfo c) => throw new NotSupportedException();
}

/// <summary>"Review / unwatched": the level, then the backend's own word.</summary>
public sealed class StatusLabelConverter : IValueConverter
{
    public object Convert(object? value, Type t, object? p, CultureInfo c)
    {
        string level = StatusLevel.Of(value), raw = (value as string ?? "").Replace('_', ' ');
        return level.Equals(raw, StringComparison.OrdinalIgnoreCase) || raw.Length == 0 ? level : $"{level} / {raw.ToLowerInvariant()}";
    }
    public object ConvertBack(object? v, Type t, object? p, CultureInfo c) => throw new NotSupportedException();
}

public sealed class TimeConverter : IValueConverter
{
    public object Convert(object? value, Type t, object? p, CultureInfo c) => value is long ms && ms > 0
        ? DateTimeOffset.FromUnixTimeMilliseconds(ms).ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture)
        : "—";
    public object ConvertBack(object? v, Type t, object? p, CultureInfo c) => throw new NotSupportedException();
}

public sealed class JoinConverter : IValueConverter
{
    public object Convert(object? value, Type t, object? p, CultureInfo c) =>
        value is IEnumerable e ? string.Join("  ", e.Cast<object>()) : "";
    public object ConvertBack(object? v, Type t, object? p, CultureInfo c) => throw new NotSupportedException();
}

public sealed class EmptyToCollapsedConverter : IValueConverter
{
    public object Convert(object? value, Type t, object? p, CultureInfo c) => value switch
    {
        null => Visibility.Collapsed,
        string s when s.Length == 0 => Visibility.Collapsed,
        ICollection col when col.Count == 0 => Visibility.Collapsed,
        _ => Visibility.Visible
    };
    public object ConvertBack(object? v, Type t, object? p, CultureInfo c) => throw new NotSupportedException();
}
