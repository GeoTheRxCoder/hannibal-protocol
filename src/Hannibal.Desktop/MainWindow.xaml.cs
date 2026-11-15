using System.ComponentModel;
using System.IO;
using System.Text.Json;
using System.Windows;
using System.Windows.Threading;
using Hannibal.Core.Agents;

namespace Hannibal.Desktop;

/// <summary>
/// Read-only dashboard. It displays the status snapshot the Core service
/// publishes and has no channel for sending commands to any service.
/// Usage: HannibalDesktop.exe [path-to-snapshot.json]
/// </summary>
public partial class MainWindow : Window
{
    private readonly SnapshotViewModel _vm = new();
    private readonly DispatcherTimer _timer = new() { Interval = TimeSpan.FromSeconds(2) };

    public MainWindow()
    {
        InitializeComponent();
        var args = Environment.GetCommandLineArgs();
        _vm.Path = args.Length > 1 ? args[1] : System.IO.Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "Hannibal", "status", "snapshot.json");
        DataContext = _vm;
        _timer.Tick += (_, _) => _vm.Reload();
        _vm.Reload();
        _timer.Start();
    }
}

public sealed class SnapshotViewModel : INotifyPropertyChanged
{
    public event PropertyChangedEventHandler? PropertyChanged;
    public string Path { get; set; } = "";
    public StatusSnapshot? Snapshot { get; private set; }
    public bool HasSnapshot => Snapshot is not null;
    public bool NoSnapshot => Snapshot is null;
    public bool IsStale { get; private set; }
    public string Environment => Snapshot?.Environment ?? "NO STATUS AVAILABLE";
    public string StatusLine { get; private set; } = "";

    public void Reload()
    {
        try
        {
            if (!File.Exists(Path))
            {
                Snapshot = null;
                StatusLine = "The Core service has not published a status snapshot at " + Path + ". Nothing is being shown as protected.";
            }
            else
            {
                Snapshot = JsonSerializer.Deserialize<StatusSnapshot>(File.ReadAllText(Path), StatusSnapshot.Json);
                long age = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() - (Snapshot?.GeneratedMs ?? 0);
                IsStale = age > 60_000;
                StatusLine = IsStale
                    ? "This status is out of date. The Core service may be stopped, or this is a saved drill snapshot."
                    : "Status is current.";
            }
        }
        catch (Exception e) when (e is IOException or JsonException or UnauthorizedAccessException)
        {
            StatusLine = "The status snapshot could not be read: " + e.Message;
        }
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(string.Empty)); // refresh all bindings
    }
}
