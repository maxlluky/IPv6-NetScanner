using System.Collections.ObjectModel;
using Avalonia.Controls;
using Avalonia.Input;
using Avalonia.Input.Platform;
using Avalonia.Interactivity;
using Avalonia.Threading;
using IPv6NetScanner.Core;

namespace IPv6NetScanner.Gui;

public partial class MainWindow : Window
{
    private readonly Ipv6Scanner _scanner = new();
    private IReadOnlyList<NetworkAdapter> _adapters = [];
    private CancellationTokenSource? _cts;

    public ObservableCollection<HostRow> Hosts { get; } = [];

    public MainWindow()
    {
        InitializeComponent();
        DataContext = this;
        _scanner.HostDiscovered += host => Dispatcher.UIThread.Post(() => Upsert(host));
        _scanner.Progress += p => Dispatcher.UIThread.Post(() => ScanProgress.Value = p);
        Opened += (_, _) => LoadAdapters();
    }

    private void LoadAdapters()
    {
        try
        {
            _adapters = NetworkAdapter.Discover().Where(a => a.IsUsable).ToList();
        }
        catch (Exception ex) when (ex is DllNotFoundException or TypeInitializationException)
        {
            _adapters = [];
            SetStatus(OperatingSystem.IsWindows()
                ? "Npcap not found. Please install Npcap (https://npcap.com)."
                : "libpcap not found. Please install it (e.g. 'sudo apt install libpcap0.8').");
            return;
        }

        AdapterBox.ItemsSource = _adapters;
        AdapterBox.SelectedIndex = _adapters.Count > 0 ? 0 : -1;
        SetStatus(_adapters.Count == 0
            ? "No usable adapter found (needs to be up and have an IPv6 link-local address)."
            : "Ready.");
    }

    private void Upsert(Host host)
    {
        var row = HostRow.From(host);
        var existing = Hosts.Select((r, i) => (r, i)).FirstOrDefault(t => t.r.Address == row.Address);
        if (existing.r is null)
            Hosts.Add(row);
        else
            Hosts[existing.i] = row;
        SetStatus($"{DateTime.Now:T}: {Hosts.Count} host(s) found.");
    }

    private async void OnScanClick(object? sender, RoutedEventArgs e)
    {
        if (_cts is not null)
        {
            _cts.Cancel();
            return;
        }
        if (AdapterBox.SelectedItem is not NetworkAdapter adapter)
            return;

        Hosts.Clear();
        _scanner.Clear();
        ScanProgress.Value = 0;
        ScanButton.Content = "Stop Scan";
        AdapterBox.IsEnabled = RefreshButton.IsEnabled = false;
        SetStatus($"{DateTime.Now:T}: Scan started...");

        _cts = new CancellationTokenSource();
        try
        {
            await Task.Run(() => _scanner.ScanAsync(adapter, ct: _cts.Token));
            SetStatus($"{DateTime.Now:T}: Scan finished - {Hosts.Count} host(s) found.");
        }
        catch (OperationCanceledException)
        {
            SetStatus($"{DateTime.Now:T}: Scan stopped - {Hosts.Count} host(s) found.");
        }
        catch (Exception ex)
        {
            SetStatus($"Scan failed: {ex.Message}" + (OperatingSystem.IsLinux()
                ? " (on Linux the app needs root or CAP_NET_RAW)"
                : ""));
        }
        finally
        {
            _cts.Dispose();
            _cts = null;
            ScanButton.Content = "Start Scan";
            AdapterBox.IsEnabled = RefreshButton.IsEnabled = true;
        }
    }

    private void OnRefreshClick(object? sender, RoutedEventArgs e) => LoadAdapters();

    private async void OnGridDoubleTapped(object? sender, TappedEventArgs e)
    {
        if (HostGrid.SelectedItem is not HostRow row || Clipboard is null)
            return;
        await Clipboard.SetTextAsync(row.Address);
        SetStatus($"Copied {row.Address} to clipboard.");
    }

    private void SetStatus(string text) => StatusText.Text = text;
}
