using IPv6NetScanner.Core;

const string usage = """
    Usage: ipv6-netscanner [--list] [-i <adapter>] [--rounds <n>]

      --list, -l          list network adapters and exit
      -i, --interface     adapter name or index (as shown by --list)
      --rounds <n>        echo requests per multicast group (default 3)

    Needs libpcap (Linux/macOS) or Npcap (Windows). On Linux run as root or grant
    the binary capabilities:  sudo setcap cap_net_raw,cap_net_admin=eip ./ipv6-netscanner
    """;

IReadOnlyList<NetworkAdapter> adapters;
try
{
    adapters = NetworkAdapter.Discover();
}
catch (Exception ex) when (ex is DllNotFoundException or TypeInitializationException or BadImageFormatException)
{
    Console.Error.WriteLine("Capture library not found. Install libpcap (Linux/macOS) or Npcap (Windows).");
    return 2;
}

string? wanted = null;
var list = false;
var rounds = 3;
for (var i = 0; i < args.Length; i++)
{
    switch (args[i])
    {
        case "-l" or "--list": list = true; break;
        case "-i" or "--interface" when i + 1 < args.Length: wanted = args[++i]; break;
        case "--rounds" when i + 1 < args.Length && int.TryParse(args[i + 1], out var r) && r > 0: rounds = r; i++; break;
        default: Console.Error.WriteLine(usage); return 1;
    }
}

if (list || wanted is null && adapters.Count(a => a.IsUsable) != 1)
{
    for (var i = 0; i < adapters.Count; i++)
    {
        var a = adapters[i];
        Console.WriteLine($"{i,2}  {(a.IsUsable ? "ok  " : "n/a ")} {a.Description}  {a.LinkLocal}");
    }
    if (!list)
        Console.Error.WriteLine("\nSelect an adapter with -i <name|index>.");
    return list ? 0 : 1;
}

var adapter = wanted is null
    ? adapters.First(a => a.IsUsable)
    : int.TryParse(wanted, out var idx) && idx >= 0 && idx < adapters.Count
        ? adapters[idx]
        : adapters.FirstOrDefault(a => a.Name.Equals(wanted, StringComparison.OrdinalIgnoreCase));

if (adapter is null || !adapter.IsUsable)
{
    Console.Error.WriteLine($"Adapter '{wanted}' not found or has no IPv6 link-local address.");
    return 1;
}

using var cts = new CancellationTokenSource();
Console.CancelKeyPress += (_, e) => { e.Cancel = true; cts.Cancel(); };

var scanner = new Ipv6Scanner();
var seen = new HashSet<string>();
scanner.HostDiscovered += h =>
{
    lock (seen)
    {
        if (seen.Add(h.Address.ToString()))
            Console.WriteLine($"{h.Address,-40} {h.MacText,-17} {h.Role,-6} {h.Vendor ?? "-"}");
    }
};

Console.WriteLine($"Scanning on {adapter.Description} from {adapter.LinkLocal} ...");
Console.WriteLine($"{"IPv6",-40} {"MAC",-17} {"Role",-6} Vendor");
try
{
    await scanner.ScanAsync(adapter, new ScanOptions { Rounds = rounds }, cts.Token);
}
catch (OperationCanceledException) { Console.WriteLine("Cancelled."); }
catch (Exception ex)
{
    Console.Error.WriteLine($"Scan failed: {ex.Message}");
    return 1;
}

Console.WriteLine($"\n{scanner.Hosts.Count} host(s) found.");
foreach (var r in scanner.Hosts.Where(h => h.IsRouter))
    Console.WriteLine($"  router: {r.Address}");
return 0;
