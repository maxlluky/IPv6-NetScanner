using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using SharpPcap;

namespace IPv6NetScanner.Core;

/// <summary>A capture-capable network adapter together with its OS-level IPv6 information.</summary>
public sealed class NetworkAdapter
{
    internal NetworkAdapter(ILiveDevice device, NetworkInterface? networkInterface)
    {
        Device = device;
        Interface = networkInterface;
        LinkLocal = networkInterface?.GetIPProperties().UnicastAddresses
            .Select(a => a.Address)
            .FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetworkV6 && a.IsIPv6LinkLocal);
    }

    internal ILiveDevice Device { get; }
    internal NetworkInterface? Interface { get; }

    /// <summary>The adapter's fe80:: address, used as the scan's source address.</summary>
    public IPAddress? LinkLocal { get; }

    public PhysicalAddress? Mac => Device.MacAddress ?? Interface?.GetPhysicalAddress();

    public string Name => Interface?.Name ?? Device.Name;

    public string Description =>
        Interface is { } ni && !string.IsNullOrWhiteSpace(ni.Description) && ni.Description != ni.Name
            ? $"{ni.Name} - {ni.Description}"
            : Name;

    /// <summary>Whether a scan can be started on this adapter.</summary>
    public bool IsUsable =>
        LinkLocal is not null && Mac is { } m && m.GetAddressBytes().Length == 6
        && Interface?.OperationalStatus == OperationalStatus.Up;

    public override string ToString() => Description;

    /// <summary>Lists the adapters libpcap/Npcap can see. Throws if the capture library is missing.</summary>
    public static IReadOnlyList<NetworkAdapter> Discover()
    {
        var interfaces = NetworkInterface.GetAllNetworkInterfaces();
        var result = new List<NetworkAdapter>();
        foreach (var device in CaptureDeviceList.New())
        {
            result.Add(new NetworkAdapter(device, Match(device, interfaces)));
        }
        return result;
    }

    private static NetworkInterface? Match(ILiveDevice device, NetworkInterface[] interfaces)
    {
        // Linux/macOS: pcap name == interface name ("eth0"). Windows: "\Device\NPF_{GUID}" contains the interface id.
        foreach (var ni in interfaces)
        {
            if (string.Equals(ni.Name, device.Name, StringComparison.Ordinal) ||
                (ni.Id.Length > 0 && device.Name.Contains(ni.Id, StringComparison.OrdinalIgnoreCase)))
                return ni;
        }
        var mac = device.MacAddress;
        return mac is null ? null : interfaces.FirstOrDefault(ni => mac.Equals(ni.GetPhysicalAddress()));
    }
}
