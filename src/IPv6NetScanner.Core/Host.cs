using System.Net;
using System.Net.NetworkInformation;

namespace IPv6NetScanner.Core;

/// <summary>A device that answered the multicast ping.</summary>
public sealed class Host
{
    public Host(IPAddress address, PhysicalAddress mac, string? vendor)
    {
        Address = address;
        Mac = mac;
        Vendor = vendor;
    }

    public IPAddress Address { get; }
    public PhysicalAddress Mac { get; }
    public string? Vendor { get; }

    /// <summary>True if the host also answered the all-routers (ff02::2) ping.</summary>
    public bool IsRouter { get; internal set; }

    public DateTimeOffset FirstSeen { get; } = DateTimeOffset.Now;

    public string Role => IsRouter ? "Router" : "Node";

    /// <summary>MAC address as aa:bb:cc:dd:ee:ff.</summary>
    public string MacText => string.Join(':', Mac.GetAddressBytes().Select(b => b.ToString("x2")));
}
