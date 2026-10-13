using System.Net;
using System.Net.NetworkInformation;

namespace IPv6NetScanner.Core;

/// <summary>A link-local multicast group that is pinged during a scan.</summary>
public sealed record ScanTarget(string Name, IPAddress Address, PhysicalAddress Mac, ushort Sequence)
{
    /// <summary>ff02::1 - every IPv6 node on the link answers.</summary>
    public static readonly ScanTarget AllNodes = new(
        "All nodes", IPAddress.Parse("ff02::1"), new PhysicalAddress([0x33, 0x33, 0, 0, 0, 0x01]), 1);

    /// <summary>ff02::2 - only routers answer.</summary>
    public static readonly ScanTarget AllRouters = new(
        "All routers", IPAddress.Parse("ff02::2"), new PhysicalAddress([0x33, 0x33, 0, 0, 0, 0x02]), 2);

    public static IReadOnlyList<ScanTarget> Default { get; } = [AllNodes, AllRouters];
}
