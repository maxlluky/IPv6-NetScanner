using System.Collections.Concurrent;
using System.Net;
using System.Net.NetworkInformation;
using PacketDotNet;
using SharpPcap;

namespace IPv6NetScanner.Core;

/// <summary>
/// Discovers IPv6 hosts on the local link by pinging the link-local multicast groups
/// ff02::1 (all nodes) and ff02::2 (all routers) and collecting the echo replies.
/// </summary>
public sealed class Ipv6Scanner
{
    private readonly VendorDatabase _vendors;
    private readonly ConcurrentDictionary<IPAddress, Host> _hosts = new();

    public Ipv6Scanner(VendorDatabase? vendors = null) => _vendors = vendors ?? VendorDatabase.Default;

    /// <summary>Raised on a thread-pool thread when a new host is found or an existing one is classified as router.</summary>
    public event Action<Host>? HostDiscovered;

    /// <summary>Raised with a value in 0..1 as the scan advances.</summary>
    public event Action<double>? Progress;

    public IReadOnlyCollection<Host> Hosts => _hosts.Values.ToArray();

    public async Task ScanAsync(NetworkAdapter adapter, ScanOptions? options = null, CancellationToken ct = default)
    {
        options ??= new ScanOptions();
        if (!adapter.IsUsable)
            throw new InvalidOperationException(
                $"Adapter '{adapter.Name}' is not usable: it needs to be up and have an IPv6 link-local address.");

        var device = adapter.Device;
        var sourceMac = adapter.Mac!;
        var sourceIp = adapter.LinkLocal!;
        var identifier = (ushort)Random.Shared.Next(1, ushort.MaxValue);

        void OnPacket(object sender, PacketCapture e) => HandlePacket(e, identifier, sourceMac);

        device.Open(new DeviceConfiguration { Mode = DeviceModes.None, ReadTimeout = 100 });
        try
        {
            device.Filter = "icmp6";
            device.OnPacketArrival += OnPacket;
            device.StartCapture();

            var steps = options.Rounds * options.Targets.Count;
            var done = 0;
            for (var round = 0; round < options.Rounds; round++)
            {
                foreach (var target in options.Targets)
                {
                    ct.ThrowIfCancellationRequested();
                    device.SendPacket(Icmpv6PacketBuilder.BuildEchoRequest(sourceMac, sourceIp, target, identifier));
                    Progress?.Invoke(0.9 * ++done / steps);
                }
                await Task.Delay(options.Interval, ct).ConfigureAwait(false);
            }

            await Task.Delay(options.Linger, ct).ConfigureAwait(false);
            Progress?.Invoke(1);
        }
        finally
        {
            device.OnPacketArrival -= OnPacket;
            try { device.StopCapture(); } catch (DeviceNotReadyException) { }
            device.Close();
        }
    }

    public void Clear() => _hosts.Clear();

    private void HandlePacket(PacketCapture capture, ushort identifier, PhysicalAddress ownMac)
    {
        try
        {
            var raw = capture.GetPacket();
            var packet = Packet.ParsePacket(raw.LinkLayerType, raw.Data);
            var ethernet = packet.Extract<EthernetPacket>();
            var ip = packet.Extract<IPv6Packet>();
            var icmp = packet.Extract<IcmpV6Packet>();
            if (ethernet is null || ip is null || icmp is null || icmp.Type != IcmpV6Type.EchoReply)
                return;
            if (ethernet.SourceHardwareAddress.Equals(ownMac))
                return;

            // Echo reply layout: type, code, checksum (4 bytes), identifier (2), sequence (2).
            var header = icmp.HeaderData;
            if (header.Length < 8)
                return;
            var replyId = (ushort)(header[4] << 8 | header[5]);
            var sequence = (ushort)(header[6] << 8 | header[7]);
            if (replyId != identifier)
                return;

            var isRouterReply = sequence == ScanTarget.AllRouters.Sequence;
            var host = _hosts.GetOrAdd(ip.SourceAddress, addr =>
            {
                var h = new Host(addr, ethernet.SourceHardwareAddress, _vendors.Lookup(ethernet.SourceHardwareAddress));
                h.IsRouter = isRouterReply;
                HostDiscovered?.Invoke(h);
                return h;
            });

            if (isRouterReply && !host.IsRouter)
            {
                host.IsRouter = true;
                HostDiscovered?.Invoke(host);
            }
        }
        catch (Exception)
        {
            // Malformed or unrelated frame - ignore.
        }
    }
}
