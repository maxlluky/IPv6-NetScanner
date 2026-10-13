using System.Net;
using System.Net.NetworkInformation;
using IPv6NetScanner.Core;

namespace IPv6NetScanner.Tests;

public class Icmpv6PacketBuilderTests
{
    private static byte[] Build() => Icmpv6PacketBuilder.BuildEchoRequest(
        PhysicalAddress.Parse("00-11-22-33-44-55"), IPAddress.Parse("fe80::211:22ff:fe33:4455"),
        ScanTarget.AllNodes, 0x1234);

    [Fact]
    public void FrameHasExpectedLayout()
    {
        var f = Build();
        Assert.Equal(14 + 40 + 8 + 32, f.Length);
        Assert.Equal(new byte[] { 0x33, 0x33, 0, 0, 0, 1 }, f[..6]);
        Assert.Equal(new byte[] { 0x86, 0xDD }, f[12..14]);
        Assert.Equal(0x60, f[14]);
        Assert.Equal(58, f[14 + 6]);                   // next header = ICMPv6
        Assert.Equal(255, f[14 + 7]);                  // hop limit
        Assert.Equal(128, f[54]);                      // echo request
        Assert.Equal(new byte[] { 0x12, 0x34, 0, 1 }, f[58..62]);
    }

    [Fact]
    public void ChecksumVerifiesToZero()
    {
        // Re-computing the checksum over a message that contains its checksum must yield 0.
        var f = Build();
        var src = f[22..38];
        var dst = f[38..54];
        Assert.Equal(0, Icmpv6PacketBuilder.Checksum(src, dst, f[54..]));
    }

    [Fact]
    public void ChecksumMatchesRfcExample()
    {
        // Hand-computed: ::1 -> ::1, echo request id 0 seq 0, no payload.
        var ip = IPAddress.IPv6Loopback.GetAddressBytes();
        byte[] icmp = [128, 0, 0, 0, 0, 0, 0, 0];
        // sum = 1 + 1 + 8 + 58 + 0x8000 = 0x8044 -> ~ = 0x7FBB
        Assert.Equal(0x7FBB, Icmpv6PacketBuilder.Checksum(ip, ip, icmp));
    }
}
