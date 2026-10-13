using System.Buffers.Binary;
using System.Net;
using System.Net.NetworkInformation;

namespace IPv6NetScanner.Core;

/// <summary>Builds raw Ethernet + IPv6 + ICMPv6 echo request frames.</summary>
public static class Icmpv6PacketBuilder
{
    public const byte NextHeaderIcmpv6 = 58;
    public const byte EchoRequest = 128;
    public const byte EchoReply = 129;

    private const int EthernetHeaderLength = 14;
    private const int Ipv6HeaderLength = 40;

    private static readonly byte[] Payload = "IPv6-NetScanner-echo-payload-32b"u8.ToArray();

    public static byte[] BuildEchoRequest(
        PhysicalAddress sourceMac, IPAddress sourceIp, ScanTarget target, ushort identifier)
    {
        var icmpLength = 8 + Payload.Length;
        var frame = new byte[EthernetHeaderLength + Ipv6HeaderLength + icmpLength];

        // Ethernet II
        target.Mac.GetAddressBytes().CopyTo(frame, 0);
        sourceMac.GetAddressBytes().CopyTo(frame, 6);
        BinaryPrimitives.WriteUInt16BigEndian(frame.AsSpan(12), 0x86DD);

        // IPv6 header
        var ip = frame.AsSpan(EthernetHeaderLength);
        ip[0] = 0x60;                                              // version 6
        BinaryPrimitives.WriteUInt16BigEndian(ip[4..], (ushort)icmpLength);
        ip[6] = NextHeaderIcmpv6;
        ip[7] = 255;                                               // hop limit 255 (link-local only)
        var src = sourceIp.GetAddressBytes();
        var dst = target.Address.GetAddressBytes();
        src.CopyTo(ip[8..]);
        dst.CopyTo(ip[24..]);

        // ICMPv6 echo request
        var icmp = ip[Ipv6HeaderLength..];
        icmp[0] = EchoRequest;
        BinaryPrimitives.WriteUInt16BigEndian(icmp[4..], identifier);
        BinaryPrimitives.WriteUInt16BigEndian(icmp[6..], target.Sequence);
        Payload.CopyTo(icmp[8..]);
        BinaryPrimitives.WriteUInt16BigEndian(icmp[2..], Checksum(src, dst, icmp));

        return frame;
    }

    /// <summary>ICMPv6 checksum incl. IPv6 pseudo header (RFC 4443 / RFC 8200). The checksum field must be zero.</summary>
    public static ushort Checksum(ReadOnlySpan<byte> source, ReadOnlySpan<byte> destination, ReadOnlySpan<byte> icmp)
    {
        uint sum = 0;
        sum = Add(sum, source);
        sum = Add(sum, destination);
        sum += (uint)icmp.Length >> 16;
        sum += (uint)icmp.Length & 0xFFFF;
        sum += NextHeaderIcmpv6;
        sum = Add(sum, icmp);
        while (sum >> 16 != 0)
            sum = (sum & 0xFFFF) + (sum >> 16);
        return (ushort)~sum;
    }

    private static uint Add(uint sum, ReadOnlySpan<byte> data)
    {
        var i = 0;
        for (; i + 1 < data.Length; i += 2)
            sum += (uint)(data[i] << 8 | data[i + 1]);
        if (i < data.Length)
            sum += (uint)(data[i] << 8);
        return sum;
    }
}
