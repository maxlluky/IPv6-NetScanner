using System.Net.NetworkInformation;
using System.Xml;

namespace IPv6NetScanner.Core;

/// <summary>MAC prefix (OUI) to manufacturer lookup, backed by the embedded Cisco/maclookup XML database.</summary>
public sealed class VendorDatabase
{
    private static readonly Lazy<VendorDatabase> Embedded = new(LoadEmbedded);
    private readonly Dictionary<string, string> _vendors;

    private VendorDatabase(Dictionary<string, string> vendors) => _vendors = vendors;

    public static VendorDatabase Default => Embedded.Value;

    public int Count => _vendors.Count;

    public static VendorDatabase Load(Stream xml)
    {
        var map = new Dictionary<string, string>(StringComparer.Ordinal);
        using var reader = XmlReader.Create(xml, new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit });
        while (reader.Read())
        {
            if (reader.NodeType != XmlNodeType.Element || reader.LocalName != "VendorMapping")
                continue;
            var prefix = reader.GetAttribute("mac_prefix");
            var name = reader.GetAttribute("vendor_name");
            if (prefix is null || name is null)
                continue;
            map[Normalize(prefix)] = name;
        }
        return new VendorDatabase(map);
    }

    /// <summary>Returns the vendor for a MAC address, or null when unknown.</summary>
    public string? Lookup(PhysicalAddress mac)
    {
        var bytes = mac.GetAddressBytes();
        if (bytes.Length < 3)
            return null;
        // Bit 1 of the first octet marks a locally administered (e.g. randomized) address - no vendor.
        if ((bytes[0] & 0x02) != 0)
            return null;
        var key = Convert.ToHexString(bytes.AsSpan(0, 3));
        return _vendors.GetValueOrDefault(key);
    }

    private static string Normalize(string prefix) =>
        new(prefix.Where(Uri.IsHexDigit).Select(char.ToUpperInvariant).Take(6).ToArray());

    private static VendorDatabase LoadEmbedded()
    {
        using var stream = typeof(VendorDatabase).Assembly.GetManifestResourceStream("vendorMacs.xml")
            ?? throw new InvalidOperationException("Embedded vendor database not found.");
        return Load(stream);
    }
}
