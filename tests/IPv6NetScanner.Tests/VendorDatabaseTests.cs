using System.Net.NetworkInformation;
using System.Text;
using IPv6NetScanner.Core;

namespace IPv6NetScanner.Tests;

public class VendorDatabaseTests
{
    private static VendorDatabase Small() => VendorDatabase.Load(new MemoryStream(Encoding.UTF8.GetBytes(
        """<M xmlns="x"><VendorMapping mac_prefix="00:00:0C" vendor_name="Cisco"></VendorMapping></M>""")));

    [Fact]
    public void FindsKnownPrefix() =>
        Assert.Equal("Cisco", Small().Lookup(PhysicalAddress.Parse("00-00-0C-12-34-56")));

    [Fact]
    public void UnknownPrefixIsNull() =>
        Assert.Null(Small().Lookup(PhysicalAddress.Parse("AA-BB-CC-12-34-56")));

    [Fact]
    public void LocallyAdministeredAddressHasNoVendor() =>
        Assert.Null(Small().Lookup(PhysicalAddress.Parse("02-00-0C-12-34-56")));

    [Fact]
    public void EmbeddedDatabaseLoads()
    {
        Assert.True(VendorDatabase.Default.Count > 10_000);
        Assert.Contains("Cisco", VendorDatabase.Default.Lookup(PhysicalAddress.Parse("00-00-0C-00-00-01")));
    }
}
