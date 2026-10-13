using IPv6NetScanner.Core;

namespace IPv6NetScanner.Gui;

public sealed record HostRow(string Address, string Mac, string Role, string Vendor)
{
    public static HostRow From(Host h) => new(h.Address.ToString(), h.MacText, h.Role, h.Vendor ?? "Unknown");
}
