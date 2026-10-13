<img src="src/IPv6NetScanner.Gui/logo.ico" alt="Logo" title="IPv6-NetScanner" align="right" height="60" />

# IPv6 Network Scanner

A fast, lightweight IPv6 link-local network scanner for **Linux, Windows and macOS**, built on .NET 10,
[SharpPcap](https://github.com/dotpcap/sharppcap), [PacketDotNet](https://github.com/dotpcap/packetnet) and [Avalonia](https://avaloniaui.net).
Background: [Scanning IPv6 networks](https://www.dionach.com/blog/scanning-ipv6-networks/).

<img src="img/01.JPG">

## How it works
IPv6 networks are far too large to sweep, so the scanner uses multicast discovery instead. It sends ICMPv6 echo requests
(with a correct checksum, hop limit 255) from the adapter's link-local address to

| Group    | Meaning                         |
|----------|---------------------------------|
| `ff02::1` | all nodes - every IPv6 host answers |
| `ff02::2` | all routers - only routers answer   |

Every echo reply is matched to our request (ICMPv6 identifier + sequence), so a host answering the router
group is reliably flagged as **Router**. Each group is pinged 3 times (1 s apart) and the scanner listens 2 s
afterwards - about 5 seconds in total. The MAC address is looked up in an embedded OUI database to show the manufacturer
(randomized/locally administered MACs show as *Unknown*).

## Requirements
* **.NET 10 runtime** (or use a self-contained build)
* A packet-capture library:
  * **Linux**: `libpcap` (`sudo apt install libpcap0.8t64`, `sudo dnf install libpcap`)
  * **macOS**: libpcap is part of the OS
  * **Windows**: [Npcap](https://npcap.com)
* Permission to capture/send raw frames:
  * **Linux**: run as root or grant capabilities once:
    `sudo setcap cap_net_raw,cap_net_admin=eip ./IPv6-NetScanner`
    (for `dotnet run` give them to the `dotnet` host binary or just use `sudo`)
  * **macOS**: run with `sudo` or give your user access to `/dev/bpf*`
  * **Windows**: Npcap installed (run as administrator if no adapters show up)

## Build & run
```bash
dotnet build

# GUI
dotnet run --project src/IPv6NetScanner.Gui

# CLI
dotnet run --project src/IPv6NetScanner.Cli -- --list
sudo dotnet run --project src/IPv6NetScanner.Cli -- -i eth0
```

Publish self-contained single files:
```bash
dotnet publish src/IPv6NetScanner.Gui -c Release -r linux-x64 --self-contained -p:PublishSingleFile=true
dotnet publish src/IPv6NetScanner.Gui -c Release -r win-x64   --self-contained -p:PublishSingleFile=true
```

## Project layout
| Path | Content |
|------|---------|
| `src/IPv6NetScanner.Core` | Scanner, packet builder, adapter discovery, OUI database (no UI dependency) |
| `src/IPv6NetScanner.Gui`  | Avalonia desktop app |
| `src/IPv6NetScanner.Cli`  | Command line scanner |
| `tests/IPv6NetScanner.Tests` | xUnit tests (checksum, packet layout, vendor lookup) |

## MAC-address vendor database
`src/IPv6NetScanner.Core/Resources/vendorMacs.xml` is embedded into the assembly. Source: [maclookup.app](https://maclookup.app/downloads/cisco-vendor-macs-xml-database).

## Limitations
* Only the local link is scanned; hosts that drop multicast echo requests (some firewalls, `icmp6 echo_ignore_multicast`) stay invisible.

## License / Copyright
See [LICENSE](LICENSE).
