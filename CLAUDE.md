# LAN Tracer

Network discovery toolkit for finding servers across ~40 sites.

## Architecture

- **Two-phase scanning**: Quick ping sweep (`discover.sh`) then targeted deep scan (`discover_servers.sh`)
- **Server-port heuristic**: ~30 targeted ports instead of full 65k scan
- **Python converter**: stdlib-only XML-to-CSV with server classification heuristics
- **DC detection**: Identifies Domain Controllers via port heuristics (Kerberos/GC + DC ports), NetBIOS `<1C>`, and LDAP rootDSE domain extraction
- **Output**: CSV for asset management (all_devices.csv + servers_only.csv) with DC and Domain columns

## Key Files

- `scripts/discover.sh` — nmap ping sweep + arp-scan + mDNS discovery, produces live_hosts.txt
- `scripts/discover_servers.sh` — deep scan with OS/service detection (requires sudo)
- `scripts/identify.sh` — focused investigation of unknown hosts (broad portscan, mDNS, MAC vendor, NetBIOS, rDNS)
- `scripts/convert_to_csv.py` — nmap XML → CSV with server classification
- `sites/*.conf` — site config files (one CIDR per line)
- `results/` — scan output (gitignored, contains sensitive data)

## Conventions

- Results go in `results/<site_name>/`
- XML is the primary parse format; grepable output saved alongside for quick grep
- No external Python dependencies — stdlib only
- Scripts must work on both macOS and Linux
