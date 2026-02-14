# LAN Tracer - Network Discovery Toolkit

Portable network discovery toolkit for finding servers across multiple sites. Designed for environments without Lansweeper licenses, with CSV export compatible with Lansweeper import.

## Prerequisites

- **nmap** — `brew install nmap` (macOS) or `sudo apt install nmap` (Linux)
- **Python 3** — stdlib only, no pip dependencies
- **sudo access** — required for OS detection and SYN scanning

## Quick Start

```bash
# 1. Sweep a subnet to find live hosts
./scripts/discover.sh mysite 10.10.1.0/24

# 2. Deep scan live hosts for server identification
./scripts/discover_servers.sh mysite

# 3. Convert results to CSV
python3 scripts/convert_to_csv.py
```

## Usage

### Phase 1: Quick Sweep (`discover.sh`)

Runs an nmap ping sweep (`-sn`) to find all live hosts. Fast — takes seconds per /24 subnet.

```bash
# Single subnet
./scripts/discover.sh office 10.10.1.0/24

# Multiple subnets
./scripts/discover.sh office 10.10.1.0/24 10.10.2.0/24 10.10.3.0/24

# From a site config file
./scripts/discover.sh office -f sites/office.conf
```

Output: `results/<site>/live_hosts.txt` + XML/grepable files.

### Phase 2: Server Deep Scan (`discover_servers.sh`)

Runs targeted port scan with OS detection and service version identification. Requires sudo.

```bash
# Use live hosts from Phase 1
./scripts/discover_servers.sh office

# Or scan a subnet directly
./scripts/discover_servers.sh office 10.10.1.0/24

# Adjust timing
./scripts/discover_servers.sh office -T3 -t 8
```

Scans ~30 server-indicative ports: SSH(22), SMTP(25), DNS(53), HTTP(80/443), Kerberos(88), SMB(135/139/445), LDAP(389/636), MSSQL(1433), Oracle(1521), MySQL(3306), RDP(3389), PostgreSQL(5432), VNC(5900), WinRM(5985/5986), K8s API(6443), Web Admin(8080/8443), MikroTik(8728/8729), Prometheus/Cockpit(9090), Elasticsearch(9200).

### Phase 3: CSV Export (`convert_to_csv.py`)

Parses nmap XML results and produces Lansweeper-compatible CSV files.

```bash
# All sites
python3 scripts/convert_to_csv.py

# Single site
python3 scripts/convert_to_csv.py --site office

# Servers only
python3 scripts/convert_to_csv.py --servers-only

# Custom output directory
python3 scripts/convert_to_csv.py --output-dir /tmp/export
```

Output columns: IP Address, MAC Address, Vendor, Hostname, OS, OS Accuracy, Open Ports, Services, Site, Likely Server, Server Indicators.

### Site Config Files

Place config files in `sites/`. Format: one CIDR per line, comments with `#`.

```
# Site: Main Office
# Location: Building A
# Contact: John Doe
10.10.1.0/24
10.10.2.0/24
10.10.10.0/24
```

## Server Classification

The CSV converter uses heuristics to flag likely servers:

- **OS match**: Contains "Server", "Linux", "FreeBSD", "ESXi", "RouterOS", etc.
- **Strong server ports**: Ports like LDAP(389), Kerberos(88), MSSQL(1433), SMB(445)
- **Port count**: 3+ server-indicative ports open

## Multi-Site Workflow

For scanning ~40 networks:

```bash
# Create config files for each site
# sites/site-a.conf, sites/site-b.conf, etc.

# Sweep all sites
for conf in sites/*.conf; do
    site=$(basename "$conf" .conf)
    ./scripts/discover.sh "$site" -f "$conf"
done

# Deep scan all sites
for site in results/*/; do
    site=$(basename "$site")
    ./scripts/discover_servers.sh "$site"
done

# Export everything
python3 scripts/convert_to_csv.py
```

## Additional Discovery Tools

nmap won't find everything — devices blocking ICMP, hosts on isolated VLANs, or machines with host firewalls will be missed. These complementary tools fill the gaps.

### SNMP Switch MAC Table Polling

The best way to find ALL connected devices. Managed switches know every MAC address on every port.

```bash
# Install snmpwalk
sudo apt install snmp snmp-mibs-downloader  # Linux
brew install net-snmp                        # macOS

# Pull MAC/ARP table from a switch (replace community string)
snmpwalk -v2c -c public 10.10.1.1 1.3.6.1.2.1.17.4.3.1.1   # Bridge MIB (MAC table)
snmpwalk -v2c -c public 10.10.1.1 1.3.6.1.2.1.4.22.1.2      # ARP table (IP-to-MAC)
snmpwalk -v2c -c public 10.10.1.1 1.3.6.1.2.1.17.4.3.1.2    # MAC-to-port mapping
```

### arp-scan — Layer 2 Discovery

Finds devices that block ICMP by sending ARP requests directly.

```bash
sudo apt install arp-scan  # or brew install arp-scan
sudo arp-scan --interface=eth0 10.10.1.0/24
sudo arp-scan --localnet  # scan local subnet
```

### nbtscan — NetBIOS Enumeration

Fast NetBIOS name scanning for Windows networks.

```bash
sudo apt install nbtscan
nbtscan 10.10.1.0/24
nbtscan -r 10.10.1.0/24  # resolve names
```

### enum4linux-ng — Windows/Samba Deep Enumeration

Enumerates domain controllers, shares, users, groups.

```bash
pip3 install enum4linux-ng
enum4linux-ng -A 10.10.1.10  # full enumeration
enum4linux-ng -S 10.10.1.10  # shares only
```

### masscan — High-Speed Port Scanning

For very large subnets where nmap is too slow. Scans millions of hosts per minute.

```bash
sudo apt install masscan
sudo masscan 10.0.0.0/8 -p 445,3389,22 --rate=10000 -oX results.xml
```

### DHCP Log Analysis

DHCP servers know every device that requested an address.

```bash
# Windows DHCP Server — export from PowerShell
Get-DhcpServerv4Lease -ScopeId 10.10.1.0 | Export-Csv dhcp_leases.csv

# ISC DHCP (Linux) — parse lease file
grep -E "^lease|hardware ethernet|client-hostname" /var/lib/dhcp/dhcpd.leases

# MikroTik — export leases
/ip dhcp-server lease print detail file=leases
```

### DNS Zone Transfers

If DNS servers allow zone transfers, you get a complete list of all DNS records.

```bash
# Attempt zone transfer
dig axfr example.local @10.10.1.1

# Reverse DNS sweep (when zone transfer blocked)
for i in $(seq 1 254); do
    host 10.10.1.$i 10.10.1.1 2>/dev/null | grep "name pointer"
done
```

### Responder (Analyze Mode) — Passive Discovery

Listens for broadcast/multicast traffic (LLMNR, NBT-NS, mDNS) to passively discover devices without sending any probes.

```bash
git clone https://github.com/lgandx/Responder.git
cd Responder
# ANALYZE MODE ONLY — does not poison, just listens
sudo python3 Responder.py -I eth0 -A
```

**Warning**: Only use analyze mode (`-A`). Without `-A`, Responder actively poisons name resolution — this is an attack tool. Analyze mode is safe and passive.
