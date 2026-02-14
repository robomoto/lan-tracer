# LAN Tracer - Network Discovery Toolkit

Portable network discovery toolkit for finding servers across multiple sites, with CSV export for asset management.

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

Runs an nmap ping sweep (`-sn`) to find all live hosts, with optional arp-scan fallback for ICMP-blocking hosts and mDNS service discovery. Fast — takes seconds per /24 subnet.

```bash
# Single subnet
./scripts/discover.sh office 10.10.1.0/24

# Multiple subnets
./scripts/discover.sh office 10.10.1.0/24 10.10.2.0/24 10.10.3.0/24

# From a site config file
./scripts/discover.sh office -f sites/office.conf

# Skip optional phases
./scripts/discover.sh office 10.10.1.0/24 --no-arp --no-mdns
```

**Phases:**
1. **nmap ping sweep** — ICMP/ARP host discovery
2. **arp-scan fallback** — catches hosts blocking ICMP (skip with `--no-arp`)
3. **mDNS discovery** — finds devices advertising Bonjour/mDNS services like smart speakers, printers, Apple devices (skip with `--no-mdns`). Uses `dns-sd` on macOS, `avahi-browse` on Linux.

Output: `results/<site>/live_hosts.txt` + XML/grepable files + `mdns_<timestamp>.txt`.

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

Scans ~30 server-indicative ports: SSH(22), SMTP(25), DNS(53), HTTP(80/443), Kerberos(88), SMB(135/139/445), LDAP(389/636), MSSQL(1433), Oracle(1521), Global Catalog(3268/3269), MySQL(3306), RDP(3389), PostgreSQL(5432), VNC(5900), WinRM(5985/5986), K8s API(6443), Web Admin(8080/8443), MikroTik(8728/8729), Prometheus/Cockpit(9090), Elasticsearch(9200).

Also runs `ldap-rootdse` (anonymous LDAP query) to detect Active Directory domain information.

### Phase 3: CSV Export (`convert_to_csv.py`)

Parses nmap XML results and produces CSV files for asset management.

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

Output columns: IP Address, MAC Address, Vendor, Hostname, OS, OS Accuracy, Open Ports, Services, Site, Likely Server, Server Indicators, Likely DC, Domain.

### Host Investigation (`identify.sh`)

When the sweep finds devices that can't be identified (all ports filtered, no OS detected), use `identify.sh` to run multiple identification techniques against specific IPs.

```bash
# Investigate a specific host
sudo ./scripts/identify.sh office 10.10.1.12

# Investigate multiple hosts
sudo ./scripts/identify.sh office 10.10.1.12 10.10.1.15

# Auto-select unidentified hosts from the latest deep scan
sudo ./scripts/identify.sh office --unidentified
```

**Techniques run (in order):**
1. Broad port scan (nmap SYN scan, ports 1-10000)
2. mDNS lookup (dns-sd / avahi-browse)
3. MAC vendor lookup (nmap OUI database)
4. NetBIOS query (nmblookup)
5. Reverse DNS (host / dig)

Output: Console summary + `results/<site>/identify_<ip>_<timestamp>.txt`

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

### Domain Controller Classification

The CSV converter identifies likely Domain Controllers using:

- **DC port heuristic**: 3+ DC-associated ports open (Kerberos/88, LDAP/389, LDAPS/636, Global Catalog/3268, DNS/53, SMB/445) **and** at least one of Kerberos(88) or Global Catalog(3268) is present
- **NetBIOS `<1C>` group type**: A definitive DC identifier from nbstat output

Domain name is extracted from `ldap-rootdse` output (`defaultNamingContext`), falling back to `smb-os-discovery` domain name.

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

## Remote Scanning via SSH

When sites are in different countries/locations, SSH into a Linux box at each site, run scans there, and pull results back for local CSV processing.

### Prerequisites at each remote site

- A Linux machine (jump box, server, VM — anything with network access to the target subnets)
- SSH access from your office to that machine (direct or via VPN)
- `nmap` installed on the remote machine
- `sudo` access for SYN scanning and OS detection

### 1. Deploy LAN Tracer to a remote site

```bash
# Copy the toolkit to the remote machine (first time only)
scp -r lan_tracer/ user@jumpbox-london:/opt/lan_tracer

# Or clone from your repo
ssh user@jumpbox-london "git clone https://your-repo/lan_tracer.git /opt/lan_tracer"
```

### 2. Create a site config locally and push it

```bash
# sites/london.conf
cat > sites/london.conf <<EOF
# Site: London Office
# Contact: Jane Smith
10.20.1.0/24
10.20.2.0/24
10.20.10.0/24
EOF

scp sites/london.conf user@jumpbox-london:/opt/lan_tracer/sites/
```

### 3. Run scans remotely via SSH

```bash
# Quick sweep
ssh user@jumpbox-london "cd /opt/lan_tracer && ./scripts/discover.sh london -f sites/london.conf"

# Deep scan (requires sudo — use -t flag for ssh pseudo-terminal)
ssh -t user@jumpbox-london "cd /opt/lan_tracer && sudo ./scripts/discover_servers.sh london"
```

For long-running scans, use `nohup` or `tmux` so the scan survives a dropped connection:

```bash
# Start scan in background (survives disconnection)
ssh user@jumpbox-london "cd /opt/lan_tracer && nohup sudo ./scripts/discover_servers.sh london > /tmp/scan.log 2>&1 &"

# Check progress later
ssh user@jumpbox-london "tail -f /tmp/scan.log"

# Or use tmux for an interactive session
ssh -t user@jumpbox-london "tmux new -s scan 'cd /opt/lan_tracer && sudo ./scripts/discover_servers.sh london'"
# Detach with Ctrl-b d, reattach later:
ssh -t user@jumpbox-london "tmux attach -t scan"
```

### 4. Pull results back to your office

```bash
# Pull a single site's results
scp -r user@jumpbox-london:/opt/lan_tracer/results/london/ results/london/

# Pull from all sites at once (add entries for each site)
for site in london paris tokyo sydney; do
    echo "Pulling results from $site..."
    scp -r "user@jumpbox-${site}:/opt/lan_tracer/results/${site}/" "results/${site}/"
done
```

### 5. Generate CSV locally

Once all results are in your local `results/` directory:

```bash
# Process everything into unified CSVs
python3 scripts/convert_to_csv.py

# Or one site at a time
python3 scripts/convert_to_csv.py --site london
```

### Scanning multiple sites in parallel

```bash
#!/usr/bin/env bash
# scan_all_sites.sh — run sweeps across all remote sites concurrently

declare -A SITES
SITES[london]="user@jumpbox-london"
SITES[paris]="user@jumpbox-paris"
SITES[tokyo]="user@jumpbox-tokyo"
SITES[sydney]="user@jumpbox-sydney"

# Phase 1: Sweep all sites in parallel
for site in "${!SITES[@]}"; do
    host="${SITES[$site]}"
    echo "Starting sweep: $site ($host)"
    ssh "$host" "cd /opt/lan_tracer && ./scripts/discover.sh $site -f sites/${site}.conf" &
done
wait
echo "All sweeps complete."

# Phase 2: Deep scan all sites in parallel
for site in "${!SITES[@]}"; do
    host="${SITES[$site]}"
    echo "Starting deep scan: $site ($host)"
    ssh -t "$host" "cd /opt/lan_tracer && sudo ./scripts/discover_servers.sh $site" &
done
wait
echo "All deep scans complete."

# Phase 3: Pull results back
for site in "${!SITES[@]}"; do
    host="${SITES[$site]}"
    scp -r "${host}:/opt/lan_tracer/results/${site}/" "results/${site}/"
done

# Phase 4: Generate CSV
python3 scripts/convert_to_csv.py
```

### Tips

- **SSH keys**: Set up key-based auth to avoid typing passwords for every site. Use `ssh-copy-id user@jumpbox-london`.
- **SSH config**: Add entries in `~/.ssh/config` to simplify hostnames and manage jump proxies:
  ```
  Host london
      HostName 203.0.113.10
      User scanner
      IdentityFile ~/.ssh/lan_tracer_key

  Host paris
      HostName 198.51.100.20
      User scanner
      ProxyJump vpn-gateway
  ```
- **Firewall rules**: The remote machine needs outbound access to the target subnets. Nmap SYN scanning requires raw sockets (sudo).
- **VPN tunnels**: If sites are connected via VPN, you may be able to scan remote subnets directly from your office — but latency and packet loss make remote nmap scans unreliable. Running nmap locally at each site gives much better results.
- **Consistent versions**: Keep the same version of LAN Tracer and nmap across all sites to ensure consistent output. Use `nmap --version` to check.

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
