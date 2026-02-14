#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
RESULTS_DIR="$PROJECT_DIR/results"

usage() {
    cat <<EOF
Usage: $(basename "$0") <site_name> <ip> [ip2 ...]
       $(basename "$0") <site_name> --unidentified

Investigate unknown hosts using multiple identification techniques.
Requires sudo for SYN scan.

Techniques:
  1. Broad port scan (nmap -sS -p 1-10000)
  2. mDNS lookup (dns-sd / avahi-browse)
  3. MAC vendor lookup (nmap OUI database)
  4. NetBIOS query (nmblookup)
  5. Reverse DNS (host / dig)

Options:
  --unidentified   Auto-select hosts from the latest sweep that had no OS/services
  -h               Show this help

Examples:
  sudo ./scripts/identify.sh office 10.10.1.12
  sudo ./scripts/identify.sh office 10.10.1.12 10.10.1.15
  sudo ./scripts/identify.sh office --unidentified
EOF
    exit 1
}

if [[ $# -lt 2 ]]; then
    usage
fi

SITE_NAME="$1"
shift

SITE_DIR="$RESULTS_DIR/$SITE_NAME"
if [[ ! -d "$SITE_DIR" ]]; then
    echo "Error: Site directory not found: $SITE_DIR"
    echo "Run discover.sh first to create the site."
    exit 1
fi

TIMESTAMP=$(date +%Y%m%d_%H%M%S)

# Check for nmap
if ! command -v nmap &>/dev/null; then
    echo "Error: nmap is not installed."
    exit 1
fi

# Locate nmap OUI database
OUI_DB=""
for path in /opt/homebrew/share/nmap/nmap-mac-prefixes \
            /usr/local/share/nmap/nmap-mac-prefixes \
            /usr/share/nmap/nmap-mac-prefixes; do
    if [[ -f "$path" ]]; then
        OUI_DB="$path"
        break
    fi
done

# Collect target IPs
TARGETS=()
if [[ "$1" == "--unidentified" ]]; then
    # Find the latest deep scan XML and extract hosts with no OS or services
    LATEST_XML=$(ls -t "$SITE_DIR"/servers_*.xml 2>/dev/null | head -1 || true)
    if [[ -z "$LATEST_XML" ]]; then
        echo "Error: No deep scan results found in $SITE_DIR"
        echo "Run discover_servers.sh first, then use --unidentified."
        exit 1
    fi
    echo "Scanning $LATEST_XML for unidentified hosts..."
    # Extract IPs where nmap found no OS match and no open ports
    while IFS= read -r ip; do
        [[ -n "$ip" ]] && TARGETS+=("$ip")
    done < <(python3 -c "
import xml.etree.ElementTree as ET, sys
tree = ET.parse('$LATEST_XML')
for host in tree.findall('.//host'):
    addr = host.find('address[@addrtype=\"ipv4\"]')
    if addr is None: continue
    ip = addr.get('addr')
    # Check for OS matches
    os_matches = host.findall('.//osmatch')
    # Check for open ports
    open_ports = host.findall('.//port/state[@state=\"open\"]')
    if not os_matches and not open_ports:
        print(ip)
" 2>/dev/null)
    if [[ ${#TARGETS[@]} -eq 0 ]]; then
        echo "No unidentified hosts found — all hosts had OS or service info."
        exit 0
    fi
    echo "Found ${#TARGETS[@]} unidentified host(s): ${TARGETS[*]}"
    echo ""
else
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -h) usage ;;
            *) TARGETS+=("$1") ;;
        esac
        shift
    done
fi

if [[ ${#TARGETS[@]} -eq 0 ]]; then
    echo "Error: No target IPs specified."
    usage
fi

# --- Investigation functions ---

run_broad_portscan() {
    local ip="$1"
    local outfile="$2"
    echo "  [1/5] Broad port scan (1-10000)..."
    local xml_out="$SITE_DIR/identify_portscan_${ip}_${TIMESTAMP}.xml"
    if sudo nmap -sS -p 1-10000 --open -T4 "$ip" -oX "$xml_out" --no-stylesheet 2>/dev/null | \
        grep -E "^[0-9]+/|^Nmap scan|^Host is" >> "$outfile"; then
        true
    fi
    # Show open ports summary
    local open_ports
    open_ports=$(grep -oP '[0-9]+/open' "$xml_out" 2>/dev/null | tr '\n' ' ' || true)
    if [[ -n "$open_ports" ]]; then
        echo "     Open ports: $open_ports"
    else
        echo "     No open ports found (1-10000)"
    fi
    echo "     XML: $xml_out"
}

run_mdns_lookup() {
    local ip="$1"
    local outfile="$2"
    echo "  [2/5] mDNS lookup..."

    if [[ "$(uname)" == "Darwin" ]]; then
        if command -v dns-sd &>/dev/null; then
            local mdns_result
            mdns_result=$(timeout 3 dns-sd -Q "$ip" 2>&1 || true)
            if [[ -n "$mdns_result" ]]; then
                echo "$mdns_result" >> "$outfile"
                echo "     $(echo "$mdns_result" | head -3)"
            else
                echo "     No mDNS response"
            fi
            # Also try browsing all services briefly
            local browse_result
            browse_result=$(timeout 3 dns-sd -B _services._dns-sd._udp local. 2>&1 || true)
            if [[ -n "$browse_result" ]]; then
                echo "--- mDNS browse ---" >> "$outfile"
                echo "$browse_result" >> "$outfile"
            fi
        else
            echo "     dns-sd not available"
        fi
    else
        if command -v avahi-browse &>/dev/null; then
            local avahi_result
            avahi_result=$(timeout 3 avahi-browse -art 2>&1 || true)
            if [[ -n "$avahi_result" ]]; then
                # Filter for our target IP
                local matches
                matches=$(echo "$avahi_result" | grep "$ip" || true)
                if [[ -n "$matches" ]]; then
                    echo "$matches" >> "$outfile"
                    echo "     $matches"
                else
                    echo "     No mDNS entries for $ip"
                fi
            else
                echo "     No mDNS response"
            fi
        else
            echo "     avahi-browse not available"
        fi
    fi
}

run_mac_vendor_lookup() {
    local ip="$1"
    local outfile="$2"
    echo "  [3/5] MAC vendor lookup..."

    # Get MAC from ARP table
    local mac=""
    if [[ "$(uname)" == "Darwin" ]]; then
        mac=$(arp -n "$ip" 2>/dev/null | awk '{print $4}' | grep -v "no" || true)
    else
        mac=$(arp -n "$ip" 2>/dev/null | awk '/ether/{print $3}' || true)
    fi

    if [[ -z "$mac" || "$mac" == "(incomplete)" ]]; then
        echo "     MAC not in ARP table (try pinging first)"
        return
    fi

    echo "     MAC: $mac"
    echo "MAC: $mac" >> "$outfile"

    if [[ -n "$OUI_DB" ]]; then
        # Extract first 3 octets, remove separators, uppercase
        local prefix
        prefix=$(echo "$mac" | tr -d ':.-' | cut -c1-6 | tr '[:lower:]' '[:upper:]')
        local vendor
        vendor=$(grep -i "^$prefix" "$OUI_DB" 2>/dev/null | cut -d' ' -f2- || true)
        if [[ -n "$vendor" ]]; then
            echo "     Vendor: $vendor"
            echo "Vendor: $vendor" >> "$outfile"
        else
            echo "     Vendor: Unknown (prefix $prefix)"
        fi
    else
        echo "     OUI database not found"
    fi
}

run_netbios_query() {
    local ip="$1"
    local outfile="$2"
    echo "  [4/5] NetBIOS query..."

    if command -v nmblookup &>/dev/null; then
        local nbresult
        nbresult=$(nmblookup -A "$ip" 2>/dev/null || true)
        if [[ -n "$nbresult" && ! "$nbresult" =~ "No reply" ]]; then
            echo "$nbresult" >> "$outfile"
            # Extract the name
            local nbname
            nbname=$(echo "$nbresult" | grep '<00>' | head -1 | awk '{print $1}' || true)
            if [[ -n "$nbname" ]]; then
                echo "     NetBIOS name: $nbname"
            else
                echo "     NetBIOS response received (see log for details)"
            fi
            # Check for <1C> group type — indicates a Domain Controller
            if echo "$nbresult" | grep -qi '<1c>'; then
                echo "     Domain Controller detected (NetBIOS <1C> group)"
            fi
        else
            echo "     No NetBIOS response"
        fi
    else
        echo "     nmblookup not available (install samba-common-bin)"
    fi
}

run_reverse_dns() {
    local ip="$1"
    local outfile="$2"
    echo "  [5/5] Reverse DNS..."

    local result=""
    if command -v host &>/dev/null; then
        result=$(host "$ip" 2>/dev/null || true)
    elif command -v dig &>/dev/null; then
        result=$(dig -x "$ip" +short 2>/dev/null || true)
    fi

    if [[ -n "$result" && ! "$result" =~ "not found" && ! "$result" =~ "NXDOMAIN" ]]; then
        echo "     $result"
        echo "Reverse DNS: $result" >> "$outfile"
    else
        echo "     No PTR record found"
    fi
}

# --- Main loop ---

echo "=== LAN Tracer - Host Identification ==="
echo "Site: $SITE_NAME"
echo "Targets: ${TARGETS[*]}"
echo ""

for IP in "${TARGETS[@]}"; do
    echo "================================================"
    echo "Investigating: $IP"
    echo "================================================"

    OUTFILE="$SITE_DIR/identify_${IP}_${TIMESTAMP}.txt"
    echo "=== Identification Report: $IP ===" > "$OUTFILE"
    echo "Date: $(date)" >> "$OUTFILE"
    echo "" >> "$OUTFILE"

    run_broad_portscan "$IP" "$OUTFILE"
    echo "" >> "$OUTFILE"

    run_mdns_lookup "$IP" "$OUTFILE"
    echo "" >> "$OUTFILE"

    run_mac_vendor_lookup "$IP" "$OUTFILE"
    echo "" >> "$OUTFILE"

    run_netbios_query "$IP" "$OUTFILE"
    echo "" >> "$OUTFILE"

    run_reverse_dns "$IP" "$OUTFILE"
    echo "" >> "$OUTFILE"

    echo ""
    echo "  Full report: $OUTFILE"
    echo ""
done

echo "=== Identification Complete ==="
