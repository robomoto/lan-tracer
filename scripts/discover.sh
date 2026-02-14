#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
RESULTS_DIR="$PROJECT_DIR/results"
SITES_DIR="$PROJECT_DIR/sites"

usage() {
    cat <<EOF
Usage: $(basename "$0") <site_name> [subnet | -f config_file | --auto]

Quick network sweep using nmap ping scan (-sn), with optional arp-scan
fallback to catch hosts that block ICMP, and mDNS service discovery.

Examples:
  $(basename "$0") office --auto                    # Auto-detect local subnets
  $(basename "$0") office 10.10.1.0/24
  $(basename "$0") office -f sites/office.conf
  $(basename "$0") office 10.10.1.0/24 10.10.2.0/24
  $(basename "$0") office -f sites/office.conf --no-arp --no-mdns

Options:
  --auto     Auto-detect local subnets from network interfaces
  -f FILE    Read subnets from a site config file (one CIDR per line)
  --no-arp   Skip arp-scan fallback (nmap only)
  --no-mdns  Skip mDNS service discovery
  -i IFACE   Network interface for arp-scan (default: auto-detect)
  -h         Show this help
EOF
    exit 1
}

if [[ $# -lt 2 ]]; then
    # Allow: discover.sh office --auto (only 2 args needed, not a bare subnet)
    usage
fi

SITE_NAME="$1"
shift

# Auto-detect local subnets from network interfaces
detect_subnets() {
    local subnets=()
    if [[ "$(uname)" == "Darwin" ]]; then
        # macOS: parse ifconfig for inet lines with netmask
        while IFS= read -r line; do
            local ip mask
            ip=$(echo "$line" | awk '{print $2}')
            mask=$(echo "$line" | awk '{print $4}')
            # Skip loopback and link-local
            [[ "$ip" == 127.* ]] && continue
            [[ "$ip" == 169.254.* ]] && continue
            # Skip point-to-point tunnel interfaces (VPNs)
            if echo "$line" | grep -q -- '-->'; then
                continue
            fi
            # Convert hex netmask to CIDR prefix length
            local cidr=0
            for octet in $(echo "$mask" | sed 's/0x//' | fold -w2); do
                local dec=$((16#$octet))
                while [[ $dec -gt 0 ]]; do
                    cidr=$((cidr + (dec & 1)))
                    dec=$((dec >> 1))
                done
            done
            # Calculate network address
            IFS='.' read -r a b c d <<< "$ip"
            IFS='.' read -r ma mb mc md <<< "$(printf "%d.%d.%d.%d" "0x${mask:2:2}" "0x${mask:4:2}" "0x${mask:6:2}" "0x${mask:8:2}")"
            local network="$((a & ma)).$((b & mb)).$((c & mc)).$((d & md))"
            subnets+=("${network}/${cidr}")
        done < <(ifconfig 2>/dev/null | grep "inet " | grep -v "127\.0\.0\.1")
    else
        # Linux: parse ip addr
        while IFS= read -r line; do
            local cidr_addr
            cidr_addr=$(echo "$line" | awk '{print $2}')
            local ip="${cidr_addr%/*}"
            local prefix="${cidr_addr#*/}"
            # Skip loopback and link-local
            [[ "$ip" == 127.* ]] && continue
            [[ "$ip" == 169.254.* ]] && continue
            # Calculate network address
            IFS='.' read -r a b c d <<< "$ip"
            local full_mask=$(( (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF ))
            local ma=$(( (full_mask >> 24) & 0xFF ))
            local mb=$(( (full_mask >> 16) & 0xFF ))
            local mc=$(( (full_mask >> 8) & 0xFF ))
            local md=$(( full_mask & 0xFF ))
            local network="$((a & ma)).$((b & mb)).$((c & mc)).$((d & md))"
            subnets+=("${network}/${prefix}")
        done < <(ip -4 addr show 2>/dev/null | grep "inet " | grep -v "127\.0\.0\.1" | grep -v "scope host")
    fi
    # Print results
    for s in "${subnets[@]}"; do
        echo "$s"
    done
}

# Collect subnets and options
SUBNETS=()
USE_ARP=true
USE_MDNS=true
ARP_IFACE=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --auto)
            echo "Detecting local subnets..."
            while IFS= read -r subnet; do
                [[ -n "$subnet" ]] && SUBNETS+=("$subnet")
            done < <(detect_subnets)
            if [[ ${#SUBNETS[@]} -eq 0 ]]; then
                echo "Error: Could not detect any local subnets."
                echo "Specify subnets manually instead."
                exit 1
            fi
            echo "  Found: ${SUBNETS[*]}"
            echo ""
            ;;
        -f)
            shift
            CONFIG_FILE="$1"
            # Resolve relative paths against project dir
            if [[ ! "$CONFIG_FILE" = /* ]]; then
                CONFIG_FILE="$PROJECT_DIR/$CONFIG_FILE"
            fi
            if [[ ! -f "$CONFIG_FILE" ]]; then
                echo "Error: Config file not found: $CONFIG_FILE"
                exit 1
            fi
            while IFS= read -r line; do
                # Skip comments and blank lines
                line="$(echo "$line" | sed 's/#.*//' | xargs)"
                [[ -z "$line" ]] && continue
                SUBNETS+=("$line")
            done < "$CONFIG_FILE"
            ;;
        --no-arp)
            USE_ARP=false
            ;;
        --no-mdns)
            USE_MDNS=false
            ;;
        -i)
            shift
            ARP_IFACE="$1"
            ;;
        -h)
            usage
            ;;
        *)
            SUBNETS+=("$1")
            ;;
    esac
    shift
done

if [[ ${#SUBNETS[@]} -eq 0 ]]; then
    echo "Error: No subnets specified."
    usage
fi

# Check for nmap
if ! command -v nmap &>/dev/null; then
    echo "Error: nmap is not installed. Install it with:"
    echo "  macOS:  brew install nmap"
    echo "  Linux:  sudo apt install nmap"
    exit 1
fi

# Check for arp-scan
HAS_ARP=false
if [[ "$USE_ARP" == true ]] && command -v arp-scan &>/dev/null; then
    HAS_ARP=true
elif [[ "$USE_ARP" == true ]]; then
    echo "Note: arp-scan not found. Install for better discovery of ICMP-blocking hosts."
    echo "  macOS:  brew install arp-scan"
    echo "  Linux:  sudo apt install arp-scan"
    echo ""
fi

# Auto-detect network interface for arp-scan
# Use the interface that routes to the first target subnet (not the default route,
# which may point at a VPN tunnel that can't do ARP)
if [[ "$HAS_ARP" == true && -z "$ARP_IFACE" ]]; then
    # Extract a sample IP from the first subnet (e.g. 192.168.50.0/24 → 192.168.50.1)
    SAMPLE_IP="${SUBNETS[0]%/*}"
    SAMPLE_IP="${SAMPLE_IP%.*}.$((${SAMPLE_IP##*.} + 1))"
    if [[ "$(uname)" == "Darwin" ]]; then
        ARP_IFACE=$(route -n get "$SAMPLE_IP" 2>/dev/null | awk '/interface:/{print $2}' || echo "en0")
    else
        ARP_IFACE=$(ip route get "$SAMPLE_IP" 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev") print $(i+1); exit}' || echo "eth0")
    fi
fi

# Create output directory
SITE_DIR="$RESULTS_DIR/$SITE_NAME"
mkdir -p "$SITE_DIR"

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
ALL_LIVE_HOSTS="$SITE_DIR/live_hosts.txt"

# Clear previous live hosts list
> "$ALL_LIVE_HOSTS"

echo "=== LAN Tracer - Quick Sweep ==="
echo "Site: $SITE_NAME"
echo "Subnets: ${SUBNETS[*]}"
echo "Output: $SITE_DIR/"
echo ""

for SUBNET in "${SUBNETS[@]}"; do
    # Sanitize subnet for filename (replace / with _)
    SUBNET_SAFE="${SUBNET//\//_}"
    XML_OUT="$SITE_DIR/sweep_${SUBNET_SAFE}_${TIMESTAMP}.xml"
    GREP_OUT="$SITE_DIR/sweep_${SUBNET_SAFE}_${TIMESTAMP}.gnmap"

    echo "--- Scanning $SUBNET ---"
    nmap -sn "$SUBNET" \
        -oX "$XML_OUT" \
        -oG "$GREP_OUT" \
        --no-stylesheet

    # Extract live host IPs from grepable output
    grep "Status: Up" "$GREP_OUT" | awk '{print $2}' >> "$ALL_LIVE_HOSTS"

    LIVE_COUNT=$(grep -c "Status: Up" "$GREP_OUT" || true)
    echo "  Found $LIVE_COUNT live hosts"
    echo "  XML:  $XML_OUT"
    echo "  Grep: $GREP_OUT"
    echo ""
done

# Phase 2: arp-scan fallback to find ICMP-blocking hosts
if [[ "$HAS_ARP" == true ]]; then
    echo "--- ARP scan fallback (finding ICMP-blocking hosts) ---"
    echo "Interface: $ARP_IFACE"
    echo ""

    NMAP_COUNT=$(wc -l < "$ALL_LIVE_HOSTS" | xargs)
    ARP_LOG="$SITE_DIR/arpscan_${TIMESTAMP}.txt"

    for SUBNET in "${SUBNETS[@]}"; do
        echo "  ARP scanning $SUBNET ..."
        sudo arp-scan --interface="$ARP_IFACE" "$SUBNET" 2>/dev/null | \
            tee -a "$ARP_LOG" | \
            awk '/^[0-9]+\./{print $1}' >> "$ALL_LIVE_HOSTS"
    done

    # Deduplicate after adding arp-scan results
    sort -u -o "$ALL_LIVE_HOSTS" "$ALL_LIVE_HOSTS"
    ARP_TOTAL=$(wc -l < "$ALL_LIVE_HOSTS" | xargs)
    ARP_NEW=$((ARP_TOTAL - NMAP_COUNT))

    echo ""
    echo "  ARP scan found $ARP_NEW additional hosts that nmap missed"
    echo "  Full ARP log: $ARP_LOG"
    echo ""
fi

# Phase 3: mDNS service discovery
if [[ "$USE_MDNS" == true ]]; then
    echo "--- mDNS service discovery ---"
    MDNS_LOG="$SITE_DIR/mdns_${TIMESTAMP}.txt"

    if [[ "$(uname)" == "Darwin" ]]; then
        if command -v dns-sd &>/dev/null; then
            echo "  Running dns-sd browse (5 seconds)..."
            # dns-sd runs indefinitely; kill after timeout
            # macOS may not have 'timeout' (coreutils) — use perl fallback
            if command -v timeout &>/dev/null; then
                timeout 5 dns-sd -B _services._dns-sd._udp local. > "$MDNS_LOG" 2>&1 || true
            else
                dns-sd -B _services._dns-sd._udp local. > "$MDNS_LOG" 2>&1 &
                local dns_sd_pid=$!
                sleep 5
                kill "$dns_sd_pid" 2>/dev/null || true
                wait "$dns_sd_pid" 2>/dev/null || true
            fi
            MDNS_COUNT=$(grep -c "Add" "$MDNS_LOG" 2>/dev/null) || MDNS_COUNT=0
            echo "  Found $MDNS_COUNT mDNS service types"
        else
            echo "  dns-sd not found (unexpected on macOS)"
        fi
    else
        if command -v avahi-browse &>/dev/null; then
            echo "  Running avahi-browse (5 seconds)..."
            timeout 5 avahi-browse -art > "$MDNS_LOG" 2>&1 || true
            MDNS_COUNT=$(grep -c "^=" "$MDNS_LOG" 2>/dev/null || echo "0")
            echo "  Found $MDNS_COUNT mDNS service entries"
        else
            echo "  avahi-browse not found. Install for mDNS discovery:"
            echo "    sudo apt install avahi-utils"
        fi
    fi

    if [[ -f "$MDNS_LOG" && -s "$MDNS_LOG" ]]; then
        echo "  mDNS log: $MDNS_LOG"
    fi
    echo ""
fi

# Deduplicate (in case arp-scan was skipped)
sort -u -o "$ALL_LIVE_HOSTS" "$ALL_LIVE_HOSTS"
TOTAL=$(wc -l < "$ALL_LIVE_HOSTS" | xargs)

echo "=== Sweep Complete ==="
echo "Total unique live hosts: $TOTAL"
echo "Live host list: $ALL_LIVE_HOSTS"
echo ""
echo "Next step: Run deep server scan with:"
echo "  ./scripts/discover_servers.sh $SITE_NAME"
