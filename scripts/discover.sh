#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
RESULTS_DIR="$PROJECT_DIR/results"
SITES_DIR="$PROJECT_DIR/sites"

usage() {
    cat <<EOF
Usage: $(basename "$0") <site_name> [subnet | -f config_file]

Quick network sweep using nmap ping scan (-sn), with optional arp-scan
fallback to catch hosts that block ICMP.

Examples:
  $(basename "$0") office 10.10.1.0/24
  $(basename "$0") office -f sites/office.conf
  $(basename "$0") office 10.10.1.0/24 10.10.2.0/24
  $(basename "$0") office -f sites/office.conf --no-arp

Options:
  -f FILE    Read subnets from a site config file (one CIDR per line)
  --no-arp   Skip arp-scan fallback (nmap only)
  -i IFACE   Network interface for arp-scan (default: auto-detect)
  -h         Show this help
EOF
    exit 1
}

if [[ $# -lt 2 ]]; then
    usage
fi

SITE_NAME="$1"
shift

# Collect subnets and options
SUBNETS=()
USE_ARP=true
ARP_IFACE=""
while [[ $# -gt 0 ]]; do
    case "$1" in
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
if [[ "$HAS_ARP" == true && -z "$ARP_IFACE" ]]; then
    if [[ "$(uname)" == "Darwin" ]]; then
        ARP_IFACE=$(route -n get default 2>/dev/null | awk '/interface:/{print $2}' || echo "en0")
    else
        ARP_IFACE=$(ip route show default 2>/dev/null | awk '{print $5; exit}' || echo "eth0")
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

# Deduplicate (in case arp-scan was skipped)
sort -u -o "$ALL_LIVE_HOSTS" "$ALL_LIVE_HOSTS"
TOTAL=$(wc -l < "$ALL_LIVE_HOSTS" | xargs)

echo "=== Sweep Complete ==="
echo "Total unique live hosts: $TOTAL"
echo "Live host list: $ALL_LIVE_HOSTS"
echo ""
echo "Next step: Run deep server scan with:"
echo "  ./scripts/discover_servers.sh $SITE_NAME"
