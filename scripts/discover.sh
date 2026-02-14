#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
RESULTS_DIR="$PROJECT_DIR/results"
SITES_DIR="$PROJECT_DIR/sites"

usage() {
    cat <<EOF
Usage: $(basename "$0") <site_name> [subnet | -f config_file]

Quick network sweep using nmap ping scan (-sn).
Finds all live hosts and saves results for deeper scanning.

Examples:
  $(basename "$0") office 10.10.1.0/24
  $(basename "$0") office -f sites/office.conf
  $(basename "$0") office 10.10.1.0/24 10.10.2.0/24

Options:
  -f FILE   Read subnets from a site config file (one CIDR per line)
  -h        Show this help
EOF
    exit 1
}

if [[ $# -lt 2 ]]; then
    usage
fi

SITE_NAME="$1"
shift

# Collect subnets
SUBNETS=()
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

# Deduplicate
sort -u -o "$ALL_LIVE_HOSTS" "$ALL_LIVE_HOSTS"
TOTAL=$(wc -l < "$ALL_LIVE_HOSTS" | xargs)

echo "=== Sweep Complete ==="
echo "Total unique live hosts: $TOTAL"
echo "Live host list: $ALL_LIVE_HOSTS"
echo ""
echo "Next step: Run deep server scan with:"
echo "  ./scripts/discover_servers.sh $SITE_NAME"
