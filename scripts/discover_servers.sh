#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
RESULTS_DIR="$PROJECT_DIR/results"

# Server-indicative ports
SERVER_PORTS="22,25,53,80,88,135,139,389,443,445,636,993,995,1433,1521,3268,3269,3306,3389,5432,5900,5985,5986,6443,8080,8443,8728,8729,9090,9200"

usage() {
    cat <<EOF
Usage: $(basename "$0") <site_name> [subnet ...]

Deep scan for server identification using OS detection, service versions,
and targeted server-port scanning.

Uses the live host list from a prior discover.sh sweep, or scans subnets directly.

Requires sudo for OS detection (-O) and SYN scan (-sS).

Examples:
  $(basename "$0") office                        # Use live_hosts.txt from sweep
  $(basename "$0") office 10.10.1.0/24           # Scan subnet directly
  $(basename "$0") office 10.10.1.0/24 10.10.2.0/24

Options:
  -t N      Max parallel hosts (nmap --min-hostgroup, default: 16)
  -T N      Timing template (0-5, default: 4)
  -h        Show this help
EOF
    exit 1
}

if [[ $# -lt 1 ]]; then
    usage
fi

SITE_NAME="$1"
shift

HOST_GROUP=16
TIMING=4
TARGETS=()

while [[ $# -gt 0 ]]; do
    case "$1" in
        -t)
            shift
            HOST_GROUP="$1"
            ;;
        -T)
            shift
            TIMING="$1"
            ;;
        -h)
            usage
            ;;
        *)
            TARGETS+=("$1")
            ;;
    esac
    shift
done

# Check for nmap
if ! command -v nmap &>/dev/null; then
    echo "Error: nmap is not installed."
    exit 1
fi

SITE_DIR="$RESULTS_DIR/$SITE_NAME"
mkdir -p "$SITE_DIR"

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
LIVE_HOSTS="$SITE_DIR/live_hosts.txt"

# Determine target list
TARGET_ARG=""
if [[ ${#TARGETS[@]} -gt 0 ]]; then
    # Subnets provided directly
    TARGET_ARG="${TARGETS[*]}"
    echo "Scanning subnets directly: $TARGET_ARG"
elif [[ -f "$LIVE_HOSTS" && -s "$LIVE_HOSTS" ]]; then
    TARGET_ARG="-iL $LIVE_HOSTS"
    HOST_COUNT=$(wc -l < "$LIVE_HOSTS" | xargs)
    echo "Using live host list: $LIVE_HOSTS ($HOST_COUNT hosts)"
else
    echo "Error: No targets specified and no live_hosts.txt found."
    echo "Run discover.sh first, or provide subnets directly."
    exit 1
fi

XML_OUT="$SITE_DIR/servers_${TIMESTAMP}.xml"
GREP_OUT="$SITE_DIR/servers_${TIMESTAMP}.gnmap"

echo ""
echo "=== LAN Tracer - Server Deep Scan ==="
echo "Site: $SITE_NAME"
echo "Ports: $SERVER_PORTS"
echo "Timing: T$TIMING, min-hostgroup: $HOST_GROUP"
echo "Output: $SITE_DIR/"
echo ""
echo "This scan requires root privileges for OS detection and SYN scanning."
echo ""

# Build nmap command
NMAP_CMD=(
    sudo nmap
    -sS                             # SYN scan
    -O                              # OS detection
    --osscan-guess                  # Aggressive OS guessing
    -sV                             # Service version detection
    -p "$SERVER_PORTS"              # Targeted server ports
    --script=smb-os-discovery,nbstat,ldap-rootdse  # Windows/DC detail scripts
    -T"$TIMING"                     # Timing template
    --min-hostgroup "$HOST_GROUP"   # Parallel host scanning
    --max-retries 2                 # Limit retries for speed
    -oX "$XML_OUT"                  # XML output
    -oG "$GREP_OUT"                 # Grepable output
    --no-stylesheet
)

# shellcheck disable=SC2086
"${NMAP_CMD[@]}" $TARGET_ARG

echo ""
echo "=== Deep Scan Complete ==="
echo "XML:  $XML_OUT"
echo "Grep: $GREP_OUT"
echo ""
echo "Next step: Convert to CSV with:"
echo "  python3 scripts/convert_to_csv.py"
echo "  python3 scripts/convert_to_csv.py --site $SITE_NAME --servers-only"
