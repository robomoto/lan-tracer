#!/usr/bin/env python3
"""Convert nmap XML scan results to Lansweeper-compatible CSV files.

Uses only Python stdlib — no external dependencies required.
"""

import argparse
import csv
import os
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

# Ports that strongly indicate a server role
SERVER_PORTS = {
    22, 25, 53, 80, 88, 135, 139, 389, 443, 445, 636, 993, 995,
    1433, 1521, 3306, 3389, 5432, 5900, 5985, 5986, 6443,
    8080, 8443, 8728, 8729, 9090, 9200,
}

# OS strings that indicate a server
SERVER_OS_KEYWORDS = [
    "server", "linux", "freebsd", "esxi", "vmware", "ubuntu",
    "centos", "debian", "red hat", "suse", "oracle linux",
    "routeros", "mikrotik", "pfsense", "opnsense", "fortigate",
    "junos", "ios", "nx-os",
]

# Ports with strong server signal (weighted higher)
STRONG_SERVER_PORTS = {
    25, 53, 88, 135, 389, 445, 636, 1433, 1521, 3306, 5432,
    5985, 5986, 6443, 8728, 8729, 9200,
}

CSV_HEADERS = [
    "IP Address",
    "MAC Address",
    "Vendor",
    "Hostname",
    "OS",
    "OS Accuracy",
    "Open Ports",
    "Services",
    "Site",
    "Likely Server",
    "Server Indicators",
]


def parse_host(host_elem, site_name):
    """Parse a single <host> element from nmap XML."""
    record = {
        "IP Address": "",
        "MAC Address": "",
        "Vendor": "",
        "Hostname": "",
        "OS": "",
        "OS Accuracy": "",
        "Open Ports": "",
        "Services": "",
        "Site": site_name,
        "Likely Server": "No",
        "Server Indicators": "",
    }

    # Skip hosts that are down
    status = host_elem.find("status")
    if status is not None and status.get("state") != "up":
        return None

    # IP and MAC addresses
    for addr in host_elem.findall("address"):
        if addr.get("addrtype") == "ipv4":
            record["IP Address"] = addr.get("addr", "")
        elif addr.get("addrtype") == "ipv6":
            if not record["IP Address"]:
                record["IP Address"] = addr.get("addr", "")
        elif addr.get("addrtype") == "mac":
            record["MAC Address"] = addr.get("addr", "")
            record["Vendor"] = addr.get("vendor", "")

    # Hostname
    hostnames = host_elem.find("hostnames")
    if hostnames is not None:
        for hn in hostnames.findall("hostname"):
            name = hn.get("name", "")
            if name:
                record["Hostname"] = name
                break  # Use first hostname

    # OS detection
    os_elem = host_elem.find("os")
    if os_elem is not None:
        best_accuracy = 0
        for osmatch in os_elem.findall("osmatch"):
            accuracy = int(osmatch.get("accuracy", "0"))
            if accuracy > best_accuracy:
                best_accuracy = accuracy
                record["OS"] = osmatch.get("name", "")
                record["OS Accuracy"] = str(accuracy)

    # Ports and services
    ports_elem = host_elem.find("ports")
    open_ports = []
    services = []
    if ports_elem is not None:
        for port in ports_elem.findall("port"):
            state = port.find("state")
            if state is not None and state.get("state") == "open":
                port_id = port.get("portid", "")
                protocol = port.get("protocol", "tcp")
                open_ports.append(f"{port_id}/{protocol}")

                service = port.find("service")
                if service is not None:
                    svc_name = service.get("name", "")
                    svc_product = service.get("product", "")
                    svc_version = service.get("version", "")
                    svc_str = svc_name
                    if svc_product:
                        svc_str += f" ({svc_product}"
                        if svc_version:
                            svc_str += f" {svc_version}"
                        svc_str += ")"
                    services.append(f"{port_id}: {svc_str}")

    record["Open Ports"] = ", ".join(open_ports)
    record["Services"] = "; ".join(services)

    # SMB/NetBIOS script results
    host_script = host_elem.find("hostscript")
    if host_script is not None:
        for script in host_script.findall("script"):
            script_id = script.get("id", "")
            if script_id in ("smb-os-discovery", "nbstat"):
                output = script.get("output", "")
                # If we don't have a hostname yet, try to extract from NetBIOS
                if not record["Hostname"] and script_id == "nbstat":
                    for line in output.splitlines():
                        if "<unique>" in line.lower() and "<active>" in line.lower():
                            parts = line.strip().split()
                            if parts:
                                record["Hostname"] = parts[0]
                                break
                # If we don't have OS yet, try SMB discovery
                if not record["OS"] and script_id == "smb-os-discovery":
                    for line in output.splitlines():
                        if "OS:" in line:
                            record["OS"] = line.split("OS:", 1)[1].strip()
                            break

    # Server classification
    indicators = []
    open_port_numbers = set()
    for p in open_ports:
        try:
            open_port_numbers.add(int(p.split("/")[0]))
        except ValueError:
            pass

    # Check OS
    os_lower = record["OS"].lower()
    for keyword in SERVER_OS_KEYWORDS:
        if keyword in os_lower:
            # "Windows 10" without "Server" is likely a workstation
            if keyword == "server" or keyword not in ("linux", "freebsd"):
                indicators.append(f"OS: {keyword}")
            elif keyword in ("linux", "freebsd"):
                indicators.append(f"OS: {keyword}")
            break

    # Check ports
    strong_matches = open_port_numbers & STRONG_SERVER_PORTS
    if strong_matches:
        indicators.append(f"strong ports: {','.join(str(p) for p in sorted(strong_matches))}")

    server_port_matches = open_port_numbers & SERVER_PORTS
    if len(server_port_matches) >= 3:
        indicators.append(f"{len(server_port_matches)} server ports open")

    # Determine if likely server
    is_server = (
        len(indicators) >= 1
        and (len(strong_matches) >= 1 or len(server_port_matches) >= 3 or any("OS:" in i for i in indicators))
    )

    if is_server:
        record["Likely Server"] = "Yes"
        record["Server Indicators"] = "; ".join(indicators)

    return record


def parse_xml_file(xml_path, site_name):
    """Parse an nmap XML file and return list of host records."""
    records = []
    try:
        tree = ET.parse(xml_path)
        root = tree.getroot()
    except ET.ParseError as e:
        print(f"  Warning: Could not parse {xml_path}: {e}", file=sys.stderr)
        return records

    for host in root.findall("host"):
        record = parse_host(host, site_name)
        if record:
            records.append(record)

    return records


def find_xml_files(results_dir, site_filter=None):
    """Find all nmap XML files in results directory, grouped by site."""
    results_path = Path(results_dir)
    xml_files = {}

    if not results_path.exists():
        return xml_files

    for site_dir in sorted(results_path.iterdir()):
        if not site_dir.is_dir():
            continue
        site_name = site_dir.name
        if site_filter and site_name != site_filter:
            continue
        xmls = sorted(site_dir.glob("*.xml"))
        if xmls:
            xml_files[site_name] = xmls

    return xml_files


def write_csv(records, output_path):
    """Write records to a CSV file."""
    with open(output_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=CSV_HEADERS)
        writer.writeheader()
        writer.writerows(records)
    return len(records)


def main():
    parser = argparse.ArgumentParser(
        description="Convert nmap XML results to Lansweeper-compatible CSV"
    )
    parser.add_argument(
        "--results-dir",
        default=None,
        help="Results directory (default: results/ in project root)",
    )
    parser.add_argument(
        "--site",
        default=None,
        help="Filter to a specific site name",
    )
    parser.add_argument(
        "--servers-only",
        action="store_true",
        help="Only output servers_only.csv",
    )
    parser.add_argument(
        "--output-dir",
        default=None,
        help="Output directory for CSV files (default: results/)",
    )
    args = parser.parse_args()

    # Resolve directories
    project_dir = Path(__file__).resolve().parent.parent
    results_dir = Path(args.results_dir) if args.results_dir else project_dir / "results"
    output_dir = Path(args.output_dir) if args.output_dir else results_dir

    # Find XML files
    xml_files = find_xml_files(results_dir, args.site)
    if not xml_files:
        print(f"No XML files found in {results_dir}/")
        if args.site:
            print(f"  (filtered to site: {args.site})")
        sys.exit(1)

    # Parse all XML files
    all_records = []
    for site_name, xml_paths in xml_files.items():
        print(f"Processing site: {site_name}")
        for xml_path in xml_paths:
            print(f"  Parsing: {xml_path.name}")
            records = parse_xml_file(xml_path, site_name)
            print(f"    Found {len(records)} hosts")
            all_records.extend(records)

    # Deduplicate by IP (keep record with most data)
    seen_ips = {}
    for record in all_records:
        ip = record["IP Address"]
        if ip in seen_ips:
            existing = seen_ips[ip]
            # Keep the record with more information
            if len(record["Services"]) > len(existing["Services"]):
                seen_ips[ip] = record
            elif len(record["OS"]) > len(existing["OS"]):
                seen_ips[ip] = record
        else:
            seen_ips[ip] = record

    deduped = list(seen_ips.values())
    # Sort by IP
    deduped.sort(key=lambda r: tuple(int(o) for o in r["IP Address"].split(".") if o.isdigit()))

    servers = [r for r in deduped if r["Likely Server"] == "Yes"]

    # Write CSVs
    os.makedirs(output_dir, exist_ok=True)

    if not args.servers_only:
        all_path = output_dir / "all_devices.csv"
        count = write_csv(deduped, all_path)
        print(f"\nAll devices: {all_path} ({count} hosts)")

    servers_path = output_dir / "servers_only.csv"
    count = write_csv(servers, servers_path)
    print(f"Servers only: {servers_path} ({count} likely servers)")

    # Summary
    print(f"\n=== Summary ===")
    print(f"Total hosts:    {len(deduped)}")
    print(f"Likely servers: {len(servers)}")
    if deduped:
        print(f"Server ratio:   {len(servers)/len(deduped)*100:.1f}%")


if __name__ == "__main__":
    main()
