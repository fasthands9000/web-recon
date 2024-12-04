import os
import requests
import socket
import argparse
import json
from dns.resolver import resolve
import subprocess

# Define constants
BURP_FILE = "burp_import.json"

# Subdomain enumeration via crt.sh
def get_subdomains(domain):
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    try:
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            data = response.json()
            subdomains = {entry["name_value"] for entry in data}
            return subdomains
    except Exception as e:
        print(f"[!] Error fetching subdomains: {e}")
    return set()

# Resolve subdomains to IPs
def resolve_subdomains(subdomains):
    resolved = {}
    for subdomain in subdomains:
        try:
            answers = resolve(subdomain, "A")
            resolved[subdomain] = [answer.address for answer in answers]
        except Exception as e:
            print(f"[!] Unable to resolve {subdomain}: {e}")
    return resolved

# Run Nmap to discover open ports
def scan_ports(ip):
    try:
        result = subprocess.run(
            ["nmap", "-p-", "-T4", "-oG", "-", ip],
            capture_output=True,
            text=True
        )
        ports = []
        for line in result.stdout.splitlines():
            if "/open/" in line:
                ports.extend([x.split("/")[0] for x in line.split() if "/open/" in x])
        return ports
    except Exception as e:
        print(f"[!] Error running nmap: {e}")
        return []

# Create Burp import file
def create_burp_file(targets):
    try:
        with open(BURP_FILE, "w") as f:
            data = [{"host": host, "ip": ips, "ports": ports} for host, (ips, ports) in targets.items()]
            json.dump(data, f, indent=4)
        print(f"[+] Burp Suite import file created: {BURP_FILE}")
    except Exception as e:
        print(f"[!] Error creating Burp import file: {e}")

# Fuzz parameters (optional integration with ffuf)
def fuzz_parameters(url):
    print(f"[+] Starting parameter fuzzing for {url}")
    try:
        subprocess.run(["ffuf", "-u", f"{url}?FUZZ=test", "-w", "/path/to/wordlist.txt", "-mc", "200,302"])
    except Exception as e:
        print(f"[!] Error fuzzing parameters: {e}")

def main():
    parser = argparse.ArgumentParser(description="Bug bounty recon script")
    parser.add_argument("domain", help="Target domain")
    args = parser.parse_args()

    # Enumerate subdomains
    print("[*] Enumerating subdomains...")
    subdomains = get_subdomains(args.domain)
    print(f"[+] Found {len(subdomains)} subdomains.")

    # Resolve subdomains to IPs
    print("[*] Resolving subdomains...")
    resolved = resolve_subdomains(subdomains)
    print(f"[+] Resolved {len(resolved)} subdomains.")

    # Scan ports for each IP
    print("[*] Scanning ports...")
    targets = {}
    for subdomain, ips in resolved.items():
        for ip in ips:
            ports = scan_ports(ip)
            targets[subdomain] = (ips, ports)

    # Create Burp Suite import file
    create_burp_file(targets)

    # Optional: Parameter fuzzing
    for subdomain in targets:
        fuzz_parameters(f"http://{subdomain}")

if __name__ == "__main__":
    main()
