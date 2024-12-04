import os
import requests
import socket
import argparse
import json
from dns.resolver import resolve
import subprocess
import logging
from datetime import datetime

# Configure logging
log_file = "recon.log"
logging.basicConfig(
    filename=log_file,
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)

# Real-time output and logging
def log_and_print(message, level="info"):
    print(message)
    if level == "info":
        logging.info(message)
    elif level == "error":
        logging.error(message)

# Subdomain enumeration via crt.sh
def get_subdomains(domain):
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    try:
        log_and_print(f"[*] Enumerating subdomains for {domain}")
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            data = response.json()
            subdomains = {entry["name_value"] for entry in data}
            log_and_print(f"[+] Found {len(subdomains)} subdomains.")
            return subdomains
    except Exception as e:
        log_and_print(f"[!] Error fetching subdomains: {e}", "error")
    return set()

# Resolve subdomains to IPs
def resolve_subdomains(subdomains):
    resolved = {}
    for subdomain in subdomains:
        try:
            log_and_print(f"[*] Resolving {subdomain}")
            answers = resolve(subdomain, "A")
            resolved[subdomain] = [answer.address for answer in answers]
            log_and_print(f"[+] {subdomain} resolved to {resolved[subdomain]}")
        except Exception as e:
            log_and_print(f"[!] Unable to resolve {subdomain}: {e}", "error")
    return resolved

# Run Nmap to discover open ports
def scan_ports(ip):
    try:
        log_and_print(f"[*] Scanning ports for {ip}")
        result = subprocess.run(
            ["nmap", "-p-", "-T3", "-oG", "-vv", ip],
            capture_output=True,
            text=True,
        )
        ports = []
        for line in result.stdout.splitlines():
            if "/open/" in line:
                ports.extend([x.split("/")[0] for x in line.split() if "/open/" in x])
        log_and_print(f"[+] Open ports on {ip}: {ports}")
        return ports
    except Exception as e:
        log_and_print(f"[!] Error running nmap on {ip}: {e}", "error")
        return []

# Create Burp import file
def create_burp_file(targets):
    try:
        log_and_print("[*] Creating Burp Suite import file...")
        with open("burp_import.json", "w") as f:
            data = [{"host": host, "ip": ips, "ports": ports} for host, (ips, ports) in targets.items()]
            json.dump(data, f, indent=4)
        log_and_print(f"[+] Burp Suite import file created: burp_import.json")
    except Exception as e:
        log_and_print(f"[!] Error creating Burp import file: {e}", "error")

# Fuzz parameters (optional integration with ffuf)
def fuzz_parameters(url):
    log_and_print(f"[+] Starting parameter fuzzing for {url}")
    try:
        subprocess.run(["/opt/ffuf", "-u", f"{url}?FUZZ=test", "-w", "/usr/share/wordlists/SecLists/Web-Content/raft-medium-words.txt", "-mc", "200,302"])
    except Exception as e:
        log_and_print(f"[!] Error fuzzing parameters: {e}", "error")

def main():
    parser = argparse.ArgumentParser(description="Bug bounty recon script")
    parser.add_argument("domain", help="Target domain")
    args = parser.parse_args()

    # Enumerate subdomains
    subdomains = get_subdomains(args.domain)

    # Resolve subdomains to IPs
    resolved = resolve_subdomains(subdomains)

    # Scan ports for each IP
    targets = {}
    for subdomain, ips in resolved.items():
        for ip in ips:
            ports = scan_ports(ip)
            if ports:
                targets[subdomain] = (ips, ports)

    # Create Burp Suite import file
    create_burp_file(targets)

    # Optional: Parameter fuzzing
    for subdomain in targets:
        fuzz_parameters(f"http://{subdomain}")

if __name__ == "__main__":
    log_and_print("[*] Recon script started")
    try:
        main()
    except KeyboardInterrupt:
        log_and_print("[!] Script interrupted by user", "error")
    except Exception as e:
        log_and_print(f"[!] An unexpected error occurred: {e}", "error")
    finally:
        log_and_print("[*] Recon script completed")
