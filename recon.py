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

# Default wordlist
DEFAULT_WORDLIST = "/usr/share/wordlists/SecLists/Discovery/Web-Content/raft-medium-words.txt"

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
        nmap_cmd = ["nmap", "-p-", "-T4", "-oG", "-", ip]
        log_and_print(f"[*] Running Nmap command: {' '.join(nmap_cmd)}")
        result = subprocess.run(
            nmap_cmd,
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            log_and_print(f"[!] Nmap failed: {result.stderr}", "error")
            return []
        ports = []
        for line in result.stdout.splitlines():
            if "/open/" in line:
                ports.extend([x.split("/")[0] for x in line.split() if "/open/" in x])
        log_and_print(f"[+] Open ports on {ip}: {ports}")
        return ports
    except Exception as e:
        log_and_print(f"[!] Error running Nmap on {ip}: {e}", "error")
        return []

# Perform parameter fuzzing with ffuf
def fuzz_parameters(url, wordlist):
    log_and_print(f"[+] Starting parameter fuzzing for {url}")
    try:
        ffuf_cmd = [
            "ffuf",
            "-u", f"{url}?FUZZ=test",
            "-w", wordlist,
            "-mc", "200,302",  # Match successful responses
        ]
        log_and_print(f"[*] Running ffuf command: {' '.join(ffuf_cmd)}")
        result = subprocess.run(
            ffuf_cmd,
            capture_output=True,
            text=True,
        )
        if result.returncode == 0:
            log_and_print(f"[+] Fuzzing results:\n{result.stdout}")
            return True  # Indicate valid dynamic inputs found
        else:
            log_and_print(f"[!] FFUF failed: {result.stderr}", "error")
            return False
    except Exception as e:
        log_and_print(f"[!] Error during fuzzing for {url}: {e}", "error")
        return False

# Run SQLMap for SQL injection testing
def run_sqlmap(url):
    log_and_print(f"[+] Running SQLMap on {url}")
    try:
        sqlmap_cmd = ["sqlmap", "-u", url, "--batch", "--level=2", "--risk=2"]
        log_and_print(f"[*] Running SQLMap command: {' '.join(sqlmap_cmd)}")
        result = subprocess.run(
            sqlmap_cmd,
            capture_output=True,
            text=True,
        )
        if result.returncode == 0:
            log_and_print(f"[+] SQLMap output:\n{result.stdout}")
        else:
            log_and_print(f"[!] SQLMap failed: {result.stderr}", "error")
    except Exception as e:
        log_and_print(f"[!] Error running SQLMap on {url}: {e}", "error")

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

# Sanitize domain input
def sanitize_domain(domain):
    """Remove URL scheme (http/https) from the domain."""
    if domain.startswith("http://") or domain.startswith("https://"):
        domain = domain.split("://")[1]
    domain = domain.rstrip("/")  # Remove trailing slash if present
    return domain

def main():
    parser = argparse.ArgumentParser(description="Bug bounty recon script")
    parser.add_argument("domain", help="Target domain (e.g., example.com or https://example.com)")
    parser.add_argument(
        "--wordlist",
        help=f"Specify a custom wordlist (default: {DEFAULT_WORDLIST})",
        default=DEFAULT_WORDLIST,
    )
    args = parser.parse_args()

    # Set wordlist
    wordlist = args.wordlist
    if not os.path.exists(wordlist):
        log_and_print(f"[!] Wordlist not found: {wordlist}", "error")
        return

    # Sanitize the domain
    domain = sanitize_domain(args.domain)

    # Prompt for subdomain enumeration
    enumerate_subdomains = input("Do you want to enumerate subdomains? (yes/no): ").strip().lower()
    if enumerate_subdomains in ["yes", "y"]:
        subdomains = get_subdomains(domain)
        if subdomains:
            resolved = resolve_subdomains(subdomains)
            log_and_print(f"[+] Subdomain enumeration completed. Resolved {len(resolved)} subdomains.")
    else:
        log_and_print("[*] Skipping subdomain enumeration.")

    # Proceed with the main domain
    log_and_print(f"[*] Proceeding with the main domain: {domain}")
    try:
        ip = socket.gethostbyname(domain)
    except socket.gaierror as e:
        log_and_print(f"[!] Failed to resolve {domain}: {e}", "error")
        return

    ports = scan_ports(ip)

    # Perform fuzzing and SQLMap testing
    url = f"https://{domain}" if args.domain.startswith("https://") else f"http://{domain}"
    if fuzz_parameters(url, wordlist):
        run_sqlmap(url)

    # Create Burp Suite import file for the main domain
    create_burp_file({domain: ([ip], ports)})

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
