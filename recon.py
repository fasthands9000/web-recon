import os
import requests
import socket
import argparse
import json
from dns.resolver import resolve
import subprocess
import logging
from datetime import datetime
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin, parse_qs
from colorama import Fore, Style, init
import time

# Initialize colorama for colorized output
init()

# Configure logging
log_file = "recon.log"
dynamic_inputs_file = "dynamic_inputs.txt"
logging.basicConfig(
    filename=log_file,
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)

# Default wordlist
DEFAULT_WORDLIST = "/usr/share/wordlists/SecLists/Discovery/Web-Content/raft-medium-words.txt"

# Path locations for ffuf and sqlmap
FFUF_PATH = "/opt/ffuf"
SQLMAP_PATH = "/opt/sqlmap/sqlmap.py"

# Real-time output and logging
def log_and_print(message, level="info"):
    if level == "info":
        print(Fore.GREEN + message + Style.RESET_ALL)
        logging.info(message)
    elif level == "error":
        print(Fore.RED + message + Style.RESET_ALL)
        logging.error(message)

# Handle user interruption
def handle_interrupt(stage_name):
    """
    Handle Ctrl+C interrupts during any phase.
    """
    print(Fore.YELLOW + f"\n🛑 {stage_name} interrupted! What would you like to do? " + Style.RESET_ALL)
    print("[s] Skip this phase")
    print("[x] Exit the script")
    print("[c] Continue this phase")
    choice = input("Enter your choice: ").strip().lower()
    if choice == "s":
        log_and_print(f"⏭️ {stage_name} phase skipped.", "info")
        return "skip"
    elif choice == "x":
        log_and_print(f"❌ {stage_name} phase exited by user.", "error")
        exit(0)
    elif choice == "c":
        log_and_print(f"🔄 Resuming {stage_name} phase...", "info")
        return "continue"
    return "continue"

# Prompt user before each phase
def user_prompt(stage_name):
    log_and_print(f"🚦 Starting {stage_name} phase.")
    print(f"\nOptions: [s] Skip | [x] Exit | [Enter] Continue")
    choice = input("What would you like to do? ").strip().lower()
    if choice == "s":
        log_and_print(f"⏭️ {stage_name} phase skipped.", "info")
        return False
    elif choice == "x":
        log_and_print(f"❌ {stage_name} phase exited by user.", "error")
        exit(0)
    return True

# Sanitize domain input
def sanitize_domain(domain):
    """Extract the domain without protocol (http/https)."""
    parsed_url = urlparse(domain)
    return parsed_url.netloc if parsed_url.netloc else domain

# Subdomain enumeration via crt.sh with retry logic
def get_subdomains(domain, retries=3):
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    for attempt in range(retries):
        try:
            log_and_print(f"🔍 Enumerating subdomains for {domain} (attempt {attempt + 1}/{retries})...")
            response = requests.get(url, timeout=10)
            if response.status_code == 200:
                data = response.json()
                subdomains = {entry["name_value"] for entry in data}
                log_and_print(f"🌐 Found {len(subdomains)} subdomains.")
                return subdomains
        except Exception as e:
            log_and_print(f"❌ Error fetching subdomains: {e}", "error")
        time.sleep(2)  # Wait before retrying
    return set()

# Resolve domain to IP
def resolve_domain(domain):
    try:
        log_and_print(f"🔗 Resolving {domain}...")
        ip = socket.gethostbyname(domain)
        log_and_print(f"✅ {domain} resolved to {ip}")
        return ip
    except socket.gaierror as e:
        log_and_print(f"❌ Failed to resolve domain {domain}: {e}", "error")
        return None

# Run Nmap to discover open ports
def scan_ports(ip):
    try:
        log_and_print(f"📡 Scanning ports for {ip}...")
        nmap_cmd = ["nmap", "-p-", "-T4", "-oG", "-", ip]
        result = subprocess.run(nmap_cmd, capture_output=True, text=True)
        if result.returncode != 0:
            log_and_print(f"❌ Nmap failed: {result.stderr}", "error")
            return []
        ports = []
        for line in result.stdout.splitlines():
            if "/open/" in line:
                ports.extend([x.split("/")[0] for x in line.split() if "/open/" in x])
        log_and_print(f"🔓 Open ports: {ports}")
        return ports
    except Exception as e:
        log_and_print(f"❌ Error running Nmap: {e}", "error")
        return []

# Spider the website for dynamic inputs
def spider_website(base_url, delay=1, max_sites=10):
    try:
        log_and_print(f"🕸️ Starting spidering for {base_url} with {delay}s delay...")
        visited = set()
        dynamic_inputs = set()
        queue = [base_url]
        site_count = 0

        parsed_base = urlparse(base_url)
        base_scope = f"{parsed_base.scheme}://{parsed_base.netloc}"

        with open(dynamic_inputs_file, "w") as f:
            while queue:
                if site_count >= max_sites:
                    log_and_print(f"🛑 Reached the maximum of {max_sites} sites. Moving to the next phase.")
                    break

                url = queue.pop(0)
                if url in visited:
                    continue
                visited.add(url)
                site_count += 1

                try:
                    response = requests.get(url, timeout=5)
                    soup = BeautifulSoup(response.text, "html.parser")

                    for link in soup.find_all("a", href=True):
                        full_url = urljoin(base_scope, link["href"])
                        if not full_url.startswith(base_scope):
                            continue
                        if full_url not in visited:
                            queue.append(full_url)

                        if "?" in full_url and full_url not in dynamic_inputs:
                            log_and_print(f"📝 Found dynamic input: {full_url}")
                            dynamic_inputs.add(full_url)
                            f.write(full_url + "\n")

                    time.sleep(delay)

                except KeyboardInterrupt:
                    action = handle_interrupt("Spidering")
                    if action == "skip":
                        return
                except Exception as e:
                    log_and_print(f"❌ Error fetching {url}: {e}", "error")

    except KeyboardInterrupt:
        action = handle_interrupt("Spidering")
        if action == "skip":
            return
    except Exception as e:
        log_and_print(f"❌ Error during spidering: {e}", "error")

# Run SQLMap for SQL injection testing
def run_sqlmap(base_url):
    try:
        log_and_print(f"🛠️ Starting SQLMap on {base_url}...")
        if not os.path.exists(SQLMAP_PATH):
            raise FileNotFoundError(f"SQLMap not found at {SQLMAP_PATH}")
        sqlmap_cmd = [SQLMAP_PATH, "-u", base_url, "--batch", "--level=2", "--risk=2"]
        result = subprocess.run(sqlmap_cmd, capture_output=True, text=True)
        if result.returncode == 0:
            log_and_print(f"🛡️ SQLMap results:\n{result.stdout}")
        else:
            log_and_print(f"❌ SQLMap failed: {result.stderr}", "error")
    except Exception as e:
        log_and_print(f"❌ Error running SQLMap: {e}", "error")

# Main script
def main():
    parser = argparse.ArgumentParser(description="Bug bounty recon script")
    parser.add_argument("domain", help="Target domain (e.g., example.com or https://example.com)")
    parser.add_argument("--wordlist", default=DEFAULT_WORDLIST, help="Custom wordlist path")
    parser.add_argument("--delay", type=int, default=1, help="Delay between requests (default: 1s)")
    args = parser.parse_args()

    domain = sanitize_domain(args.domain)

    # Stage 1: Subdomain Enumeration
    if user_prompt("Subdomain Enumeration"):
        subdomains = get_subdomains(domain)
        if subdomains:
            for sub in subdomains:
                log_and_print(f"🔹 Subdomain: {sub}")

    # Stage 2: Port Scanning
    if user_prompt("Port Scanning"):
        ip = resolve_domain(domain)
        if ip:
            scan_ports(ip)

    # Stage 3: Spidering
    if user_prompt("Spidering"):
        base_url = f"https://{domain}"
        spider_website(base_url, delay=args.delay, max_sites=10)

    # Stage 4: SQLMap Testing
    if user_prompt("SQLMap Testing"):
        base_url = f"https://{domain}"
        run_sqlmap(base_url)

if __name__ == "__main__":
    log_and_print("🔥 [*] Recon script started 🔥")
    try:
        main()
    except KeyboardInterrupt:
        handle_interrupt("Main Script")
    finally:
        log_and_print("🎉 Recon script completed! 🎉")
