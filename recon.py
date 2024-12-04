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
import time  # For rate limiting

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
SQLMAP_PATH = "/usr/bin/sqlmap"

# Real-time output and logging
def log_and_print(message, level="info"):
    if level == "info":
        print(Fore.GREEN + message + Style.RESET_ALL)
        logging.info(message)
    elif level == "error":
        print(Fore.RED + message + Style.RESET_ALL)
        logging.error(message)

# Subdomain enumeration via crt.sh
def get_subdomains(domain):
    try:
        log_and_print(f"🔍 {Fore.BLUE}Enumerating subdomains for {domain}...{Style.RESET_ALL}")
        response = requests.get(f"https://crt.sh/?q=%25.{domain}&output=json", timeout=10)
        if response.status_code == 200:
            data = response.json()
            subdomains = {entry["name_value"] for entry in data}
            log_and_print(f"🌐 {Fore.CYAN}Found {len(subdomains)} subdomains.{Style.RESET_ALL}")
            return subdomains
    except Exception as e:
        log_and_print(f"❌ {Fore.RED}Error fetching subdomains: {e}{Style.RESET_ALL}", "error")
    return set()

# Resolve subdomains to IPs
def resolve_subdomains(subdomains):
    resolved = {}
    for subdomain in subdomains:
        try:
            log_and_print(f"🔗 {Fore.YELLOW}Resolving {subdomain}...{Style.RESET_ALL}")
            answers = resolve(subdomain, "A")
            resolved[subdomain] = [answer.address for answer in answers]
            log_and_print(f"✅ {Fore.GREEN}{subdomain} resolved to {resolved[subdomain]}{Style.RESET_ALL}")
        except Exception as e:
            log_and_print(f"❌ {Fore.RED}Unable to resolve {subdomain}: {e}{Style.RESET_ALL}", "error")
    return resolved

# Run Nmap to discover open ports
def scan_ports(ip):
    try:
        log_and_print(f"📡 {Fore.BLUE}Scanning ports for {ip}...{Style.RESET_ALL}")
        nmap_cmd = ["nmap", "-p-", "-T4", "-oG", "-", ip]
        result = subprocess.run(nmap_cmd, capture_output=True, text=True)
        if result.returncode != 0:
            log_and_print(f"❌ {Fore.RED}Nmap failed: {result.stderr}{Style.RESET_ALL}", "error")
            return []
        ports = []
        for line in result.stdout.splitlines():
            if "/open/" in line:
                ports.extend([x.split("/")[0] for x in line.split() if "/open/" in x])
        log_and_print(f"🔓 {Fore.CYAN}Open ports: {ports}{Style.RESET_ALL}")
        return ports
    except Exception as e:
        log_and_print(f"❌ {Fore.RED}Error running Nmap: {e}{Style.RESET_ALL}", "error")
        return []

# Spider the website for dynamic inputs
def spider_website(base_url, delay=1):
    try:
        log_and_print(f"🕸️ {Fore.YELLOW}Starting spidering for {base_url} with {delay}s delay...{Style.RESET_ALL}")
        visited = set()
        dynamic_inputs = set()
        queue = [base_url]

        parsed_base = urlparse(base_url)
        base_scope = f"{parsed_base.scheme}://{parsed_base.netloc}"

        with open(dynamic_inputs_file, "w") as f:
            while queue:
                url = queue.pop(0)
                if url in visited:
                    continue
                visited.add(url)

                response = requests.get(url, timeout=5)
                soup = BeautifulSoup(response.text, "html.parser")

                for link in soup.find_all("a", href=True):
                    full_url = urljoin(base_scope, link["href"])
                    if not full_url.startswith(base_scope):
                        continue
                    if full_url not in visited:
                        queue.append(full_url)

                    if "?" in full_url and full_url not in dynamic_inputs:
                        log_and_print(f"📝 {Fore.CYAN}Found dynamic input: {full_url}{Style.RESET_ALL}")
                        dynamic_inputs.add(full_url)
                        f.write(full_url + "\n")

                time.sleep(delay)
    except KeyboardInterrupt:
        log_and_print(f"❌ {Fore.RED}Spidering interrupted by user.{Style.RESET_ALL}", "error")
    except Exception as e:
        log_and_print(f"❌ {Fore.RED}Error during spidering: {e}{Style.RESET_ALL}", "error")

# Perform parameter fuzzing with ffuf
def fuzz_parameters(url, wordlist):
    try:
        log_and_print(f"💥 {Fore.BLUE}Starting parameter fuzzing for {url}...{Style.RESET_ALL}")
        ffuf_cmd = [FFUF_PATH, "-u", f"{url}?FUZZ=test", "-w", wordlist, "-mc", "200,302"]
        result = subprocess.run(ffuf_cmd, capture_output=True, text=True)
        if result.returncode == 0:
            print(Fore.YELLOW + "✨ FFUF results: ✨" + Style.RESET_ALL)
            print(result.stdout)
            log_and_print(f"✨ {Fore.CYAN}Fuzzing results logged.{Style.RESET_ALL}")
        else:
            log_and_print(f"❌ {Fore.RED}FFUF failed: {result.stderr}{Style.RESET_ALL}", "error")
    except Exception as e:
        log_and_print(f"❌ {Fore.RED}Error during fuzzing: {e}{Style.RESET_ALL}", "error")

# Run SQLMap for SQL injection testing
def run_sqlmap(base_url):
    try:
        log_and_print(f"🛠️ {Fore.YELLOW}Running SQLMap on {base_url}...{Style.RESET_ALL}")
        sqlmap_cmd = [SQLMAP_PATH, "-u", base_url, "--batch", "--level=2", "--risk=2"]
        result = subprocess.run(sqlmap_cmd, capture_output=True, text=True)
        if result.returncode == 0:
            print(Fore.MAGENTA + "🔥 SQLMap Results: 🔥" + Style.RESET_ALL)
            print(result.stdout)
            log_and_print(f"🛡️ {Fore.CYAN}SQLMap results logged.{Style.RESET_ALL}")
        else:
            log_and_print(f"❌ {Fore.RED}SQLMap failed: {result.stderr}{Style.RESET_ALL}", "error")
    except Exception as e:
        log_and_print(f"❌ {Fore.RED}Error running SQLMap: {e}{Style.RESET_ALL}", "error")

# Main script
def main():
    parser = argparse.ArgumentParser(description="Bug bounty recon script")
    parser.add_argument("domain", help="Target domain (e.g., example.com or https://example.com)")
    parser.add_argument("--wordlist", default=DEFAULT_WORDLIST, help="Custom wordlist path")
    parser.add_argument("--delay", type=int, default=1, help="Delay between requests (default: 1s)")
    args = parser.parse_args()

    domain = args.domain

    # Stage 1: Subdomain Enumeration
    print(Fore.LIGHTCYAN_EX + "\n🚀 Stage 1: Subdomain Enumeration 🌐\n" + Style.RESET_ALL)
    subdomains = get_subdomains(domain)
    if subdomains:
        resolve_subdomains(subdomains)

    # Stage 2: Port Scanning
    print(Fore.LIGHTCYAN_EX + "\n📡 Stage 2: Port Scanning 🔍\n" + Style.RESET_ALL)
    try:
        ip = socket.gethostbyname(domain)
        scan_ports(ip)
    except Exception as e:
        log_and_print(f"❌ {Fore.RED}Failed to resolve or scan domain {domain}: {e}{Style.RESET_ALL}", "error")

    # Stage 3: Spidering
    print(Fore.LIGHTCYAN_EX + "\n🕸️ Stage 3: Spidering 🕷️\n" + Style.RESET_ALL)
    base_url = f"https://{domain}" if domain.startswith("https://") else f"http://{domain}"
    spider_website(base_url, delay=args.delay)

    # Stage 4: Parameter Fuzzing
    print(Fore.LIGHTCYAN_EX + "\n💥 Stage 4: Parameter Fuzzing 🔍\n" + Style.RESET_ALL)
    fuzz_parameters(base_url, args.wordlist)

    # Stage 5: SQLMap
    print(Fore.LIGHTCYAN_EX + "\n🛠️ Stage 5: SQLMap Testing 🔐\n" + Style.RESET_ALL)
    run_sqlmap(base_url)

if __name__ == "__main__":
    log_and_print("🔥 [*] Recon script started 🔥")
    try:
        main()
    except KeyboardInterrupt:
        log_and_print("❌ [!] Script interrupted by user.", "error")
    finally:
        log_and_print("🎉 [*] Recon script completed! 🎉")
