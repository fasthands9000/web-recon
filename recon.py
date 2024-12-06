import os
import requests
import socket
import argparse
import subprocess
import logging
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup
from colorama import Fore, Style, init

# Initialize colorama for colorized output
init()

# Configure logging
log_file = "recon.log"
dynamic_inputs_file = "dynamic_inputs_burp.txt"
logging.basicConfig(
    filename=log_file,
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)

# Default settings
DEFAULT_WORDLIST = "/usr/share/wordlists/SecLists/Discovery/Web-Content/raft-medium-words.txt"
DEFAULT_RESPONSE_CODES = "200,301,302,303,304,305,306,307"
DEFAULT_THREADS = 10

# Paths
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

# Display a warning at the start of the script
def display_warning():
    print(Fore.RED + "⚠️ WARNING: This tool is made for educational purposes only.")
    print("Use at your own risk. Unauthorized use against systems you don't own is illegal.")
    print("Stupid actions reap serious consequences." + Style.RESET_ALL)

# Handle user interruption gracefully
def handle_interrupt(stage_name):
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
    parsed_url = urlparse(domain)
    return parsed_url.netloc if parsed_url.netloc else domain

# Port Scanning with Nmap
def scan_ports(domain):
    try:
        log_and_print(f"📡 Scanning ports for {domain}...")
        nmap_cmd = ["nmap", "-p-", "-T4", "-oG", "-", domain]
        result = subprocess.run(nmap_cmd, capture_output=True, text=True)
        if result.returncode != 0:
            log_and_print(f"❌ Nmap failed: {result.stderr}", "error")
            return []

        open_ports = []
        for line in result.stdout.splitlines():
            if "/open/" in line:
                open_ports.extend([x.split("/")[0] for x in line.split() if "/open/" in x])

        if open_ports:
            log_and_print(f"🔓 Open ports: {open_ports}")
        else:
            log_and_print("❌ No open ports found.", "error")

        return open_ports
    except Exception as e:
        log_and_print(f"❌ Error during port scanning: {e}", "error")
        return []

# Subdomain Enumeration using ffuf
def enumerate_subdomains(domain, wordlist, response_codes, threads):
    try:
        log_and_print(f"🔍 Enumerating subdomains for {domain} using ffuf with {threads} threads...")
        ffuf_cmd = [
            FFUF_PATH,
            "-u", f"https://FUZZ.{domain}",
            "-w", wordlist,
            "-mc", response_codes,
            "-t", str(threads),
            "-v"
        ]
        subprocess.run(ffuf_cmd)  # Live output with no capture for visibility
    except KeyboardInterrupt:
        if handle_interrupt("Subdomain Enumeration") == "skip":
            return []

# Directory Enumeration using ffuf
def enumerate_directories(base_url, wordlist, response_codes, threads):
    try:
        log_and_print(f"🔍 Enumerating directories for {base_url} using ffuf with {threads} threads...")
        ffuf_cmd = [
            FFUF_PATH,
            "-u", f"{base_url}/FUZZ",
            "-w", wordlist,
            "-mc", response_codes,
            "-t", str(threads),
            "-v"
        ]
        subprocess.run(ffuf_cmd)  # Live output with no capture for visibility
    except KeyboardInterrupt:
        if handle_interrupt("Directory Enumeration") == "skip":
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
                except KeyboardInterrupt:
                    if handle_interrupt("Spidering") == "skip":
                        return
                except Exception as e:
                    log_and_print(f"❌ Error fetching {url}: {e}", "error")

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
    parser = argparse.ArgumentParser(
        description="Bug bounty recon script",
        formatter_class=argparse.RawTextHelpFormatter,
    )

    parser.add_argument("domain", help="Target domain (e.g., example.com or https://example.com)")
    parser.add_argument("--wordlist", default=DEFAULT_WORDLIST, help="Path to the wordlist (default: SecLists raft-medium-words.txt)")
    parser.add_argument("--response-codes", default=DEFAULT_RESPONSE_CODES, help="Comma-separated HTTP response codes to match")
    parser.add_argument("--threads", type=int, default=DEFAULT_THREADS, help="Number of threads to use for ffuf")
    parser.add_argument("--delay", type=int, default=1, help="Delay between requests in seconds")
    
    args = parser.parse_args()

    display_warning()
    domain = sanitize_domain(args.domain)

    # Stage 1: Port Scanning
    if user_prompt("Port Scanning"):
        scan_ports(domain)

    # Stage 2: Subdomain Enumeration
    if user_prompt("Subdomain Enumeration"):
        enumerate_subdomains(domain, args.wordlist, args.response_codes, args.threads)

    # Stage 3: Directory Enumeration
    if user_prompt("Directory Enumeration"):
        base_url = f"https://{domain}"
        enumerate_directories(base_url, args.wordlist, args.response_codes, args.threads)

    # Stage 4: Spidering
    if user_prompt("Spidering"):
        base_url = f"https://{domain}"
        spider_website(base_url, delay=args.delay)

    # Stage 5: SQLMap Testing
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
