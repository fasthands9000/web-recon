import os
import requests
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
headers_output_file = "headers.txt"
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
FFUF_PATH = "/usr/bin/ffuf"

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

# Scan headers for the found endpoints
def scan_headers(endpoints):
    try:
        log_and_print(f"🔍 Scanning headers for endpoints...")
        with open(headers_output_file, "w") as f:
            for url in endpoints:
                try:
                    response = requests.head(url, timeout=5)
                    headers = response.headers
                    log_and_print(f"📋 Headers for {url}: {headers}")
                    f.write(f"Headers for {url}:\n{headers}\n\n")
                except Exception as e:
                    log_and_print(f"❌ Failed to fetch headers for {url}: {e}", "error")
    except Exception as e:
        log_and_print(f"❌ Error during header scanning: {e}", "error")

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

    # Stage 1: Subdomain Enumeration
    if user_prompt("Subdomain Enumeration"):
        enumerate_subdomains(domain, args.wordlist, args.response_codes, args.threads)

    # Stage 2: Directory Enumeration
    if user_prompt("Directory Enumeration"):
        base_url = f"https://{domain}"
        enumerate_directories(base_url, args.wordlist, args.response_codes, args.threads)

    # Stage 3: Spidering
    if user_prompt("Spidering"):
        base_url = f"https://{domain}"
        spider_website(base_url, delay=args.delay)

    # Stage 4: Header Scanning
    if user_prompt("Header Scanning"):
        base_url = f"https://{domain}"
        endpoints = [base_url]  # Replace with a list of discovered URLs if available
        scan_headers(endpoints)

if __name__ == "__main__":
    log_and_print("🔥 [*] Recon script started 🔥")
    try:
        main()
    except KeyboardInterrupt:
        handle_interrupt("Main Script")
    finally:
        log_and_print("🎉 Recon script completed! 🎉")
