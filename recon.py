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

# Spider the website for dynamic inputs (strictly in scope with rate limiting)
def spider_website(base_url, auto_sqlmap=False, delay=1):
    """
    Crawl a website for dynamic inputs, staying strictly in scope.
    Logs discovered inputs to a file.
    """
    log_and_print(f"[*] Starting spidering for {base_url} with {delay}s delay between requests")
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

            try:
                response = requests.get(url, timeout=5)
                soup = BeautifulSoup(response.text, "html.parser")

                # Process links in the page
                for link in soup.find_all("a", href=True):
                    full_url = urljoin(base_scope, link["href"])
                    if not full_url.startswith(base_scope):
                        continue  # Skip URLs outside the base domain
                    if full_url not in visited:
                        queue.append(full_url)

                    # Check for dynamic inputs
                    if "?" in full_url and full_url not in dynamic_inputs:
                        params = parse_qs(urlparse(full_url).query)
                        log_and_print(f"[+] Found dynamic input: {full_url}")
                        dynamic_inputs.add(full_url)
                        f.write(full_url + "\n")

                        # Run SQLMap if auto_sqlmap is enabled
                        if auto_sqlmap:
                            for param in params.keys():
                                run_sqlmap_on_parameter(full_url, param)

                # Rate limiting
                time.sleep(delay)

            except Exception as e:
                log_and_print(f"[!] Error spidering {url}: {e}", "error")

# Run SQLMap for SQL injection testing
def run_sqlmap_on_parameter(url, parameter):
    log_and_print(f"[+] Running SQLMap on parameter '{parameter}' in URL: {url}")
    try:
        sqlmap_cmd = [
            SQLMAP_PATH,
            "-u", f"{url}",
            "--data", f"{parameter}=test",
            "--batch",
            "--level=2",
            "--risk=2",
        ]
        log_and_print(f"[*] Running SQLMap command: {' '.join(sqlmap_cmd)}")
        result = subprocess.run(
            sqlmap_cmd,
            capture_output=True,
            text=True,
        )
        if result.returncode == 0:
            print(Fore.MAGENTA + "🔥 SQLMap Results: 🔥" + Style.RESET_ALL)
            print(result.stdout)
            log_and_print(f"[+] SQLMap output:\n{result.stdout}")
        else:
            log_and_print(f"[!] SQLMap failed: {result.stderr}", "error")
    except Exception as e:
        log_and_print(f"[!] Error running SQLMap on {url} with parameter {parameter}: {e}", "error")

# Sanitize domain input
def sanitize_domain(domain):
    """Remove URL scheme (http/https) from the domain."""
    if domain.startswith("http://") or domain.startswith("https://"):
        domain = domain.split("://")[1]
    domain = domain.rstrip("/")  # Remove trailing slash if present
    return domain

# Main script
def main():
    parser = argparse.ArgumentParser(description="Bug bounty recon script")
    parser.add_argument("domain", help="Target domain (e.g., example.com or https://example.com)")
    parser.add_argument(
        "--wordlist",
        help=f"Specify a custom wordlist (default: {DEFAULT_WORDLIST})",
        default=DEFAULT_WORDLIST,
    )
    parser.add_argument(
        "--auto-sqlmap",
        help="Automatically run SQLMap on discovered parameters (default: false)",
        action="store_true",
    )
    parser.add_argument(
        "--delay",
        help="Set delay (in seconds) between requests to avoid rate limiting (default: 1s)",
        type=int,
        default=1,
    )
    args = parser.parse_args()

    # Set wordlist
    wordlist = args.wordlist
    if not os.path.exists(wordlist):
        log_and_print(f"[!] Wordlist not found: {wordlist}", "error")
        return

    # Sanitize the domain
    domain = sanitize_domain(args.domain)

    # Spider the website
    url = f"https://{domain}" if args.domain.startswith("https://") else f"http://{domain}"
    spider_website(url, auto_sqlmap=args.auto_sqlmap, delay=args.delay)

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
