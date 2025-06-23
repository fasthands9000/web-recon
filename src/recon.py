#!/usr/bin/env python3
"""
recon_plus.py
--------------
Modular, single‑VM recon helper for private bug‑bounty work.

* Tag‑driven phases (`--scans sub,dir,js`, `--scans all`, or `--help-scans`).
* External binaries (ffuf, nuclei, gowitness, sslscan, etc.) auto‑detected.
* Spider output (`dynamic_inputs_burp.txt`) feeds downstream modules.
* Branch‑safe: gentle defaults (`-t 10`, spider delay 1 s) to avoid DoS.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os
import re
import shlex
import shutil
import socket
import subprocess
import sys
import tempfile
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path
from time import sleep
from typing import Iterable, List
from urllib.parse import urljoin, urlparse, urlunparse

import requests
from bs4 import BeautifulSoup
from colorama import Fore, Style, init

# ── constants ────────────────────────────────────────────────────────────────

FFUF = "/usr/bin/ffuf"
DEFAULT_WORDLIST = "/usr/share/wordlists/seclists/Discovery/Web-Content/raft-medium-words.txt"
DEFAULT_VHOST_WORDLIST = "/usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt"
DEFAULT_CODES = "200,301,302,401,403"
LOGFILE = "recon.log"
SEC_HEADERS = {
    "content-security-policy",
    "x-frame-options",
    "strict-transport-security",
    "x-xss-protection",
    "x-content-type-options",
}

init(autoreset=True)

# ── helpers ──────────────────────────────────────────────────────────────────

def colour(msg: str, lvl: int) -> str:
    return {
        logging.INFO: Fore.GREEN,
        logging.WARNING: Fore.YELLOW,
        logging.ERROR: Fore.RED,
    }.get(lvl, "") + msg + Style.RESET_ALL


def log(msg: str, lvl: int = logging.INFO) -> None:
    print(colour(msg, lvl))
    logging.log(lvl, msg)


def run(cmd: list[str], check: bool = False) -> subprocess.CompletedProcess[str]:
    """Run command with live output and unified logging."""
    log("$ " + " ".join(map(shlex.quote, cmd)))
    try:
        return subprocess.run(cmd, check=check)
    except KeyboardInterrupt:
        log("User cancelled – exiting.", logging.WARNING)
        sys.exit(130)


@dataclass
class Config:
    domain: str
    scheme: str
    wordlist: str
    vhost_wordlist: str
    codes: str
    threads: int
    delay: int
    scans: list[str]
    interactive: bool

    @property
    def root(self) -> str:  # convenience
        return f"{self.scheme}://{self.domain}"


# ── ffuf wrappers ────────────────────────────────────────────────────────────

def ffuf(url_tmpl: str, wordlist: str, cfg: Config, *extra: str) -> None:
    run([
        FFUF,
        "-u", url_tmpl,
        "-w", wordlist,
        "-t", str(cfg.threads),
        "-mc", cfg.codes,
        "-v",
        *extra,
    ])


# ── core phases ──────────────────────────────────────────────────────────────

def subdomain_scan(cfg: Config) -> None:
    log("[*] Sub‑domain enumeration")
    ffuf(f"{cfg.scheme}://FUZZ.{cfg.domain}", cfg.wordlist, cfg)


def dir_scan(cfg: Config) -> None:
    log("[*] Directory enumeration")
    ffuf(f"{cfg.root}/FUZZ", cfg.wordlist, cfg)


def vhost_scan(cfg: Config) -> None:
    log("[*] V‑host enumeration")
    try:
        ip = socket.gethostbyname(cfg.domain)
    except Exception as e:  # noqa: BLE001
        log(f"[!] DNS failed: {e}", logging.ERROR)
        return
    ffuf(
        f"http://{ip}/",
        cfg.vhost_wordlist,
        cfg,
        "-H", f"Host: FUZZ.{cfg.domain}",
        "-fs", "4242",  # hide default length
    )


def spider(cfg: Config, max_sites: int = 200) -> list[str]:
    log("[*] Spidering for parameterised URLs…")
    pending = {cfg.root}
    visited: set[str] = set()
    found: list[str] = []
    sess = requests.Session()

    while pending and len(visited) < max_sites:
        url = pending.pop()
        visited.add(url)
        try:
            r = sess.get(url, timeout=6)
            soup = BeautifulSoup(r.text, "html.parser")
            for tag in soup.find_all("a", href=True):
                new = urljoin(cfg.root, tag["href"])
                if new.startswith(cfg.root) and new not in visited:
                    pending.add(new)
                if "?" in new:
                    found.append(new)
                    log(f"    [+] {new}")
        except Exception as e:  # noqa: BLE001
            log(f"    [!] {e}", logging.WARNING)
    Path("dynamic_inputs_burp.txt").write_text("\n".join(found))
    return found


def header_scan(urls: Iterable[str], cfg: Config) -> None:
    log("[*] Header scan (HEAD requests)")

    def fetch(u: str):
        try:
            return u, requests.head(u, timeout=4).headers
        except Exception:
            return u, None

    with ThreadPoolExecutor(cfg.threads) as pool, open("headers.txt", "w") as fp:
        for url, hdr in pool.map(fetch, urls):
            if hdr:
                fp.write(f"{url}\n{json.dumps(dict(hdr), indent=2)}\n\n")


# ── optional modules ─────────────────────────────────────────────────────────

def linter_scan(urls: Iterable[str]) -> None:
    log("[*] Security‑header linter")
    for url in urls:
        try:
            hdr = requests.head(url, timeout=4).headers
            missing = SEC_HEADERS - {h.lower() for h in hdr}
            if missing:
                log(f"    [!] {url} missing: {', '.join(sorted(missing))}", logging.WARNING)
        except Exception:
            pass


def screenshot_scan(cfg: Config) -> None:
    tool = shutil.which("gowitness") or shutil.which("aquatone")
    if not tool:
        log("[!] gowitness/aquatone not found – skipping", logging.WARNING)
        return
    log("[*] Screenshot & tech fingerprint")
    if "gowitness" in tool:
        run([tool, "single", "-u", cfg.root])
    else:
        run([tool, "--url", cfg.root])


def js_secrets_scan(urls: Iterable[str], cfg: Config) -> None:
    log("[*] JS endpoint & secret grep")
    patt = re.compile(r"(?i)(api_key|secret|token|bearer)[:=]\s*[\'\"]?([A-Za-z0-9\-_]{8,})")
    sess = requests.Session()
    for u in urls:
        if u.endswith(".js"):
            try:
                r = sess.get(u, timeout=6)
                for m in patt.finditer(r.text):
                    log(f"    [+] {u}: {m.group(0)[:60]}…", logging.INFO)
            except Exception:
                pass


def tls_scan(cfg: Config) -> None:
    tool = shutil.which("sslscan") or shutil.which("sslyze")
    if not tool:
        log("[!] sslscan/sslyze not in PATH – skipping", logging.WARNING)
        return
    log("[*] TLS / cipher audit")
    if "sslscan" in tool:
        run([tool, cfg.domain])
    else:
        run([tool, "--regular", cfg.domain])


def takeover_scan(cfg: Config) -> None:
    tool = shutil.which("subjack")
    if not tool:
        log("[!] subjack not found – skipping takeover check", logging.WARNING)
        return
    log("[*] Sub‑domain takeover heuristics")
    out = Path(tempfile.mktemp())
    run([tool, "-d", cfg.domain, "-w", DEFAULT_VHOST_WORDLIST, "-o", str(out), "-ssl"])
    if out.exists():
        log(out.read_text())


def nuclei_scan(targets: Iterable[str]) -> None:
    tool = shutil.which("nuclei")
    if not tool:
        log("[!] nuclei not installed – skipping", logging.WARNING)
        return
    log("[*] Nuclei template run")
    with tempfile.NamedTemporaryFile("w", delete=False) as f:
        f.write("\n".join(targets))
    run([tool, "-l", f.name, "-severity", "medium,high,critical", "-silent"])


def cors_scan(urls: Iterable[str]) -> None:
    log("[*] CORS mis‑config probe")
    sess = requests.Session()
    evil = "https://evil.com"
    for u in urls:
        try:
            r = sess.get(u, headers={"Origin": evil}, timeout=4)
            if r.headers.get("Access-Control-Allow-Origin") in ("*", evil):
                log(f"    [!] Potential CORS issue at {u}", logging.WARNING)
        except Exception:
            pass


def diff_scan(urls: Iterable[str]) -> None:
    log("[*] Baseline diffing")
    sess = requests.Session()
    for u in urls:
        try:
            a = sess.get(u, timeout=4).text
            sleep(1)
            b = sess.get(u, timeout=4).text
            if hashlib.md5(a.encode()).hexdigest() != hashlib.md5(b.encode()).hexdigest():
                log(f"    [+] {u} response changed between requests", logging.INFO)
        except Exception:  # noqa: BLE001
            pass


def burp_blind_scan(urls: Iterable[str]) -> None:
    payload = os.environ.get("COLLABORATOR_PAYLOAD")
    if not payload:
        log("[!] Set COLLABORATOR_PAYLOAD env var to enable blind scans", logging.WARNING)
        return
    log("[*] Burp Collaborator hooks – injecting payload")
    sess = requests.Session()
    for u in urls:
        try:
            parts = list(urlparse(u))
            if "=" in parts[4]:
                parts[4] += f"&ping={payload}"
            else:
                parts[4] = f"ping={payload}"
            new = urlunparse(parts)
            sess.get(new, timeout=3)
        except Exception:
            pass


# ── tag map ─────────────────────────────────────────────────────────────────

SCAN_FUNCS = {
    "sub": subdomain_scan,
    "dir": dir_scan,
    "vhost": vhost_scan,
    "spider": spider,
    "headers": header_scan,
    # optionals
    "linter": linter_scan,
    "screenshot": screenshot_scan,
    "js": js_secrets_scan,
    "tls": tls_scan,
    "takeover": takeover_scan,
    "nuclei": nuclei_scan,
    "cors": cors_scan,
    "diff": diff_scan,
    "burp": burp_blind_scan,
}
BASIC_ORDER = ["sub", "dir", "vhost", "spider", "headers"]

# ── CLI & main ──────────────────────────────────────────────────────────────

def build_cfg() -> Config:
    parser = argparse.ArgumentParser(
        prog="recon_plus",
        description="Modular single‑VM recon helper. Use --help-scans to list tags.",
    )

    # positional
    parser.add_argument("domain", help="example.com or https://example.com")

    # flags
    parser.add_argument("-k", "--insecure", action="store_true", help="Use HTTP (skip TLS)")
    parser.add_argument("-w", "--wordlist", default=DEFAULT_WORDLIST)
    parser.add_argument("--vhost-wordlist", default=DEFAULT_VHOST_WORDLIST)
    parser.add_argument("--codes", default=DEFAULT_CODES, help="ffuf match codes")
    parser.add_argument("-t", "--threads", type=int, default=10)
    parser.add_argument("--delay", type=int, default=1, help="Spider delay seconds")
    parser.add_argument("--interactive", "-i", action="store_true", help="Prompt before each tag")

    # scan selection
    parser.add_argument(
        "--scans",
        default="basic",
        help="Comma‑sep tags, or 'all', or 'basic' (sub,dir,vhost,spider,headers)",
    )
    parser.add_argument("--help-scans", action="store_true", help="List all scan tags and exit")

    args = parser.parse_args()

    if args.help_scans:
        print("Available scan tags:")
        for tag in sorted(SCAN_FUNCS):
            print(f"  - {tag}")
        sys.exit(0)

    domain_url = args.domain if "://" in args.domain else f"https://{args.domain}"
    parsed = urlparse(domain_url)

    # determine which scans to run
    if args.scans == "all":
        selected = list(SCAN_FUNCS)
    elif args.scans == "basic":
        selected = BASIC_ORDER.copy()
    else:
        selected = [s.strip() for s in args.scans.split(",") if s.strip() in SCAN_FUNCS]

    return Config(
        domain=parsed.netloc or parsed.path,
        scheme="http" if args.insecure else "https",
        wordlist=args.wordlist,
        vhost_wordlist=args.vhost_wordlist,
        codes=args.codes,
        threads=args.threads,
        delay=args.delay,
        scans=selected,
        interactive=args.interactive,
    )


def ask(cfg: Config, tag: str) -> bool:
    if not cfg.interactive:
        return True
    resp = input(f"{Fore.CYAN}[?] Run {tag} scan? [Y/n]{Style.RESET_ALL} ").strip().lower()
    return resp != "n"


def main() -> None:
    logging.basicConfig(
        filename=LOGFILE,
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
    )

    cfg = build_cfg()
    log("[+] Recon started")

    cached_urls: list[str] = []

    # Keep execution order: BASIC_ORDER first, then any additional chosen tags
    ordered_tags = BASIC_ORDER + [t for t in cfg.scans if t not in BASIC_ORDER]

    for tag in ordered_tags:
        if tag not in cfg.scans:
            continue
        if not ask(cfg, tag):
            continue

        fn = SCAN_FUNCS[tag]
        try:
            if tag == "spider":
                cached_urls = fn(cfg)  # type: ignore[arg-type]
            elif tag in {"headers", "linter", "js", "cors", "diff", "burp"}:
                fn(cached_urls or [cfg.root], cfg) if tag in {"headers"} else fn(cached_urls or [cfg.root])
            elif tag == "nuclei":
                fn(cached_urls or [cfg.root])
            else:
                fn(cfg)
        except Exception as e:  # noqa: BLE001
            log(f"[!] {tag} scan error: {e}", logging.ERROR)

    log("[+] Recon finished")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        log("Interrupted – exiting.", logging.WARNING)
