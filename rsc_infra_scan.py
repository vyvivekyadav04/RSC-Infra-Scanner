#!/usr/bin/env python3
"""
Heuristic scanner: check which domains are likely using Next.js App Router / RSC-style infra.

- Input:  List.txt  (one domain or URL per line)
- Output: Clean formatted table with colored status marks.
- This DOES NOT exploit the CVE; it only fingerprints the stack.
"""

import argparse
import asyncio
import re
import sys
from dataclasses import dataclass, field
from typing import List, Optional, Tuple
from urllib.parse import urlparse

import aiohttp

LIST_FILE = "List.txt"
CONCURRENCY = 20
TIMEOUT = 8  # seconds

# ANSI colors
GREEN_MARK = "\033[92m[+]\033[0m"  # green
RED_MARK = "\033[91m[-]\033[0m"    # red

RSC_HTML_PATTERNS = [
    re.compile(r"(window|self)\.__next_f\s*=", re.I),
    re.compile(r"react-server-dom-webpack", re.I),
]

NEXT_HTML_HINTS = [
    re.compile(r'id=["\']__next["\']', re.I),
]

NEXT_HEADER_HINTS = [
    "x-nextjs-cache",
    "x-nextjs-matched-path",
    "x-nextjs-page",
    "x-nextjs-router-state-tree",
]


@dataclass
class ScanResult:
    domain: str
    url: str
    ok: bool
    score: int = 0
    signals: List[str] = field(default_factory=list)
    error: Optional[str] = None

    def format_output(self, verbose: bool = False) -> str:
        """Format output - clean table by default, CSV in verbose mode."""
        if verbose:
            # Original CSV format
            if not self.ok:
                status = RED_MARK
                return f"{self.domain},{status},ERROR,0,{self.error or ''}"
            
            detected = self.score >= 50
            status = GREEN_MARK if detected else RED_MARK
            detected_str = "yes" if detected else "no"
            sig_str = "; ".join(self.signals) if self.signals else ""
            return f"{self.domain},{status},{detected_str},{self.score},{sig_str}"
        else:
            # Clean table format (no signals column)
            if not self.ok:
                return f"{RED_MARK} {self.domain:<40} ERROR     {self.score:>3}  {self.error or 'request_failed'}"

            detected = self.score >= 50
            status = GREEN_MARK if detected else RED_MARK
            is_rsc_like = "yes" if detected else "no"
            
            return f"{status} {self.domain:<40} {is_rsc_like:<8} {self.score:>3}"


def normalize_target(line: str) -> Optional[Tuple[str, str]]:
    """
    Turn a line from List.txt into (domain, url).
    Accepts bare domains (example.com) or full URLs.
    """
    line = line.strip()
    if not line or line.startswith("#"):
        return None

    if "://" not in line:
        # bare domain
        domain = line.split("/")[0]
        url = f"https://{domain}/"
        return domain, url

    parsed = urlparse(line)
    if not parsed.netloc:
        return None
    domain = parsed.netloc
    scheme = parsed.scheme or "https"
    path = parsed.path or "/"
    url = f"{scheme}://{domain}{path}"
    return domain, url


async def fetch_once(session: aiohttp.ClientSession, url: str) -> Tuple[Optional[aiohttp.ClientResponse], Optional[str]]:
    try:
        async with session.get(
            url,
            timeout=TIMEOUT,
            allow_redirects=True,
        ) as resp:
            text = await resp.text(errors="ignore")
            resp._body_text = text  # stash text for reuse
            return resp, None
    except Exception as e:
        return None, str(e)


def analyze_response(result: ScanResult, resp: aiohttp.ClientResponse) -> None:
    """
    Assign score based on headers + HTML patterns.
    Threshold (>=50) => "likely Next.js RSC/App Router style infra".
    """
    text = getattr(resp, "_body_text", "") or ""
    headers = {k.lower(): v for k, v in resp.headers.items()}

    # 1) Strong HTML RSC signals
    for rx in RSC_HTML_PATTERNS:
        if rx.search(text):
            result.score += 60
            result.signals.append(f"HTML:{rx.pattern}")
            break

    # 2) Generic Next.js hints
    for rx in NEXT_HTML_HINTS:
        if rx.search(text):
            result.score += 20
            result.signals.append(f"HTML_HINT:{rx.pattern}")
            break

    # 3) Next.js-specific headers
    for h in NEXT_HEADER_HINTS:
        if h in headers:
            result.score += 25
            result.signals.append(f"HDR:{h}={headers[h]}")

    # 4) Content-Type hint
    ctype = headers.get("content-type", "")
    if "text/x-component" in ctype:
        result.score += 80
        result.signals.append(f"HDR:content-type={ctype}")

    # Cap score
    result.score = min(result.score, 100)


async def scan_target(semaphore: asyncio.Semaphore, session: aiohttp.ClientSession, domain: str, url: str) -> ScanResult:
    async with semaphore:
        result = ScanResult(domain=domain, url=url, ok=False)

        # Try HTTPS first; optionally fall back to HTTP if SSL fails.
        resp, err = await fetch_once(session, url)

        if resp is None and err and "SSL" in err.upper():
            # Try HTTP fallback if we started with HTTPS
            if url.startswith("https://"):
                http_url = "http://" + url[len("https://") :]
                resp, err = await fetch_once(session, http_url)
                if resp:
                    result.url = http_url

        if resp is None:
            result.ok = False
            result.error = err or "request_failed"
            return result

        result.ok = True
        analyze_response(result, resp)
        return result


def print_help():
    """Print help message."""
    help_text = f"""
RSC Infrastructure Scanner - CVE-2025-55182 / CVE-2025-66478 Detection

DESCRIPTION:
    Fingerprints domains for likely Next.js App Router / React Server Components (RSC) 
    infrastructure. This tool does NOT exploit vulnerabilities; it only performs passive 
    HTTP/HTML/header fingerprinting to identify targets that might be affected by 
    CVE-2025-55182 and CVE-2025-66478.

USAGE:
    python rsc_infra_scan.py [OPTIONS]

OPTIONS:
    -h, --help          Show this help message and exit
    -v, --verbose       Show verbose output in CSV format with all signal details
    -f, --file FILE     Specify input file (default: List.txt)

INPUT FILE FORMAT:
    Create a List.txt file (or use -f to specify another file) with one domain or URL per line.
    Lines starting with # are treated as comments.
    
    Example:
        example.com
        https://subdomain.example.org
        # This is a comment
        nextjs-demo.vercel.app

OUTPUT:
    By default, shows a clean table with:
        - Status (green [+] for detected, red [-] for not detected)
        - Domain name
        - is_rsc_like (yes/no)
        - Score (0-100)
    
    With -v flag, shows original CSV format:
        domain,status,is_rsc_like,score,signals_or_error

DETECTION:
    The scanner checks for:
    - window.__next_f (Next.js App Router / RSC runtime)
    - react-server-dom-webpack
    - id="__next" container
    - x-nextjs-* response headers
    - Content-Type: text/x-component
    
    A score >= 50 indicates likely RSC/Next.js infrastructure.

AFFECTED VERSIONS:
    - React: 19.0.0, 19.1.0, 19.1.1, 19.2.0
    - Next.js: 15.x and 16.x using the App Router

NOTE:
    This tool only identifies infrastructure that appears to use Next.js/RSC technology.
    It does NOT verify if a specific CVE is exploitable or if the target is running 
    a vulnerable version. Always verify vulnerability status through proper security 
    testing and vendor advisories.

LEGAL:
    Only scan systems that you own or have explicit written permission to test.
    This tool is for educational and research purposes only.
"""
    print(help_text)


async def main_async(verbose: bool = False, input_file: str = LIST_FILE):
    # Read list of domains
    try:
        with open(input_file, "r", encoding="utf-8") as f:
            raw_lines = f.readlines()
    except FileNotFoundError:
        print(f"[-] File not found: {input_file}", file=sys.stderr)
        sys.exit(1)

    targets: List[Tuple[str, str]] = []
    seen_domains = set()

    for line in raw_lines:
        norm = normalize_target(line)
        if not norm:
            continue
        domain, url = norm
        if domain in seen_domains:
            continue
        seen_domains.add(domain)
        targets.append((domain, url))

    if not targets:
        print("[-] No valid targets in input file", file=sys.stderr)
        sys.exit(1)

    if not verbose:
        print(f"\n{'='*100}")
        print(f"{'RSC Infrastructure Scanner - CVE-2025-55182 / CVE-2025-66478 Detection':^100}")
        print(f"{'='*100}\n")
        print(f"Scanning {len(targets)} target(s)...\n")

    semaphore = asyncio.Semaphore(CONCURRENCY)

    connector = aiohttp.TCPConnector(ssl=False)  # allow self-signed, etc.
    headers = {
        "User-Agent": "RSC-Infra-Scanner/1.1 (research; no-exploit)",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    }

    async with aiohttp.ClientSession(connector=connector, headers=headers) as session:
        tasks = [
            scan_target(semaphore, session, domain, url)
            for domain, url in targets
        ]
        results = await asyncio.gather(*tasks)

    # Print results
    if verbose:
        # CSV format (original)
        print("domain,status,is_rsc_like,score,signals_or_error")
        for r in results:
            print(r.format_output(verbose=True))
    else:
        # Clean table format
        print(f"{'Status':<4} {'Domain':<40} {'is_rsc_like':<12} {'Score':<8}")
        print("-" * 70)
        
        detected_count = 0
        for r in results:
            print(r.format_output(verbose=False))
            if r.ok and r.score >= 50:
                detected_count += 1
        
        # Summary
        print("\n" + "-" * 70)
        print(f"Summary: {detected_count}/{len(results)} targets detected as likely RSC/Next.js infrastructure")
        print("-" * 70 + "\n")


def main():
    parser = argparse.ArgumentParser(
        description="RSC Infrastructure Scanner for CVE-2025-55182 / CVE-2025-66478",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        add_help=False
    )
    
    parser.add_argument(
        "-h", "--help",
        action="store_true",
        help="Show help message and exit"
    )
    
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Show verbose output in CSV format with all signal details"
    )
    
    parser.add_argument(
        "-f", "--file",
        default=LIST_FILE,
        help=f"Specify input file (default: {LIST_FILE})"
    )
    
    args = parser.parse_args()
    
    if args.help:
        print_help()
        sys.exit(0)
    
    try:
        asyncio.run(main_async(verbose=args.verbose, input_file=args.file))
    except KeyboardInterrupt:
        print("\n[!] Interrupted", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()