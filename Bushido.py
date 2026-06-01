#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Bushido - Advanced Network Security Scanner
"""

import os, sys

# Force UTF-8 on Windows so the banner and colored output render correctly
os.environ.setdefault('PYTHONUTF8', '1')
if hasattr(sys.stdout, 'buffer'):
    import io
    try:
        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8',
                                      errors='replace', line_buffering=True)
        sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8',
                                      errors='replace', line_buffering=True)
    except Exception:
        pass
from colorama import Fore, Style, init

init(autoreset=True)

import argparse

# Suppress paramiko's verbose internal logging (connection resets during brute-force)
import logging
logging.getLogger('paramiko').setLevel(logging.CRITICAL)
logging.getLogger('paramiko.transport').setLevel(logging.CRITICAL)

from scanner.port_scanner    import PortScanner
from scanner.host_discovery  import HostDiscovery
from scanner.os_detection    import OSDetector
from scanner.vuln_search     import VulnScanner, print_vulns
from scanner.exploit_reader  import interactive_reader
from scanner.admin_finder    import AdminFinder, print_admin_results
from scanner.bruteforce      import (BruteForcer, print_brute_results,
                                     find_rockyou, load_wordlist,
                                     DEFAULT_USERNAMES, DEFAULT_PASSWORDS)
from scanner.hash_cracker    import (HashCracker, identify_hash,
                                     print_crack_results)
from scanner.sqli_scanner    import SQLiScanner, print_sqli_results
from scanner.utils           import parse_targets, parse_ports, print_banner, print_goodbye
from scanner.output          import OutputFormatter


# ─────────────────────────────────────────────────────────────────────────────
# Argument parser
# ─────────────────────────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog='Bushido',
        description='Bushido - Advanced Network Security Scanner',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  SCAN EXAMPLES
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  python Bushido.py -t 192.168.1.1 -p 1-1000
  python Bushido.py -t 192.168.1.1 -p 1-1000 -sV -O
  python Bushido.py -t 192.168.1.1 -p 1-1000 -A          (all: sV+O+sE)
  python Bushido.py -t 192.168.1.1 -p 80,443 --admin      (admin finder)
  python Bushido.py -t 192.168.1.1 -p 1-1000 -A --admin

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  BRUTE-FORCE EXAMPLES
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  python Bushido.py --brute ssh://192.168.1.1
  python Bushido.py --brute ftp://192.168.1.1:21
  python Bushido.py --brute http://192.168.1.1/admin --http-form
  python Bushido.py --brute ssh://192.168.1.1 -U users.txt -W rockyou.txt
  python Bushido.py --brute ssh://192.168.1.1 --rockyou

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  HASH CRACKING EXAMPLES
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  python Bushido.py --crack 5f4dcc3b5aa765d61d8327deb882cf99
  python Bushido.py --crack hashes.txt -W rockyou.txt
  python Bushido.py --crack 5f4dcc3b5aa765d61d8327deb882cf99 --hash-type MD5
  python Bushido.py --identify 5f4dcc3b5aa765d61d8327deb882cf99
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""
    )

    # ── Scan target ───────────────────────────────────────────────────────────
    scan = parser.add_argument_group('Scan Options')
    scan.add_argument('-t', '--target',
                      help='Target IP, hostname, range (192.168.1.1-10) or CIDR')
    scan.add_argument('-p', '--ports', default='1-1000',
                      help='Ports: 80,443 or 1-1000 (default: 1-1000)')
    scan.add_argument('-sT', '--tcp-connect', action='store_true',
                      help='TCP Connect scan (default)')
    scan.add_argument('-sS', '--syn-scan', action='store_true',
                      help='SYN scan (requires root/admin)')
    scan.add_argument('-sU', '--udp-scan', action='store_true',
                      help='UDP scan')
    scan.add_argument('-sV', '--service-detection', action='store_true',
                      help='Service and version detection')
    scan.add_argument('-O', '--os-detection', action='store_true',
                      help='OS detection')
    scan.add_argument('-sE', '--exploit-search', action='store_true',
                      help='Search Exploit-DB for vulnerabilities')
    scan.add_argument('-A', '--aggressive', action='store_true',
                      help='Aggressive: enables -sV -O -sE')
    scan.add_argument('--vuln-results', type=int, default=10, metavar='N',
                      help='Max exploit results per service (default: 10)')
    scan.add_argument('-Pn', '--skip-ping', action='store_true',
                      help='Skip host discovery')
    scan.add_argument('-T', '--timing', type=int, choices=range(6),
                      default=3, metavar='0-5',
                      help='Timing template 0-5 (default: 3)')
    scan.add_argument('--threads', type=int, default=100,
                      help='Scan threads (default: 100)')
    scan.add_argument('-o', '--output', help='Save scan results to JSON file')
    scan.add_argument('-v', '--verbose', action='store_true',
                      help='Verbose output')

    # ── Admin finder ──────────────────────────────────────────────────────────
    adm = parser.add_argument_group('Admin Path Finder')
    adm.add_argument('--admin', action='store_true',
                     help='Scan for admin/login panels on HTTP/HTTPS ports')
    adm.add_argument('--admin-port', type=int, default=None,
                     help='Specific port for admin scan (default: auto-detect)')
    adm.add_argument('--admin-paths', metavar='FILE',
                     help='Custom admin paths file (one path per line)')
    adm.add_argument('--admin-threads', type=int, default=30,
                     help='Admin finder threads (default: 30)')

    # ── Brute-force ───────────────────────────────────────────────────────────
    bf = parser.add_argument_group('Brute-Force (Hydra-style)')
    bf.add_argument('--brute', metavar='PROTO://HOST[:PORT][/PATH]',
                    help='Brute-force target. e.g. ssh://192.168.1.1  '
                         'ftp://host:21  http://host/login  https://host/wp-login.php')
    bf.add_argument('-U', '--userlist', metavar='FILE',
                    help='Username wordlist file')
    bf.add_argument('-W', '--wordlist', metavar='FILE',
                    help='Password wordlist file')
    bf.add_argument('--rockyou', action='store_true',
                    help='Use rockyou.txt as password list (auto-locate)')
    bf.add_argument('--username', metavar='USER',
                    help='Single username to try')
    bf.add_argument('--password', metavar='PASS',
                    help='Single password to try')
    bf.add_argument('--wordpress', action='store_true',
                    help='WordPress wp-login.php mode (auto-detects nonce+cookies, '
                         'verifies wordpress_logged_in_ cookie on success)')
    bf.add_argument('--http-form', action='store_true',
                    help='Use HTTP POST form login instead of Basic Auth')
    bf.add_argument('--user-field', default='username',
                    help='Form username field name (default: username)')
    bf.add_argument('--pass-field', default='password',
                    help='Form password field name (default: password)')
    bf.add_argument('--fail-string', default='',
                    help='String in response that indicates login FAILURE')
    bf.add_argument('--success-string', default='',
                    help='String in response that indicates login SUCCESS')
    bf.add_argument('--brute-threads', type=int, default=32,
                    help='Brute-force threads (default: 32)')
    bf.add_argument('--brute-timeout', type=float, default=8.0,
                    help='Connection timeout per attempt in seconds (default: 8.0)')
    bf.add_argument('--brute-delay', type=float, default=0.0,
                    help='Delay between attempts in seconds (default: 0)')
    bf.add_argument('--no-stop', action='store_true',
                    help='Continue after first found credential')
    bf.add_argument('--wordlist-limit', type=int, default=0,
                    help='Limit wordlist to first N entries (0 = no limit)')

    # ── Hash cracking ─────────────────────────────────────────────────────────
    hc = parser.add_argument_group('Hash Cracking (John-style)')
    hc.add_argument('--crack', metavar='HASH_OR_FILE',
                    help='Hash string or file containing hashes (one per line)')
    hc.add_argument('--identify', metavar='HASH',
                    help='Identify hash type without cracking')
    hc.add_argument('--hash-type', default='auto',
                    help='Hash type: auto, MD5, SHA1, SHA256, SHA512, '
                         'NTLM, bcrypt, MySQL41 (default: auto)')
    hc.add_argument('--crack-threads', type=int, default=8,
                    help='Hash cracking threads (default: 8)')

    # ── SQL Injection ─────────────────────────────────────────────────────────
    sq = parser.add_argument_group('SQL Injection Scanner (SQLMap-style)')
    sq.add_argument('--sqli', metavar='URL',
                    help='Test URL for SQL injection. Include parameters: '
                         'http://site.com/page?id=1')
    sq.add_argument('--sqli-param', metavar='PARAM',
                    help='Specific parameter to test (default: all)')
    sq.add_argument('--sqli-extract', action='store_true',
                    help='Extract DB version and database names if vulnerable')
    sq.add_argument('--sqli-timeout', type=float, default=10.0,
                    help='Request timeout in seconds (default: 10.0)')
    sq.add_argument('--sqli-threads', type=int, default=4,
                    help='Threads for parallel technique testing (default: 4)')

    return parser


# ─────────────────────────────────────────────────────────────────────────────
# Brute-force URL parser
# ─────────────────────────────────────────────────────────────────────────────

def parse_brute_target(spec: str):
    """
    Parse  proto://host[:port][/path]  into components.
    Returns (protocol, host, port, path)
    """
    import re
    m = re.match(
        r'^([\w]+)://'          # protocol
        r'([^:/]+)'             # host
        r'(?::(\d+))?'          # optional :port
        r'(/.*)?$',             # optional /path
        spec.strip()
    )
    if not m:
        return None, None, None, '/'

    proto = m.group(1).lower()
    host  = m.group(2)
    port  = int(m.group(3)) if m.group(3) else None
    path  = m.group(4) or '/'

    # Default ports
    default_ports = {
        'ssh': 22, 'ftp': 21, 'telnet': 23,
        'http': 80, 'https': 443,
        'mysql': 3306, 'postgresql': 5432,
        'smb': 445, 'rdp': 3389,
    }
    if port is None:
        port = default_ports.get(proto, 80)

    return proto, host, port, path


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────

def main():
    print_banner()
    parser = build_parser()

    # ── No arguments → show interactive menu instead of full help dump ────────
    if len(sys.argv) == 1:
        _show_menu(parser)
        return

    args = parser.parse_args()

    # ── Mode: identify hash ───────────────────────────────────────────────────
    if args.identify:
        types = identify_hash(args.identify)
        print(f"\n  Hash   : {Fore.WHITE}{args.identify}{Style.RESET_ALL}")
        print(f"  Type(s): {Fore.YELLOW}{', '.join(types)}{Style.RESET_ALL}\n")
        return

    # ── Mode: SQL injection scan ──────────────────────────────────────────────
    if args.sqli:
        _run_sqli(args)
        return

    # ── Mode: hash cracking ───────────────────────────────────────────────────
    if args.crack:
        _run_crack(args)
        return

    # ── Mode: brute-force ─────────────────────────────────────────────────────
    if args.brute:
        _run_brute(args)
        return

    # ── Mode: network scan (requires -t) ──────────────────────────────────────
    if not args.target:
        _show_menu(parser)
        return

    _run_scan(args)


def _show_menu(parser):
    """Show a clean interactive menu instead of the raw argparse help dump."""
    R  = Fore.RED
    W  = Fore.WHITE
    G  = Fore.GREEN + Style.BRIGHT   # hacker green — visible
    C  = Fore.CYAN
    Y  = Fore.YELLOW
    DM = Style.DIM
    B  = Style.BRIGHT
    RS = Style.RESET_ALL

    print(f"  {R}{'-' * 60}{RS}")
    print(f"  {W}{B}  BUSHIDO  {RS}{DM}-- AI Automated Red Team Toolkit{RS}")
    print(f"  {R}{'-' * 60}{RS}")
    print()
    print(f"  {R}{B}[1]{RS}  {W}Scan a target{RS}          {G}Port scan, service & OS detection{RS}")
    print(f"  {R}{B}[2]{RS}  {W}Brute-force{RS}             {G}SSH, FTP, HTTP, WordPress & more{RS}")
    print(f"  {R}{B}[3]{RS}  {W}Hash cracking{RS}           {G}MD5, SHA1, SHA256, NTLM, bcrypt...{RS}")
    print(f"  {R}{B}[4]{RS}  {W}Admin path finder{RS}       {G}Discover login panels on web targets{RS}")
    print(f"  {R}{B}[5]{RS}  {W}Vulnerability search{RS}    {G}Search Exploit-DB for known CVEs{RS}")
    print(f"  {R}{B}[6]{RS}  {W}SQL Injection{RS}           {G}Error, Boolean, Time-blind, UNION + WAF bypass{RS}")
    print()
    print(f"  {R}{'-' * 60}{RS}")
    print(f"  {W}[h]{RS}  {DM}Show full help & all options{RS}")
    print(f"  {W}[q]{RS}  {DM}Quit{RS}")
    print(f"  {R}{'-' * 60}{RS}")
    print()

    while True:
        try:
            choice = input(f"  {R}bushido>{RS} ").strip().lower()
        except (KeyboardInterrupt, EOFError):
            print_goodbye()
            sys.exit(0)

        if not choice:
            continue

        if choice in ('q', 'quit', 'exit'):
            print_goodbye()
            sys.exit(0)

        elif choice in ('h', 'help', '--help'):
            print()
            parser.print_help()
            print()

        elif choice == '1':
            print()
            print(f"  {W}{B}SCAN OPTIONS{RS}")
            print(f"  {R}{'-' * 58}{RS}")
            examples = [
                ("Basic scan",          "python Bushido.py -t 192.168.1.1 -p 1-1000"),
                ("Service detection",   "python Bushido.py -t 192.168.1.1 -p 1-1000 -sV"),
                ("OS detection",        "python Bushido.py -t 192.168.1.1 -p 1-1000 -sV -O"),
                ("Full aggressive",     "python Bushido.py -t 192.168.1.1 -p 1-1000 -A"),
                ("CIDR range",          "python Bushido.py -t 192.168.1.0/24 -p 22,80,443 -Pn"),
                ("Skip ping",           "python Bushido.py -t 192.168.1.1 -p 1-65535 -Pn -T4"),
                ("Save to file",        "python Bushido.py -t 192.168.1.1 -p 1-1000 -o out.json"),
            ]
            for label, cmd in examples:
                print(f"  {G}{label:<22}{RS}  {C}{cmd}{RS}")
            print()

        elif choice == '2':
            print()
            print(f"  {W}{B}BRUTE-FORCE OPTIONS{RS}")
            print(f"  {R}{'-' * 58}{RS}")
            examples = [
                ("SSH",                 "python Bushido.py --brute ssh://192.168.1.1 --rockyou"),
                ("FTP",                 "python Bushido.py --brute ftp://192.168.1.1 -U u.txt -W p.txt"),
                ("WordPress",           "python Bushido.py --brute https://site.com/wp-login.php -U u.txt -W p.txt"),
                ("HTTP form",           "python Bushido.py --brute http://site.com/login --http-form --fail-string 'Invalid'"),
                ("Single user",         "python Bushido.py --brute ssh://host --username admin --rockyou"),
                ("Limit wordlist",      "python Bushido.py --brute ssh://host -W rockyou.txt --wordlist-limit 10000"),
            ]
            for label, cmd in examples:
                print(f"  {G}{label:<22}{RS}  {C}{cmd}{RS}")
            print()

        elif choice == '3':
            print()
            print(f"  {W}{B}HASH CRACKING OPTIONS{RS}")
            print(f"  {R}{'-' * 58}{RS}")
            examples = [
                ("Identify hash",       "python Bushido.py --identify 5f4dcc3b5aa765d61d8327deb882cf99"),
                ("Crack MD5",           "python Bushido.py --crack 5f4dcc3b5aa765d61d8327deb882cf99 -W rockyou.txt"),
                ("Crack file",          "python Bushido.py --crack hashes.txt -W rockyou.txt"),
                ("Specify type",        "python Bushido.py --crack <hash> --hash-type SHA256 -W p.txt"),
                ("NTLM crack",          "python Bushido.py --crack <hash> --hash-type NTLM -W rockyou.txt"),
                ("bcrypt crack",        "python Bushido.py --crack '$2b$12$...' --hash-type bcrypt -W p.txt"),
            ]
            for label, cmd in examples:
                print(f"  {G}{label:<22}{RS}  {C}{cmd}{RS}")
            print()

        elif choice == '4':
            print()
            print(f"  {W}{B}ADMIN PATH FINDER{RS}")
            print(f"  {R}{'-' * 58}{RS}")
            examples = [
                ("Basic admin scan",    "python Bushido.py -t 192.168.1.1 -p 80 --admin"),
                ("HTTPS target",        "python Bushido.py -t site.com -p 443 --admin"),
                ("Custom paths",        "python Bushido.py -t site.com -p 80 --admin --admin-paths paths.txt"),
                ("Combined with scan",  "python Bushido.py -t site.com -p 1-1000 -sV --admin"),
            ]
            for label, cmd in examples:
                print(f"  {G}{label:<22}{RS}  {C}{cmd}{RS}")
            print()

        elif choice == '5':
            print()
            print(f"  {W}{B}VULNERABILITY SEARCH{RS}")
            print(f"  {R}{'-' * 58}{RS}")
            examples = [
                ("Scan + vuln search",  "python Bushido.py -t 192.168.1.1 -p 1-1000 -sV -sE"),
                ("Full aggressive",     "python Bushido.py -t 192.168.1.1 -p 1-1000 -A"),
                ("Limit results",       "python Bushido.py -t 192.168.1.1 -p 1-1000 -sV -sE --vuln-results 5"),
            ]
            for label, cmd in examples:
                print(f"  {G}{label:<22}{RS}  {C}{cmd}{RS}")
            print()

        elif choice == '6':
            print()
            print(f"  {W}{B}SQL INJECTION SCANNER{RS}")
            print(f"  {R}{'-' * 58}{RS}")
            print(f"  {Y}Techniques:{RS} Error-based, Boolean-blind, Time-based blind, UNION-based")
            print(f"  {Y}WAF bypass:{RS} Comment injection, case variation, URL encoding, whitespace")
            print()
            examples = [
                ("Basic scan",          "python Bushido.py --sqli 'http://site.com/page?id=1'"),
                ("Specific param",      "python Bushido.py --sqli 'http://site.com/page?id=1' --sqli-param id"),
                ("Extract DB info",     "python Bushido.py --sqli 'http://site.com/page?id=1' --sqli-extract"),
                ("Verbose output",      "python Bushido.py --sqli 'http://site.com/page?id=1' -v"),
                ("Custom timeout",      "python Bushido.py --sqli 'http://site.com/page?id=1' --sqli-timeout 15"),
                ("Root-me challenge",   "python Bushido.py --sqli 'http://challenge01.root-me.org/web-serveur/ch9/?id=1'"),
            ]
            for label, cmd in examples:
                print(f"  {G}{label:<22}{RS}  {C}{cmd}{RS}")
            print()

        else:
            print(f"  {Y}[?] Type 1-6 for options, h for full help, q to quit.{RS}")
            continue

        # After showing a section, re-display the mini menu
        print(f"  {R}{'-' * 60}{RS}")
        print(f"  {DM}[1] Scan  [2] Brute  [3] Hash  [4] Admin  [5] Vulns  [6] SQLi  [h] Help  [q] Quit{RS}")
        print(f"  {R}{'-' * 60}{RS}")
        print()


# ─────────────────────────────────────────────────────────────────────────────
# SQL Injection runner
# ─────────────────────────────────────────────────────────────────────────────

def _run_sqli(args):
    url = args.sqli.strip()

    # Ensure URL has a scheme
    if not url.startswith('http://') and not url.startswith('https://'):
        url = 'http://' + url

    # Warn if no parameters
    from scanner.sqli_scanner import extract_params
    params = extract_params(url)
    if not params:
        print(f"\n  {Fore.YELLOW}[!]{Style.RESET_ALL} No GET parameters found in URL.")
        print(f"  {Style.DIM}Add parameters like: {url}?id=1&name=test{Style.RESET_ALL}")
        print(f"  {Style.DIM}Or use --sqli-param to specify a parameter name.{Style.RESET_ALL}")
        # Still proceed — user may know what they're doing
        if not getattr(args, 'sqli_param', None):
            return

    custom_params = [args.sqli_param] if getattr(args, 'sqli_param', None) else None

    print(f"\n  {Fore.CYAN}[*]{Style.RESET_ALL} SQL Injection Scanner")
    print(f"  {Fore.CYAN}[*]{Style.RESET_ALL} Target  : {Fore.YELLOW}{url}{Style.RESET_ALL}")
    print(f"  {Fore.CYAN}[*]{Style.RESET_ALL} Params  : {Fore.YELLOW}"
          f"{', '.join(custom_params or list(params.keys()))}{Style.RESET_ALL}")
    print(f"  {Fore.CYAN}[*]{Style.RESET_ALL} Testing : Error-based, Boolean-blind, "
          f"Time-based blind, UNION-based")
    print(f"  {Fore.CYAN}[*]{Style.RESET_ALL} WAF bypass variants enabled")

    scanner = SQLiScanner(
        timeout=args.sqli_timeout,
        threads=args.sqli_threads,
        verbose=args.verbose,
        extract_data=args.sqli_extract,
    )

    results = scanner.scan(url, custom_params=custom_params)
    print_sqli_results(results)

    # Suggest brute-force if admin panel found
    if results['vulnerable']:
        print(f"  {Fore.RED}[!]{Style.RESET_ALL} Target is vulnerable to SQL injection.")
        print(f"  {Style.DIM}Consider running --admin to find login panels.{Style.RESET_ALL}")
        print(f"  {Style.DIM}Use --brute to attempt credential attacks.{Style.RESET_ALL}")


# ─────────────────────────────────────────────────────────────────────────────
# Hash cracking runner
# ─────────────────────────────────────────────────────────────────────────────

def _run_crack(args):
    # Load wordlist
    wordlist = _resolve_wordlist(args)
    if not wordlist:
        print(f"{Fore.RED}[!] No wordlist provided. Use -W <file> or --rockyou{Style.RESET_ALL}")
        sys.exit(1)

    # Load hashes
    hashes = []
    crack_input = args.crack.strip()
    if os.path.isfile(crack_input):
        with open(crack_input, 'r', errors='ignore') as f:
            hashes = [line.strip() for line in f if line.strip()]
        print(f"{Fore.CYAN}[*]{Style.RESET_ALL} Loaded {len(hashes)} hash(es) from {crack_input}")
    else:
        hashes = [crack_input]

    cracker = HashCracker(threads=args.crack_threads, verbose=args.verbose)
    results = cracker.crack_multiple(hashes, wordlist, hash_type=args.hash_type)
    print_crack_results(results)


# ─────────────────────────────────────────────────────────────────────────────
# Brute-force runner
# ─────────────────────────────────────────────────────────────────────────────

def _run_brute(args):
    proto, host, port, path = parse_brute_target(args.brute)
    if not proto:
        print(f"{Fore.RED}[!] Invalid brute-force target: {args.brute}{Style.RESET_ALL}")
        print(f"    Format: proto://host[:port][/path]")
        sys.exit(1)

    # ── Auto-detect WordPress ─────────────────────────────────────────────────
    # Trigger WordPress mode if: --wordpress flag, or path contains wp-login/wp-admin
    wp_paths = ('wp-login', 'wp-admin', 'wordpress')
    is_wordpress = (
        getattr(args, 'wordpress', False)
        or any(p in path.lower() for p in wp_paths)
    )

    # ── Build username list ───────────────────────────────────────────────────
    if args.username:
        usernames = [args.username]
    elif args.userlist:
        usernames = load_wordlist(args.userlist)
        if not usernames:
            print(f"{Fore.RED}[!] Username list is empty or could not be read.{Style.RESET_ALL}")
            sys.exit(1)
    else:
        usernames = DEFAULT_USERNAMES
        print(f"{Fore.YELLOW}[!]{Style.RESET_ALL} No username list. "
              f"Using {len(usernames)} built-in usernames.")

    # ── Resolve password source ───────────────────────────────────────────────
    password_file  = None
    passwords_list = []

    if args.password:
        passwords_list = [args.password]
    elif getattr(args, 'wordlist', None):
        password_file = args.wordlist
        # Validate file exists
        if not os.path.isfile(password_file):
            print(f"{Fore.RED}[!] Wordlist not found: {password_file}{Style.RESET_ALL}")
            sys.exit(1)
        print(f"{Fore.CYAN}[*]{Style.RESET_ALL} Password file: {password_file} "
              f"(streaming — no RAM limit)")
    elif getattr(args, 'rockyou', False):
        rpath = find_rockyou()
        if not rpath:
            print(f"{Fore.RED}[!] rockyou.txt not found. "
                  f"Specify path with -W{Style.RESET_ALL}")
            sys.exit(1)
        password_file = rpath
        print(f"{Fore.CYAN}[*]{Style.RESET_ALL} Using rockyou: {rpath} (streaming)")
    else:
        passwords_list = DEFAULT_PASSWORDS
        print(f"{Fore.YELLOW}[!]{Style.RESET_ALL} No password list. "
              f"Using {len(passwords_list)} built-in passwords.")

    # ── Check SSH dependency ──────────────────────────────────────────────────
    if proto == 'ssh':
        try:
            import paramiko
        except ImportError:
            print(f"{Fore.RED}[!] SSH brute-force requires paramiko: "
                  f"pip install paramiko{Style.RESET_ALL}")
            sys.exit(1)

    # ── Build HTTP options ────────────────────────────────────────────────────
    if is_wordpress:
        # WordPress always authenticates via /wp-login.php POST
        # /wp-admin just redirects to wp-login — never use basic auth for WP
        http_opts = {'mode': 'wordpress', 'path': '/wp-login.php'}
        print(f"{Fore.CYAN}[*]{Style.RESET_ALL} Mode: {Fore.RED}WordPress "
              f"(wp-login.php + cookie verification){Style.RESET_ALL}")
    elif args.http_form:
        http_opts = {
            'mode':           'form',
            'path':           path,
            'user_field':     args.user_field,
            'pass_field':     args.pass_field,
            'fail_string':    args.fail_string,
            'success_string': getattr(args, 'success_string', ''),
        }
    else:
        http_opts = {'mode': 'basic', 'path': path}

    # ── Run ───────────────────────────────────────────────────────────────────
    # stop_on_first logic:
    #   HTTP/WordPress: stop after first valid login (default) unless --no-stop
    #   SSH/FTP/other:  find ALL valid credentials unless --stop-first is set
    #   --no-stop flag always overrides to find everything
    if args.no_stop:
        stop_on_first = False
    elif proto in ('http', 'https'):
        stop_on_first = True   # web logins: one is enough
    else:
        stop_on_first = False  # SSH/FTP: find all valid users

    bf = BruteForcer(
        threads=args.brute_threads,
        timeout=args.brute_timeout,
        delay=args.brute_delay,
        stop_on_first=stop_on_first,
        verbose=args.verbose,
    )

    results = bf.run(
        proto, host, port,
        usernames, passwords_list,
        http_opts=http_opts,
        password_file=password_file,
        password_limit=args.wordlist_limit,
    )
    print_brute_results(results, proto, host, port)


# ─────────────────────────────────────────────────────────────────────────────
# Network scan runner
# ─────────────────────────────────────────────────────────────────────────────

def _run_scan(args):
    # -A enables sV + O + sE
    if args.aggressive:
        args.service_detection = True
        args.os_detection      = True
        args.exploit_search    = True

    if args.exploit_search and not args.service_detection:
        print(f"{Fore.YELLOW}[!] -sE requires -sV. Enabling service detection.{Style.RESET_ALL}")
        args.service_detection = True

    # ── Extract port from URL if user passed a full URL as target ────────────
    # e.g. http://host:8080/path  →  port 8080, http
    # e.g. https://host/path      →  port 443
    raw_target = args.target.strip()
    if '://' in raw_target:
        scheme = raw_target.split('://')[0].lower()
        after  = raw_target.split('://', 1)[1]
        host_port = after.split('/')[0]
        if ':' in host_port:
            # explicit port in URL
            url_port = int(host_port.split(':')[1])
            if args.ports == '1-1000':   # only override if user didn't specify
                args.ports = str(url_port)
        elif scheme == 'https' and args.ports == '1-1000':
            args.ports = '443'
        elif scheme == 'http' and args.ports == '1-1000':
            args.ports = '80'

    targets = parse_targets(args.target)
    ports   = parse_ports(args.ports)

    if not targets:
        print(f"{Fore.RED}[!] Invalid target: {args.target}{Style.RESET_ALL}")
        sys.exit(1)
    if not ports:
        print(f"{Fore.RED}[!] Invalid ports: {args.ports}{Style.RESET_ALL}")
        sys.exit(1)

    scan_type = ('syn' if args.syn_scan else
                 'udp' if args.udp_scan else 'connect')

    results = []

    # ── Host discovery ────────────────────────────────────────────────────────
    if not args.skip_ping:
        print(f"\n{Fore.CYAN}[*]{Style.RESET_ALL} Host discovery for {len(targets)} target(s)...")
        alive = HostDiscovery().ping_sweep(targets, verbose=args.verbose)
        if not alive:
            print(f"{Fore.YELLOW}[!] No hosts up. Use -Pn to skip discovery.{Style.RESET_ALL}")
            sys.exit(0)
        print(f"{Fore.GREEN}[+]{Style.RESET_ALL} {len(alive)} host(s) up")
        targets = alive

    # ── Summary ───────────────────────────────────────────────────────────────
    print(f"\n{Fore.CYAN}[*]{Style.RESET_ALL} Scan type : {scan_type.upper()}")
    print(f"{Fore.CYAN}[*]{Style.RESET_ALL} Targets   : {len(targets)}")
    print(f"{Fore.CYAN}[*]{Style.RESET_ALL} Ports     : {len(ports)}")
    print(f"{Fore.CYAN}[*]{Style.RESET_ALL} Timing    : T{args.timing}")
    if args.service_detection:
        print(f"{Fore.CYAN}[*]{Style.RESET_ALL} Service detection : {Fore.GREEN}ON{Style.RESET_ALL}")
    if args.os_detection:
        print(f"{Fore.CYAN}[*]{Style.RESET_ALL} OS detection      : {Fore.GREEN}ON{Style.RESET_ALL}")
    if args.exploit_search:
        print(f"{Fore.CYAN}[*]{Style.RESET_ALL} Exploit-DB search : {Fore.GREEN}ON{Style.RESET_ALL} "
              f"(max {args.vuln_results}/service)")
    if args.admin:
        print(f"{Fore.CYAN}[*]{Style.RESET_ALL} Admin finder      : {Fore.GREEN}ON{Style.RESET_ALL}")

    # ── Init modules ──────────────────────────────────────────────────────────
    scanner     = PortScanner(scan_type=scan_type, timing=args.timing,
                              threads=args.threads,
                              service_detection=args.service_detection,
                              verbose=args.verbose)
    os_det      = OSDetector()   if args.os_detection   else None

    if args.exploit_search:
        # Check if pyxploitdb is available before starting
        from scanner.vuln_search import _PYXPLOITDB_AVAILABLE
        if not _PYXPLOITDB_AVAILABLE:
            print(f"{Fore.YELLOW}[!]{Style.RESET_ALL} pyxploitdb not installed — "
                  f"Exploit-DB search disabled.")
            print(f"    {Style.DIM}Fix: pip install pyxploitdb{Style.RESET_ALL}")
            args.exploit_search = False
            vuln_scan = None
        else:
            vuln_scan = VulnScanner(max_results=args.vuln_results)
    else:
        vuln_scan = None

    # Load custom admin paths
    custom_admin_paths = []
    if args.admin_paths and os.path.isfile(args.admin_paths):
        with open(args.admin_paths) as f:
            custom_admin_paths = [l.strip() for l in f if l.strip()]

    admin_finder = AdminFinder(threads=args.admin_threads,
                               custom_paths=custom_admin_paths) \
                   if args.admin else None

    # ── Per-target scan ───────────────────────────────────────────────────────
    for target in targets:
        print(f"\n{Fore.CYAN}[*]{Style.RESET_ALL} Scanning {Fore.YELLOW}{target}{Style.RESET_ALL}...")
        result = scanner.scan(target, ports)

        if os_det:
            open_nums      = [p['port'] for p in result['open_ports']]
            result['os']   = os_det.detect(target, open_nums)

        if vuln_scan:
            print(f"{Fore.CYAN}[*]{Style.RESET_ALL} Searching Exploit-DB...")
            result = vuln_scan.scan_host(result)

        results.append(result)

        # ── Port table ────────────────────────────────────────────────────────
        print(f"\n{'═' * 72}")
        print(f"  {Fore.WHITE}Results for {Fore.YELLOW}{target}{Style.RESET_ALL}")
        print(f"{'═' * 72}")

        if result['open_ports']:
            result['open_ports'].sort(key=lambda x: x['port'])
            print(f"  {Fore.WHITE}{'PORT':<10} {'PROTO':<7} {'STATE':<8} "
                  f"{'SERVICE':<15} {'VERSION'}{Style.RESET_ALL}")
            print(f"  {'-'*9} {'-'*6} {'-'*7} {'-'*14} {'-'*28}")

            for pi in result['open_ports']:
                port    = pi['port']
                proto   = pi.get('protocol', 'tcp')
                state   = pi['state']
                service = pi.get('service', 'unknown')
                version = pi.get('version', '')
                vc      = len(pi.get('vulns', []))

                vtag = ''
                if args.exploit_search:
                    vtag = (f"  {Fore.RED}[{vc} exploit(s)]{Style.RESET_ALL}"
                            if vc else f"  {Fore.GREEN}[clean]{Style.RESET_ALL}")

                print(f"  {Fore.GREEN}{port:<10}{Style.RESET_ALL} {proto:<7} {state:<8} "
                      f"{Fore.CYAN}{service:<15}{Style.RESET_ALL} {version}{vtag}")
        else:
            print(f"  {Fore.YELLOW}No open ports found.{Style.RESET_ALL}")

        # ── OS output ─────────────────────────────────────────────────────────
        if os_det and 'os' in result:
            oi = result['os']
            cc = {'high': Fore.GREEN, 'medium': Fore.YELLOW,
                  'low': Fore.RED}.get(oi['confidence'], Fore.WHITE)
            print(f"\n  {Fore.WHITE}OS Detection:{Style.RESET_ALL}")
            print(f"  {'-'*45}")
            print(f"  Guess      : {Fore.YELLOW}{oi['os_guess']}{Style.RESET_ALL}")
            print(f"  Confidence : {cc}{oi['confidence']}{Style.RESET_ALL}")
            print(f"  Method     : {oi['method']}")

        # ── Vuln report ───────────────────────────────────────────────────────
        if args.exploit_search:
            pwv = [p for p in result['open_ports'] if p.get('vulns')]
            if pwv:
                print(f"\n{'═' * 72}")
                print(f"  {Fore.RED}VULNERABILITY REPORT{Style.RESET_ALL}  — {target}")
                print(f"{'═' * 72}")
                for pi in pwv:
                    print_vulns(pi)
            else:
                print(f"\n  {Fore.GREEN}[✔] No public exploits found.{Style.RESET_ALL}")

        # ── Admin finder ──────────────────────────────────────────────────────
        if admin_finder:
            open_ports_list = [p['port'] for p in result['open_ports']]

            # Determine which ports to run the admin finder on
            if args.admin_port:
                # User explicitly specified a port
                http_ports = [args.admin_port]
            else:
                # Scan ALL open ports found by the port scanner.
                # The admin finder itself will detect whether each port
                # responds to HTTP — non-HTTP ports will simply return
                # no results and be skipped cleanly.
                http_ports = open_ports_list if open_ports_list else [80]

            for hport in http_ports:
                # Treat port 443, 8443, 9443 as HTTPS; everything else as HTTP
                use_ssl = hport in (443, 8443, 9443, 4443)
                print(f"\n{Fore.CYAN}[*]{Style.RESET_ALL} Admin finder on "
                      f"{'https' if use_ssl else 'http'}://{target}:{hport} ...")
                admin_results = admin_finder.scan(target, hport, use_ssl)
                result.setdefault('admin_paths', {})[hport] = admin_results
                # Only print results if something was found
                if admin_results:
                    print_admin_results(target, hport, admin_results)
                else:
                    print(f"  {Fore.GREEN}[✔]{Style.RESET_ALL} "
                          f"No admin panels on port {hport}.")

        print(f"{'═' * 72}")

    # ── Save output ───────────────────────────────────────────────────────────
    if args.output:
        OutputFormatter().save_json(results, args.output)
        print(f"\n{Fore.GREEN}[+]{Style.RESET_ALL} Results saved to {args.output}")

    print(f"\n{Fore.CYAN}[*]{Style.RESET_ALL} Scan complete!")

    # ── Interactive exploit reader ────────────────────────────────────────────
    if args.exploit_search:
        total_vulns = sum(len(p.get('vulns', []))
                          for r in results
                          for p in r.get('open_ports', []))
        if total_vulns > 0:
            interactive_reader(results)


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _resolve_wordlist(args) -> list:
    """Resolve password wordlist from args (used by hash cracker only)."""
    limit = getattr(args, 'wordlist_limit', 0)

    if getattr(args, 'wordlist', None):
        wl = load_wordlist(args.wordlist, limit)
        print(f"{Fore.CYAN}[*]{Style.RESET_ALL} Loaded {len(wl):,} passwords from {args.wordlist}")
        return wl

    if getattr(args, 'rockyou', False):
        path = find_rockyou()
        if path:
            wl = load_wordlist(path, limit)
            print(f"{Fore.CYAN}[*]{Style.RESET_ALL} Loaded {len(wl):,} passwords from {path}")
            return wl
        else:
            print(f"{Fore.RED}[!] rockyou.txt not found. "
                  f"Download it or specify path with -W{Style.RESET_ALL}")
            print(f"    Common location: /usr/share/wordlists/rockyou.txt")
            sys.exit(1)

    return []


# ─────────────────────────────────────────────────────────────────────────────

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n\n{Fore.YELLOW}[!] Interrupted by user{Style.RESET_ALL}")
        sys.exit(0)
    except PermissionError:
        print(f"\n{Fore.RED}[!] Requires root/administrator privileges{Style.RESET_ALL}")
        sys.exit(1)
    except Exception as e:
        print(f"\n{Fore.RED}[!] Error: {e}{Style.RESET_ALL}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
