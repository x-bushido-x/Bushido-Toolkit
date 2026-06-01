#!/usr/bin/env python3
"""
BushidoMap - Network Scanner
A powerful network scanning tool inspired by nmap
"""

import argparse
import sys
from colorama import Fore, Style, init

init(autoreset=True)

from scanner.port_scanner import PortScanner
from scanner.host_discovery import HostDiscovery
from scanner.os_detection import OSDetector
from scanner.vuln_search import VulnScanner, print_vulns
from scanner.exploit_reader import interactive_reader
from scanner.utils import parse_targets, parse_ports, print_banner
from scanner.output import OutputFormatter


def main():
    print_banner()

    parser = argparse.ArgumentParser(
        description='BushidoMap - Network Scanner',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python bushidomap.py -t 192.168.1.1 -p 1-1000
  python bushidomap.py -t 192.168.1.1 -p 80,443 -sV
  python bushidomap.py -t 192.168.1.1 -p 1-1000 -sV -O
  python bushidomap.py -t 192.168.1.1 -p 1-1000 -sV -sE          (service + exploit search)
  python bushidomap.py -t 192.168.1.1 -p 1-1000 -A               (all: sV + O + sE)
  python bushidomap.py -t 192.168.1.0/24 -p 22,80,443 -Pn
        """
    )

    # ── Target / ports ────────────────────────────────────────────────────────
    parser.add_argument('-t', '--target', required=True,
                        help='Target IP, hostname, range (192.168.1.1-10) or CIDR (192.168.1.0/24)')
    parser.add_argument('-p', '--ports', default='1-1000',
                        help='Ports to scan: 80,443 or 1-1000 (default: 1-1000)')

    # ── Scan types ────────────────────────────────────────────────────────────
    parser.add_argument('-sT', '--tcp-connect', action='store_true',
                        help='TCP Connect scan (default)')
    parser.add_argument('-sS', '--syn-scan', action='store_true',
                        help='SYN scan (requires root/admin)')
    parser.add_argument('-sU', '--udp-scan', action='store_true',
                        help='UDP scan')

    # ── Detection options ─────────────────────────────────────────────────────
    parser.add_argument('-sV', '--service-detection', action='store_true',
                        help='Detect service name and version on open ports')
    parser.add_argument('-O', '--os-detection', action='store_true',
                        help='Enable OS detection (TTL, banner, port heuristics)')
    parser.add_argument('-sE', '--exploit-search', action='store_true',
                        help='Search Exploit-DB for known vulnerabilities on detected services')
    parser.add_argument('-A', '--aggressive', action='store_true',
                        help='Aggressive mode: enables -sV, -O and -sE together')

    # ── Exploit-DB options ────────────────────────────────────────────────────
    parser.add_argument('--vuln-results', type=int, default=10, metavar='N',
                        help='Max exploit results per service (default: 10)')

    # ── Misc ──────────────────────────────────────────────────────────────────
    parser.add_argument('-Pn', '--skip-ping', action='store_true',
                        help='Skip host discovery, treat all hosts as up')
    parser.add_argument('-T', '--timing', type=int, choices=[0, 1, 2, 3, 4, 5],
                        default=3, help='Timing template 0-5 (default: 3 Normal)')
    parser.add_argument('-o', '--output', help='Save results to file (JSON)')
    parser.add_argument('--threads', type=int, default=100,
                        help='Number of threads (default: 100)')
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='Verbose output')

    args = parser.parse_args()

    # -A enables sV + O + sE
    if args.aggressive:
        args.service_detection = True
        args.os_detection      = True
        args.exploit_search    = True

    # -sE requires -sV (need version info to search meaningfully)
    if args.exploit_search and not args.service_detection:
        print(f"{Fore.YELLOW}[!] -sE requires -sV. Enabling service detection automatically.{Style.RESET_ALL}")
        args.service_detection = True

    # ── Parse targets / ports ─────────────────────────────────────────────────
    targets = parse_targets(args.target)
    ports   = parse_ports(args.ports)

    if not targets:
        print(f"{Fore.RED}[!] Error: Invalid target specification{Style.RESET_ALL}")
        sys.exit(1)
    if not ports:
        print(f"{Fore.RED}[!] Error: Invalid port specification{Style.RESET_ALL}")
        sys.exit(1)

    # Determine scan type
    if args.syn_scan:
        scan_type = 'syn'
    elif args.udp_scan:
        scan_type = 'udp'
    else:
        scan_type = 'connect'

    results = []

    # ── Host discovery ────────────────────────────────────────────────────────
    if not args.skip_ping:
        print(f"\n{Fore.CYAN}[*]{Style.RESET_ALL} Starting host discovery for {len(targets)} target(s)...")
        discovery   = HostDiscovery()
        alive_hosts = discovery.ping_sweep(targets, verbose=args.verbose)

        if not alive_hosts:
            print(f"\n{Fore.YELLOW}[!] No hosts appear to be up. Use -Pn to skip host discovery.{Style.RESET_ALL}")
            sys.exit(0)

        print(f"{Fore.GREEN}[+]{Style.RESET_ALL} Found {len(alive_hosts)} host(s) up")
        targets = alive_hosts

    # ── Scan summary ──────────────────────────────────────────────────────────
    print(f"\n{Fore.CYAN}[*]{Style.RESET_ALL} Scan type  : {scan_type.upper()}")
    print(f"{Fore.CYAN}[*]{Style.RESET_ALL} Targets    : {len(targets)}")
    print(f"{Fore.CYAN}[*]{Style.RESET_ALL} Ports      : {len(ports)}")
    print(f"{Fore.CYAN}[*]{Style.RESET_ALL} Timing     : T{args.timing}")
    if args.service_detection:
        print(f"{Fore.CYAN}[*]{Style.RESET_ALL} Service detection  : {Fore.GREEN}ON{Style.RESET_ALL}")
    if args.os_detection:
        print(f"{Fore.CYAN}[*]{Style.RESET_ALL} OS detection       : {Fore.GREEN}ON{Style.RESET_ALL}")
    if args.exploit_search:
        print(f"{Fore.CYAN}[*]{Style.RESET_ALL} Exploit-DB search  : {Fore.GREEN}ON{Style.RESET_ALL} (max {args.vuln_results} results/service)")

    # ── Initialise modules ────────────────────────────────────────────────────
    scanner = PortScanner(
        scan_type=scan_type,
        timing=args.timing,
        threads=args.threads,
        service_detection=args.service_detection,
        verbose=args.verbose
    )
    os_detector   = OSDetector()   if args.os_detection   else None
    vuln_scanner  = VulnScanner(max_results=args.vuln_results) if args.exploit_search else None

    # ── Per-target scan ───────────────────────────────────────────────────────
    for target in targets:
        print(f"\n{Fore.CYAN}[*]{Style.RESET_ALL} Scanning {target}...")
        result = scanner.scan(target, ports)

        # OS detection
        if os_detector:
            open_port_nums = [p['port'] for p in result['open_ports']]
            result['os']   = os_detector.detect(target, open_port_nums)

        # Exploit-DB vulnerability search
        if vuln_scanner:
            print(f"{Fore.CYAN}[*]{Style.RESET_ALL} Searching Exploit-DB for vulnerabilities...")
            result = vuln_scanner.scan_host(result)

        results.append(result)

        # ── Print port table ──────────────────────────────────────────────────
        print(f"\n{'═' * 70}")
        print(f"  {Fore.WHITE}Scan results for {Fore.YELLOW}{target}{Style.RESET_ALL}")
        print(f"{'═' * 70}")

        if result['open_ports']:
            result['open_ports'].sort(key=lambda x: x['port'])

            print(f"  {Fore.WHITE}{'PORT':<10} {'PROTO':<7} {'STATE':<8} {'SERVICE':<15} {'VERSION'}{Style.RESET_ALL}")
            print(f"  {'-'*9} {'-'*6} {'-'*7} {'-'*14} {'-'*28}")

            for port_info in result['open_ports']:
                port    = port_info['port']
                proto   = port_info.get('protocol', 'tcp')
                state   = port_info['state']
                service = port_info.get('service', 'unknown')
                version = port_info.get('version', '')
                vuln_count = len(port_info.get('vulns', []))

                vuln_tag = ''
                if args.exploit_search:
                    if vuln_count > 0:
                        vuln_tag = f"  {Fore.RED}[{vuln_count} exploit(s)]{Style.RESET_ALL}"
                    else:
                        vuln_tag = f"  {Fore.GREEN}[clean]{Style.RESET_ALL}"

                print(f"  {Fore.GREEN}{port:<10}{Style.RESET_ALL} {proto:<7} {state:<8} "
                      f"{Fore.CYAN}{service:<15}{Style.RESET_ALL} {version}{vuln_tag}")
        else:
            print(f"  {Fore.YELLOW}No open ports found in the scanned range{Style.RESET_ALL}")

        # ── OS detection output ───────────────────────────────────────────────
        if os_detector and 'os' in result:
            os_info = result['os']
            conf_color = {
                'high':   Fore.GREEN,
                'medium': Fore.YELLOW,
                'low':    Fore.RED,
            }.get(os_info['confidence'], Fore.WHITE)

            print(f"\n  {Fore.WHITE}OS Detection:{Style.RESET_ALL}")
            print(f"  {'─' * 45}")
            print(f"  Guess      : {Fore.YELLOW}{os_info['os_guess']}{Style.RESET_ALL}")
            print(f"  Confidence : {conf_color}{os_info['confidence']}{Style.RESET_ALL}")
            print(f"  Method     : {os_info['method']}")

        # ── Vulnerability details ─────────────────────────────────────────────
        if args.exploit_search:
            ports_with_vulns = [p for p in result['open_ports'] if p.get('vulns')]
            if ports_with_vulns:
                print(f"\n{'═' * 70}")
                print(f"  {Fore.RED}VULNERABILITY REPORT  {Fore.WHITE}— {target}{Style.RESET_ALL}")
                print(f"{'═' * 70}")
                for port_info in ports_with_vulns:
                    print_vulns(port_info)
            else:
                print(f"\n  {Fore.GREEN}[✔] No public exploits found for any detected service.{Style.RESET_ALL}")

        print(f"{'═' * 70}")

    # ── Save output ───────────────────────────────────────────────────────────
    if args.output:
        formatter = OutputFormatter()
        # Strip colorama objects before serialising
        formatter.save_json(results, args.output)
        print(f"\n{Fore.GREEN}[+]{Style.RESET_ALL} Results saved to {args.output}")

    print(f"\n{Fore.CYAN}[*]{Style.RESET_ALL} Scan complete!")

    # ── Interactive exploit reader ────────────────────────────────────────────
    if args.exploit_search:
        total_vulns = sum(
            len(p.get('vulns', []))
            for r in results
            for p in r.get('open_ports', [])
        )
        if total_vulns > 0:
            interactive_reader(results)


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n\n{Fore.YELLOW}[!] Scan interrupted by user{Style.RESET_ALL}")
        sys.exit(0)
    except PermissionError:
        print(f"\n{Fore.RED}[!] Error: This scan type requires root/administrator privileges{Style.RESET_ALL}")
        sys.exit(1)
    except Exception as e:
        print(f"\n{Fore.RED}[!] Error: {e}{Style.RESET_ALL}")
        sys.exit(1)
