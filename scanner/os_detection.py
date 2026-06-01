"""
OS Detection via TTL analysis, TCP fingerprinting, and banner grabbing
"""

import socket
import re
import subprocess
import platform
from typing import Dict, Optional


# TTL-based OS guessing
TTL_OS_MAP = [
    (range(0,   65),  'Network device / unknown'),
    (range(65,  69),  'Linux / Android'),
    (range(60,  65),  'macOS / iOS / FreeBSD'),
    (range(100, 130), 'Windows'),
    (range(240, 256), 'Cisco IOS / Solaris'),
]

# Banner patterns for OS detection
OS_BANNER_PATTERNS = [
    (r'Ubuntu',                     'Linux (Ubuntu)'),
    (r'Debian',                     'Linux (Debian)'),
    (r'CentOS|Red Hat|RHEL',        'Linux (RHEL/CentOS)'),
    (r'Fedora',                     'Linux (Fedora)'),
    (r'Alpine',                     'Linux (Alpine)'),
    (r'Kali',                       'Linux (Kali)'),
    (r'FreeBSD',                    'FreeBSD'),
    (r'OpenBSD',                    'OpenBSD'),
    (r'NetBSD',                     'NetBSD'),
    (r'Darwin',                     'macOS'),
    (r'Windows Server 2022',        'Windows Server 2022'),
    (r'Windows Server 2019',        'Windows Server 2019'),
    (r'Windows Server 2016',        'Windows Server 2016'),
    (r'Windows Server 2012',        'Windows Server 2012'),
    (r'Windows 11',                 'Windows 11'),
    (r'Windows 10',                 'Windows 10'),
    (r'Windows 7',                  'Windows 7'),
    (r'Microsoft',                  'Windows'),
    (r'IOS',                        'Cisco IOS'),
    (r'Junos',                      'Juniper JunOS'),
    (r'VMware',                     'VMware ESXi'),
]


class OSDetector:
    def __init__(self, timeout=3.0):
        self.timeout = timeout

    def detect(self, target: str, open_ports: list) -> Dict:
        """
        Attempt OS detection using multiple techniques.
        Returns a dict with 'os_guess' and 'confidence'.
        """
        result = {
            'os_guess': 'Unknown',
            'confidence': 'low',
            'method': ''
        }

        # 1. Banner-based detection (most reliable when it works)
        banner_os = self._banner_os(target, open_ports)
        if banner_os:
            result.update({'os_guess': banner_os, 'confidence': 'high', 'method': 'banner'})
            return result

        # 2. TTL-based detection
        ttl_os = self._ttl_os(target)
        if ttl_os:
            result.update({'os_guess': ttl_os, 'confidence': 'medium', 'method': 'ttl'})

        # 3. Port-based heuristics (refine the guess)
        port_os = self._port_heuristics(open_ports)
        if port_os:
            if result['confidence'] == 'low':
                result.update({'os_guess': port_os, 'confidence': 'low', 'method': 'port-heuristic'})
            else:
                # Combine TTL + port hints
                result['os_guess'] = f"{result['os_guess']} ({port_os})"

        return result

    # ── Banner-based ──────────────────────────────────────────────────────────
    def _banner_os(self, target: str, open_ports: list) -> Optional[str]:
        """Grab banners from open ports and look for OS strings"""
        probe_ports = [p for p in [22, 21, 25, 80, 443, 8080] if p in open_ports]

        for port in probe_ports:
            banner = self._grab_banner(target, port)
            if not banner:
                continue
            for pattern, os_name in OS_BANNER_PATTERNS:
                if re.search(pattern, banner, re.IGNORECASE):
                    return os_name

        return None

    def _grab_banner(self, target: str, port: int) -> str:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((target, port))

            if port in (80, 8080):
                sock.send(b'HEAD / HTTP/1.0\r\n\r\n')
            elif port == 22:
                pass  # SSH sends banner automatically
            else:
                sock.send(b'\r\n')

            banner = sock.recv(1024).decode('utf-8', errors='ignore')
            sock.close()
            return banner
        except Exception:
            return ''

    # ── TTL-based ─────────────────────────────────────────────────────────────
    def _ttl_os(self, target: str) -> Optional[str]:
        """Ping the target and read the TTL from the response"""
        ttl = self._get_ttl(target)
        if ttl is None:
            return None

        # Normalize TTL to initial value (64, 128, 255 are common starting points)
        if ttl <= 64:
            initial = 64
        elif ttl <= 128:
            initial = 128
        else:
            initial = 255

        ttl_os_map = {
            64:  'Linux / macOS / FreeBSD',
            128: 'Windows',
            255: 'Cisco IOS / Solaris / Network device',
        }
        return ttl_os_map.get(initial)

    def _get_ttl(self, target: str) -> Optional[int]:
        """Run a ping and extract the TTL value"""
        try:
            is_windows = platform.system().lower() == 'windows'
            cmd = ['ping', '-n', '1', '-w', '1000', target] if is_windows \
                  else ['ping', '-c', '1', '-W', '1', target]

            result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                    timeout=3)
            output = result.stdout.decode('utf-8', errors='ignore')

            # Windows: TTL=128   Linux: ttl=64
            match = re.search(r'[Tt][Tt][Ll]=(\d+)', output)
            if match:
                return int(match.group(1))
        except Exception:
            pass
        return None

    # ── Port heuristics ───────────────────────────────────────────────────────
    def _port_heuristics(self, open_ports: list) -> Optional[str]:
        """Guess OS from the combination of open ports"""
        ports = set(open_ports)

        # Windows-specific ports
        if ports & {135, 139, 445, 3389, 5985, 5986}:
            if 3389 in ports:
                return 'Windows (RDP enabled)'
            return 'Windows'

        # Linux/Unix indicators
        if 22 in ports and not ports & {135, 445}:
            if 80 in ports or 443 in ports:
                return 'Linux (web server)'
            return 'Linux / Unix'

        # Network device indicators
        if ports & {161, 162, 179, 520}:
            return 'Network device (router/switch)'

        return None
