"""
Admin path / login panel detector
Crawls common admin URLs on HTTP/HTTPS services.

DESIGN PRINCIPLE — DEFAULT DENY:
  Only report a path as "found" when there is POSITIVE PROOF it exists:
  - 200 OK  → page exists and is accessible
  - 401     → exists but requires authentication (login panel!)
  - 403     → exists but access denied (panel exists, just locked)

  301/302 redirects are followed ONCE. If the final response is 200/401/403
  it counts. If the redirect goes to a completely different host (e.g.
  HTTP→HTTPS redirect of the root domain), it is SKIPPED — that means the
  path doesn't exist, the server just redirects everything.
"""

import socket
import ssl
import re
import concurrent.futures
from typing import List, Dict, Optional
from colorama import Fore, Style

# ── Common admin/login paths ──────────────────────────────────────────────────
ADMIN_PATHS = [
    # Generic login
    '/admin', '/admin/', '/admin/login', '/admin/login.php',
    '/administrator', '/administrator/', '/administrator/index.php',
    '/login', '/login.php', '/login.html', '/login.aspx',
    '/signin', '/sign-in', '/auth', '/auth/login',
    '/user/login', '/users/login', '/account/login',
    '/panel', '/panel/', '/controlpanel',
    '/dashboard', '/dashboard/', '/manage', '/management',
    '/backend', '/backend/', '/secure', '/secure/login',
    '/portal', '/portal/login', '/webadmin', '/siteadmin',
    # WordPress
    '/wp-admin', '/wp-admin/', '/wp-login.php',
    # Joomla
    '/administrator/index.php', '/joomla/administrator',
    # Drupal
    '/user', '/user/login', '/admin/user/login',
    # phpMyAdmin
    '/phpmyadmin', '/phpmyadmin/', '/pma', '/pma/',
    '/phpMyAdmin', '/phpMyAdmin/', '/mysql', '/mysqladmin',
    # cPanel / Plesk / WHM
    '/cpanel', '/whm', '/plesk', '/webmail',
    # Common CMS
    '/magento/admin', '/shop/admin', '/store/admin',
    '/typo3', '/typo3/index.php',
    # API / config
    '/api/admin', '/api/login', '/api/auth',
    '/config', '/config.php', '/setup', '/install',
    # Misc
    '/manager', '/manager/html', '/tomcat/manager',
    '/jenkins', '/jenkins/login', '/gitlab/users/sign_in',
    '/.env', '/server-status', '/server-info',
]

# Only these final status codes count as "found"
REAL_HITS = {200, 401, 403}


def _ssl_ctx():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _raw_get(host: str, port: int, path: str,
             use_ssl: bool, timeout: float) -> tuple:
    """
    Send a GET request. Returns (status_code, headers_dict, body_snippet).
    Returns (-1, {}, '') on error.
    """
    try:
        raw = socket.create_connection((host, port), timeout=timeout)
        sock = _ssl_ctx().wrap_socket(raw, server_hostname=host) if use_ssl else raw

        req = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            f"AppleWebKit/537.36 Chrome/120.0 Safari/537.36\r\n"
            f"Accept: text/html,*/*\r\n"
            f"Connection: close\r\n\r\n"
        ).encode()

        sock.sendall(req)

        data = b''
        while len(data) < 16384:
            chunk = sock.recv(4096)
            if not chunk:
                break
            data += chunk
            if b'\r\n\r\n' in data:
                break
        sock.close()

        text = data.decode('utf-8', errors='ignore')
        first = text.split('\r\n')[0]
        m = re.match(r'HTTP/[\d.]+ (\d+)', first)
        status = int(m.group(1)) if m else -1

        headers = {}
        hdr_sec = text.split('\r\n\r\n')[0] if '\r\n\r\n' in text else text
        for line in hdr_sec.split('\r\n')[1:]:
            if ':' in line:
                k, _, v = line.partition(':')
                headers[k.strip().lower()] = v.strip()

        body = text.split('\r\n\r\n', 1)[1] if '\r\n\r\n' in text else ''
        return status, headers, body

    except Exception:
        return -1, {}, ''


def _probe_path(target: str, port: int, path: str,
                use_ssl: bool, timeout: float) -> Optional[Dict]:
    """
    Probe a single path. Follows one redirect if needed.
    Returns a result dict only for REAL_HITS (200, 401, 403).
    Returns None for everything else.
    """
    status, headers, body = _raw_get(target, port, path, use_ssl, timeout)

    if status == -1:
        return None

    # ── Follow one redirect ───────────────────────────────────────────────
    if status in (301, 302, 303, 307, 308):
        location = headers.get('location', '')
        if not location:
            return None

        # Parse the redirect target
        loc = location.strip()

        # If it redirects to a completely different host → skip
        # (this is the HTTP→HTTPS whole-site redirect pattern)
        if loc.startswith('http://') or loc.startswith('https://'):
            import urllib.parse
            parsed = urllib.parse.urlparse(loc)
            redir_host = parsed.hostname or ''
            redir_port = parsed.port or (443 if parsed.scheme == 'https' else 80)
            redir_path = parsed.path or '/'
            redir_ssl  = (parsed.scheme == 'https')

            # Same host, different scheme (HTTP→HTTPS) — follow it
            if redir_host.lower() == target.lower():
                status2, headers2, body2 = _raw_get(
                    redir_host, redir_port, redir_path, redir_ssl, timeout
                )
                if status2 not in REAL_HITS:
                    return None
                status, headers, body = status2, headers2, body2
            else:
                # Different host entirely → not a real path on this server
                return None

        elif loc.startswith('/'):
            # Relative redirect — follow on same host
            status2, headers2, body2 = _raw_get(
                target, port, loc, use_ssl, timeout
            )
            if status2 not in REAL_HITS:
                return None
            status, headers, body = status2, headers2, body2
        else:
            return None

    # ── Only report real hits ─────────────────────────────────────────────
    if status not in REAL_HITS:
        return None

    # Extract page title
    title = ''
    tm = re.search(r'<title[^>]*>(.*?)</title>', body,
                   re.IGNORECASE | re.DOTALL)
    if tm:
        title = tm.group(1).strip()[:80]
        # Clean HTML entities
        title = re.sub(r'&#\d+;', '', title)
        title = re.sub(r'&amp;', '&', title)
        title = re.sub(r'&lt;', '<', title)
        title = re.sub(r'&gt;', '>', title)

    return {
        'path':   path,
        'code':   status,
        'title':  title,
    }


class AdminFinder:
    def __init__(self, threads: int = 30, timeout: float = 4.0,
                 custom_paths: List[str] = None):
        self.threads = threads
        self.timeout = timeout
        self.paths   = list(dict.fromkeys(ADMIN_PATHS + (custom_paths or [])))

    def scan(self, target: str, port: int, use_ssl: bool = False) -> List[Dict]:
        """
        Scan a host:port for real admin/login paths.
        Returns only paths that return 200, 401, or 403.
        """
        found = []

        with concurrent.futures.ThreadPoolExecutor(
                max_workers=self.threads) as ex:
            futures = {
                ex.submit(_probe_path, target, port, path,
                          use_ssl, self.timeout): path
                for path in self.paths
            }
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    found.append(result)

        found.sort(key=lambda x: x['path'])
        return found


def print_admin_results(target: str, port: int, results: List[Dict]):
    """Pretty-print admin finder results."""
    proto = 'https' if port in (443, 8443) else 'http'
    base  = f"{proto}://{target}:{port}"

    print(f"\n{'=' * 70}")
    print(f"  {Fore.RED}ADMIN PANEL FINDER{Style.RESET_ALL}  --  "
          f"{Fore.YELLOW}{base}{Style.RESET_ALL}")
    print(f"{'=' * 70}")

    if not results:
        print(f"  {Fore.GREEN}No real admin/login paths found.{Style.RESET_ALL}")
        print(f"{'=' * 70}")
        return

    code_colors = {
        200: Fore.GREEN,
        401: Fore.YELLOW,
        403: Fore.RED,
    }
    code_labels = {
        200: 'OPEN',
        401: 'AUTH',
        403: 'DENY',
    }

    print(f"  {Fore.WHITE}{'CODE':<6} {'STATUS':<6} "
          f"{'PATH':<38} TITLE{Style.RESET_ALL}")
    print(f"  {'─'*5} {'─'*5} {'─'*37} {'─'*20}")

    for r in results:
        code  = r['code']
        path  = r['path']
        title = r.get('title', '')
        cc    = code_colors.get(code, Fore.WHITE)
        label = code_labels.get(code, str(code))

        print(f"  {cc}{code:<6}{Style.RESET_ALL}"
              f"{cc}{label:<6}{Style.RESET_ALL}"
              f"{Fore.CYAN}{path:<38}{Style.RESET_ALL}"
              f"{title[:35]}")

    print(f"\n  {Fore.GREEN}[+]{Style.RESET_ALL} "
          f"Found {len(results)} real path(s):")
    for r in results:
        code  = r['code']
        cc    = code_colors.get(code, Fore.WHITE)
        print(f"      {cc}[{code}]{Style.RESET_ALL}  "
              f"{Fore.CYAN}{base}{r['path']}{Style.RESET_ALL}")

    print(f"{'=' * 70}")
