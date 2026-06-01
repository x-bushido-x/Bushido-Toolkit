"""
Vulnerability search against Exploit-DB via pyxploitdb
"""

import re
import time
import concurrent.futures
from typing import List, Dict, Optional
from colorama import Fore, Style


# ── Query builder ─────────────────────────────────────────────────────────────

# Maps service names to the product name Exploit-DB knows
SERVICE_TO_PRODUCT = {
    'http':        'Apache',
    'https':       'Apache',
    'http-proxy':  'Apache',
    'https-alt':   'Apache',
    'ssh':         'OpenSSH',
    'ftp':         'vsftpd',
    'ftp-data':    'vsftpd',
    'smtp':        'Postfix',
    'dns':         'BIND',
    'mysql':       'MySQL',
    'postgresql':  'PostgreSQL',
    'redis':       'Redis',
    'mongodb':     'MongoDB',
    'smb':         'Samba',
    'rdp':         'Windows RDP',
    'vnc':         'VNC',
    'telnet':      'telnet',
    'pop3':        'Dovecot',
    'imap':        'Dovecot',
    'mssql':       'Microsoft SQL Server',
    'oracle':      'Oracle',
    'memcached':   'Memcached',
    'elasticsearch': 'Elasticsearch',
}

# Known product names to detect in banner strings
KNOWN_PRODUCTS = [
    'OpenSSH', 'Apache', 'nginx', 'IIS', 'Microsoft-IIS',
    'vsftpd', 'ProFTPD', 'Pure-FTPd',
    'Postfix', 'Exim', 'Sendmail',
    'MySQL', 'MariaDB', 'PostgreSQL',
    'Redis', 'MongoDB', 'Memcached', 'Elasticsearch',
    'OpenSSL', 'Samba', 'Dovecot',
    'BIND', 'named',
    'Tomcat', 'JBoss', 'WebLogic', 'lighttpd',
    'WordPress', 'Drupal', 'Joomla', 'phpMyAdmin',
    'OpenVPN', 'Cisco',
]


def build_queries(service: str, version: str) -> List[str]:
    """
    Build a ranked list of search queries from service + version banner.
    Strategy: try exact version → major.minor → major only → product name only.
    Always includes broad fallbacks so we never return empty-handed.
    """
    service = (service or '').strip().lower()
    version = (version or '').strip()

    # ── Extract product name ──────────────────────────────────────────────────
    product = ''

    # Strip parentheses from banners like "(vsFTPd 3.0.5)"
    clean_version = re.sub(r'[()]', '', version).strip()

    # Try to find a known product name in the banner
    for p in KNOWN_PRODUCTS:
        if re.search(re.escape(p), clean_version, re.IGNORECASE):
            product = p
            break

    # Fall back to service-to-product map
    if not product:
        product = SERVICE_TO_PRODUCT.get(service, '')

    # Last resort: capitalize the service name
    if not product:
        product = service.capitalize()

    # ── Extract version number ────────────────────────────────────────────────
    ver_num = ''
    ver_match = re.search(r'(\d+\.\d+[\.\d]*)', clean_version)
    if ver_match:
        ver_num = ver_match.group(1).rstrip('.-')

    # ── Build query list from most specific to broadest ───────────────────────
    queries = []

    if product and ver_num:
        parts = ver_num.split('.')

        # 1. Exact: "vsftpd 3.0.5"
        queries.append(f"{product} {ver_num}")

        # 2. Major.minor: "vsftpd 3.0"
        if len(parts) >= 2:
            major_minor = f"{parts[0]}.{parts[1]}"
            if major_minor != ver_num:
                queries.append(f"{product} {major_minor}")

        # 3. Major only: "vsftpd 3"
        if parts[0] not in ver_num.replace(parts[0], '', 1):
            queries.append(f"{product} {parts[0]}")

    # 4. Product name only (broadest — always finds something)
    if product:
        queries.append(product)

    # 5. Raw service name as final fallback
    if service and service.lower() not in [q.lower() for q in queries]:
        queries.append(service)

    # Deduplicate preserving order
    seen, unique = set(), []
    for q in queries:
        key = q.lower().strip()
        if key and key not in seen:
            seen.add(key)
            unique.append(q)

    return unique


# ── Exploit-DB search ─────────────────────────────────────────────────────────

def _do_search(query: str, max_results: int) -> List[Dict]:
    """Run a single pyxploitdb query and normalise results."""
    import pyxploitdb
    raw = pyxploitdb.searchEDB(query, _print=False, nb_results=max_results)
    results = []
    for r in raw:
        eid = getattr(r, 'id', '?')
        results.append({
            'id':       eid,
            'title':    getattr(r, 'description', ''),
            'type':     getattr(r, 'type', ''),
            'platform': getattr(r, 'platform', ''),
            'date':     getattr(r, 'date_published', ''),
            'verified': bool(getattr(r, 'verified', 0)),
            'author':   getattr(r, 'author', ''),
            'url':      getattr(r, 'link',
                                f'https://www.exploit-db.com/exploits/{eid}'),
        })
    return results


# Check once at module load whether pyxploitdb is available
_PYXPLOITDB_AVAILABLE = False
try:
    import pyxploitdb as _px
    _PYXPLOITDB_AVAILABLE = True
except ImportError:
    pass


def search_exploitdb(query: str, max_results: int = 10,
                     timeout: float = 15.0) -> List[Dict]:
    """
    Search Exploit-DB with a per-query timeout.
    Returns empty list (never raises) if pyxploitdb is not installed.
    """
    if not _PYXPLOITDB_AVAILABLE:
        return []   # silently skip — caller handles missing results

    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ex:
            future = ex.submit(_do_search, query, max_results)
            return future.result(timeout=timeout)
    except concurrent.futures.TimeoutError:
        return []
    except Exception:
        return []


# ── Main vulnerability scanner ────────────────────────────────────────────────

class VulnScanner:
    def __init__(self, max_results: int = 10, delay: float = 0.3,
                 query_timeout: float = 15.0):
        self.max_results   = max_results
        self.delay         = delay
        self.query_timeout = query_timeout

    def scan_host(self, scan_result: Dict) -> Dict:
        """
        Enrich each open port in a scan result with Exploit-DB data.
        Always tries all queries from specific to broad — never gives up empty.
        """
        enriched = []

        for port_info in scan_result.get('open_ports', []):
            port_info = dict(port_info)
            service   = port_info.get('service', 'unknown')
            version   = port_info.get('version', '')

            # Always search — even for unknown services use the port number
            # to find generic exploits
            if service == 'unknown' and not version:
                port_info['vulns']      = []
                port_info['vuln_query'] = ''
                enriched.append(port_info)
                continue

            queries = build_queries(service, version)
            vulns   = []
            used_q  = queries[0] if queries else service

            for query in queries:
                results = search_exploitdb(
                    query,
                    max_results=self.max_results,
                    timeout=self.query_timeout
                )
                if results:
                    vulns  = results
                    used_q = query
                    break
                time.sleep(self.delay)

            # If still nothing, try the raw service name one more time
            if not vulns and service != 'unknown':
                results = search_exploitdb(
                    service,
                    max_results=self.max_results,
                    timeout=self.query_timeout
                )
                if results:
                    vulns  = results
                    used_q = service

            port_info['vulns']      = vulns
            port_info['vuln_query'] = used_q
            enriched.append(port_info)
            time.sleep(self.delay)

        scan_result = dict(scan_result)
        scan_result['open_ports'] = enriched
        return scan_result


# ── Pretty printer ────────────────────────────────────────────────────────────

def print_vulns(port_info: Dict):
    """Print vulnerability results for a single port."""
    port    = port_info.get('port', '?')
    service = port_info.get('service', 'unknown')
    version = port_info.get('version', '')
    vulns   = port_info.get('vulns', [])
    query   = port_info.get('vuln_query', '')

    label = f"{port}/{service}"
    if version:
        label += f"  ({version[:60]})"

    print(f"\n  {Fore.CYAN}[VULNS]{Style.RESET_ALL} {Fore.WHITE}{label}{Style.RESET_ALL}")
    print(f"  {Fore.WHITE}Search query :{Style.RESET_ALL} {Fore.YELLOW}{query}{Style.RESET_ALL}")
    print(f"  {'─' * 70}")

    if not vulns:
        print(f"  {Fore.GREEN}No public exploits found in Exploit-DB.{Style.RESET_ALL}")
        return

    print(f"  {Fore.RED}Found {len(vulns)} exploit(s):{Style.RESET_ALL}\n")

    type_colors = {
        'remote': Fore.RED,
        'local':  Fore.YELLOW,
        'dos':    Fore.MAGENTA,
        'webapps': Fore.CYAN,
    }

    for i, v in enumerate(vulns, 1):
        verified  = (f"{Fore.GREEN}✔ verified{Style.RESET_ALL}"
                     if v['verified'] else f"{Fore.YELLOW}unverified{Style.RESET_ALL}")
        etype     = v.get('type', '').lower()
        ecolor    = type_colors.get(etype, Fore.WHITE)
        platform  = v.get('platform', '')
        date      = v.get('date', '')
        edb_id    = v.get('id', '?')
        title     = v.get('title', '')

        # Clean HTML entities from title
        title = re.sub(r'&#0*39;', "'", title)
        title = re.sub(r'&amp;', '&', title)
        title = re.sub(r'&lt;', '<', title)
        title = re.sub(r'&gt;', '>', title)

        print(f"  {Fore.RED}[{i:02d}]{Style.RESET_ALL} "
              f"{Fore.WHITE}{title}{Style.RESET_ALL}")
        print(f"       {Fore.BLUE}EDB-{edb_id}{Style.RESET_ALL}  │  "
              f"Type: {ecolor}{etype.upper()}{Style.RESET_ALL}  │  "
              f"Platform: {platform}  │  "
              f"Date: {date}  │  {verified}")
        if v.get('author'):
            print(f"       Author : {v['author']}")
        print(f"       {Fore.CYAN}{v['url']}{Style.RESET_ALL}")
        print()
