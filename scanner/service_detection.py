"""
Service and version detection
"""

import socket
import select as _select
import re
import ssl
import errno
from typing import Dict, Optional


# ── Port → service name map ───────────────────────────────────────────────────
PORT_SERVICES = {
    20: 'ftp-data',    21: 'ftp',         22: 'ssh',
    23: 'telnet',      25: 'smtp',         53: 'dns',
    67: 'dhcp',        68: 'dhcp',         69: 'tftp',
    80: 'http',        88: 'kerberos',    110: 'pop3',
   111: 'rpcbind',    119: 'nntp',        123: 'ntp',
   135: 'msrpc',      137: 'netbios-ns', 138: 'netbios-dgm',
   139: 'netbios-ssn',143: 'imap',        161: 'snmp',
   162: 'snmptrap',   179: 'bgp',         194: 'irc',
   389: 'ldap',       443: 'https',       445: 'smb',
   465: 'smtps',      500: 'isakmp',      514: 'syslog',
   515: 'printer',    587: 'submission',  631: 'ipp',
   636: 'ldaps',      993: 'imaps',       995: 'pop3s',
  1080: 'socks',     1194: 'openvpn',   1433: 'mssql',
  1521: 'oracle',    1723: 'pptp',      2049: 'nfs',
  2181: 'zookeeper', 2375: 'docker',    2376: 'docker-ssl',
  3000: 'http-dev',  3306: 'mysql',     3389: 'rdp',
  5000: 'upnp',      5432: 'postgresql',5900: 'vnc',
  5985: 'winrm',     5986: 'winrm-ssl', 6379: 'redis',
  6443: 'kubernetes',7001: 'weblogic',  8080: 'http-proxy',
  8443: 'https-alt', 8888: 'http-alt',  9000: 'php-fpm',
  9090: 'http-alt',  9200: 'elasticsearch', 9300: 'elasticsearch',
 11211: 'memcached',27017: 'mongodb',  27018: 'mongodb',
 50000: 'db2',
}

# Windows WSAEWOULDBLOCK / WSAEINPROGRESS codes
_WIN_INPROGRESS = {10035, 10036}
# POSIX in-progress codes
_POSIX_INPROGRESS = {errno.EINPROGRESS, errno.EWOULDBLOCK}
_ALL_INPROGRESS = _WIN_INPROGRESS | _POSIX_INPROGRESS


def _tcp_connect(target: str, port: int, timeout: float) -> Optional[socket.socket]:
    """
    Open a TCP connection using non-blocking socket + select().
    Works correctly on both Windows and Linux/macOS.
    Returns the connected socket on success, or None on failure.
    The caller is responsible for closing the socket.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.setblocking(False)
        err = sock.connect_ex((target, port))

        if err == 0:
            # Instant connect (loopback etc.)
            sock.setblocking(True)
            sock.settimeout(timeout)
            return sock

        if err not in _ALL_INPROGRESS:
            sock.close()
            return None

        # Wait for connection to complete
        _, writable, _ = _select.select([], [sock], [], timeout)
        if not writable:
            sock.close()
            return None

        so_error = sock.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
        if so_error != 0:
            sock.close()
            return None

        sock.setblocking(True)
        sock.settimeout(timeout)
        return sock

    except Exception:
        try:
            sock.close()
        except Exception:
            pass
        return None


class ServiceDetector:
    def __init__(self, timeout=3.0):
        self.timeout = timeout

    def detect(self, target: str, port: int) -> Dict:
        """Detect service name and version on a port."""
        result = {
            'service': PORT_SERVICES.get(port, 'unknown'),
            'version': ''
        }

        detectors = [
            self._detect_ssh,
            self._detect_ftp,
            self._detect_smtp,
            self._detect_http,
            self._detect_https,
            self._detect_dns,
            self._detect_mysql,
            self._detect_redis,
            self._detect_mongodb,
            self._detect_generic_banner,
        ]

        for detector in detectors:
            try:
                info = detector(target, port)
                if info:
                    result.update(info)
                    break
            except Exception:
                continue

        return result

    # ── SSH ───────────────────────────────────────────────────────────────────
    def _detect_ssh(self, target: str, port: int) -> Dict:
        if port not in (22, 2222, 22222):
            return {}
        sock = _tcp_connect(target, port, self.timeout)
        if not sock:
            return {}
        try:
            banner = sock.recv(256).decode('utf-8', errors='ignore').strip()
            if banner.startswith('SSH'):
                return {'service': 'ssh', 'version': banner[:80]}
        except Exception:
            pass
        finally:
            sock.close()
        return {}

    # ── FTP ───────────────────────────────────────────────────────────────────
    def _detect_ftp(self, target: str, port: int) -> Dict:
        if port not in (21, 20, 2121):
            return {}
        sock = _tcp_connect(target, port, self.timeout)
        if not sock:
            return {}
        try:
            banner = sock.recv(512).decode('utf-8', errors='ignore').strip()
            try:
                sock.send(b'QUIT\r\n')
            except Exception:
                pass
            if banner.startswith('220'):
                version = banner.split('\n')[0][4:60].strip()
                return {'service': 'ftp', 'version': version}
        except Exception:
            pass
        finally:
            sock.close()
        return {}

    # ── SMTP ──────────────────────────────────────────────────────────────────
    def _detect_smtp(self, target: str, port: int) -> Dict:
        if port not in (25, 465, 587, 2525):
            return {}
        sock = _tcp_connect(target, port, self.timeout)
        if not sock:
            return {}
        try:
            banner = sock.recv(512).decode('utf-8', errors='ignore').strip()
            try:
                sock.send(b'QUIT\r\n')
            except Exception:
                pass
            if banner.startswith('220'):
                version = banner.split('\n')[0][4:60].strip()
                return {'service': 'smtp', 'version': version}
        except Exception:
            pass
        finally:
            sock.close()
        return {}

    # ── HTTP ──────────────────────────────────────────────────────────────────
    def _detect_http(self, target: str, port: int) -> Dict:
        http_ports = {80, 8080, 8000, 8888, 3000, 9090, 7001}
        if port not in http_ports and not (8000 <= port <= 8100):
            return {}
        sock = _tcp_connect(target, port, self.timeout)
        if not sock:
            return {}
        try:
            sock.send(b'HEAD / HTTP/1.0\r\nHost: ' + target.encode() + b'\r\n\r\n')
            response = sock.recv(2048).decode('utf-8', errors='ignore')
            if 'HTTP/' not in response:
                return {}
            result = {'service': 'http'}
            m = re.search(r'Server:\s*(.+)', response, re.IGNORECASE)
            if m:
                result['version'] = m.group(1).strip()[:60]
            return result
        except Exception:
            return {}
        finally:
            sock.close()

    # ── HTTPS ─────────────────────────────────────────────────────────────────
    def _detect_https(self, target: str, port: int) -> Dict:
        if port not in (443, 8443, 9443, 4443):
            return {}
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((target, port), timeout=self.timeout) as raw:
                with ctx.wrap_socket(raw, server_hostname=target) as ssock:
                    ssock.send(b'HEAD / HTTP/1.0\r\nHost: ' + target.encode() + b'\r\n\r\n')
                    response = ssock.recv(2048).decode('utf-8', errors='ignore')
            result = {'service': 'https'}
            m = re.search(r'Server:\s*(.+)', response, re.IGNORECASE)
            if m:
                result['version'] = m.group(1).strip()[:60]
            return result
        except Exception:
            return {}

    # ── DNS ───────────────────────────────────────────────────────────────────
    def _detect_dns(self, target: str, port: int) -> Dict:
        if port != 53:
            return {}
        # version.bind CHAOS TXT query
        query = (
            b'\xaa\xaa\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00'
            b'\x07version\x04bind\x00'
            b'\x00\x10\x00\x03'
        )
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(self.timeout)
            sock.sendto(query, (target, port))
            response, _ = sock.recvfrom(512)
            sock.close()
            version = ''
            if len(response) > 12:
                for m in re.findall(rb'[\x20-\x7e]{4,}', response[12:]):
                    decoded = m.decode('ascii', errors='ignore')
                    if re.search(r'\d+\.\d+', decoded):
                        version = decoded[:40]
                        break
            return {'service': 'dns', 'version': version or 'DNS'}
        except Exception:
            pass
        # Fallback: TCP connect confirms DNS is open
        sock2 = _tcp_connect(target, 53, self.timeout)
        if sock2:
            sock2.close()
            return {'service': 'dns', 'version': 'DNS'}
        return {}

    # ── MySQL ─────────────────────────────────────────────────────────────────
    def _detect_mysql(self, target: str, port: int) -> Dict:
        if port not in (3306, 3307):
            return {}
        sock = _tcp_connect(target, port, self.timeout)
        if not sock:
            return {}
        try:
            data = sock.recv(256)
            if len(data) >= 5 and data[4] in (9, 10):
                payload = data[4:]
                null_idx = payload.find(b'\x00', 1)
                if null_idx > 1:
                    ver = payload[1:null_idx].decode('utf-8', errors='ignore')
                    return {'service': 'mysql', 'version': f'MySQL {ver}'}
        except Exception:
            pass
        finally:
            sock.close()
        return {}

    # ── Redis ─────────────────────────────────────────────────────────────────
    def _detect_redis(self, target: str, port: int) -> Dict:
        if port not in (6379, 6380):
            return {}
        sock = _tcp_connect(target, port, self.timeout)
        if not sock:
            return {}
        try:
            sock.send(b'INFO server\r\n')
            response = sock.recv(1024).decode('utf-8', errors='ignore')
            m = re.search(r'redis_version:(\S+)', response)
            if m:
                return {'service': 'redis', 'version': f'Redis {m.group(1)}'}
        except Exception:
            pass
        finally:
            sock.close()
        return {}

    # ── MongoDB ───────────────────────────────────────────────────────────────
    def _detect_mongodb(self, target: str, port: int) -> Dict:
        if port not in (27017, 27018, 27019):
            return {}
        sock = _tcp_connect(target, port, self.timeout)
        if not sock:
            return {}
        try:
            msg = (
                b'\x41\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00'
                b'\xd4\x07\x00\x00\x00\x00\x00\x00'
                b'admin.$cmd\x00'
                b'\x00\x00\x00\x00\x01\x00\x00\x00'
                b'\x13\x00\x00\x00\x01ismaster\x00'
                b'\x00\x00\x00\x00\x00\x00\xf0\x3f\x00'
            )
            sock.send(msg)
            response = sock.recv(1024)
            if len(response) > 20:
                text = response.decode('utf-8', errors='ignore')
                m = re.search(r'(\d+\.\d+\.\d+)', text)
                ver = f'MongoDB {m.group(1)}' if m else 'MongoDB'
                return {'service': 'mongodb', 'version': ver}
        except Exception:
            pass
        finally:
            sock.close()
        return {}

    # ── Generic banner ────────────────────────────────────────────────────────
    def _detect_generic_banner(self, target: str, port: int) -> Dict:
        sock = _tcp_connect(target, port, self.timeout)
        if not sock:
            return {}
        try:
            try:
                sock.send(b'HEAD / HTTP/1.0\r\n\r\n')
            except Exception:
                pass
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            if not banner:
                return {}
            service   = PORT_SERVICES.get(port, 'unknown')
            first_line = banner.split('\n')[0][:80].strip()
            m = re.search(r'([A-Za-z][\w\-\.]+)[/ ](\d+[\.\d]+[\w\-\.]*)', first_line)
            version = f"{m.group(1)} {m.group(2)}" if m else first_line[:60]
            return {'service': service, 'version': version}
        except Exception:
            return {}
        finally:
            sock.close()
