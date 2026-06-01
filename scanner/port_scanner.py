"""
Port scanning functionality
"""

import socket
import select
import errno
import concurrent.futures
from typing import List, Dict
from .service_detection import ServiceDetector, PORT_SERVICES


class PortScanner:
    def __init__(self, scan_type='connect', timing=3, threads=100,
                 service_detection=False, verbose=False):
        self.scan_type = scan_type
        self.timing = timing
        self.threads = threads
        self.service_detection = service_detection
        self.verbose = verbose
        self.timeout = self._get_timeout(timing)

        if service_detection:
            self.service_detector = ServiceDetector(timeout=self.timeout + 1)

    def _get_timeout(self, timing):
        # Timeouts are per-port connection wait time in seconds.
        # T3 is bumped to 2s so remote hosts across the internet
        # don't get falsely marked closed on slower connections.
        timeouts = {
            0: 10.0,  # Paranoid
            1:  5.0,  # Sneaky
            2:  3.0,  # Polite
            3:  2.0,  # Normal  (was 1.0 — too short for remote hosts)
            4:  1.0,  # Aggressive
            5:  0.5,  # Insane
        }
        return timeouts.get(timing, 2.0)

    def scan(self, target: str, ports: List[int]) -> Dict:
        result = {
            'target': target,
            'open_ports': [],
            'closed_ports': [],
            'filtered_ports': []
        }

        if self.scan_type == 'syn':
            return self._syn_scan(target, ports, result)
        elif self.scan_type == 'udp':
            return self._udp_scan(target, ports, result)
        else:
            return self._connect_scan(target, ports, result)

    def _connect_scan(self, target: str, ports: List[int], result: Dict) -> Dict:
        total     = len(ports)
        completed = 0

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(self._check_tcp_port, target, port): port
                       for port in ports}

            for future in concurrent.futures.as_completed(futures):
                port = futures[future]
                completed += 1

                # Progress indicator for large scans
                if total > 100 and completed % 100 == 0:
                    pct = int(completed / total * 100)
                    open_so_far = len(result['open_ports'])
                    print(f"\r  [*] Progress: {completed}/{total} ports ({pct}%)  "
                          f"Open: {open_so_far}   ", end='', flush=True)

                try:
                    is_open = future.result()
                    if is_open:
                        port_info = {
                            'port': port,
                            'state': 'open',
                            'protocol': 'tcp',
                            'service': PORT_SERVICES.get(port, 'unknown'),
                            'version': ''
                        }

                        if self.service_detection:
                            detected = self.service_detector.detect(target, port)
                            port_info['service'] = detected.get('service', port_info['service'])
                            port_info['version'] = detected.get('version', '')

                        result['open_ports'].append(port_info)

                        if self.verbose:
                            svc = port_info['service']
                            ver = port_info['version']
                            print(f"\r[+] {target}:{port}/tcp  OPEN  {svc}  {ver}")
                    else:
                        result['closed_ports'].append(port)
                except Exception as e:
                    if self.verbose:
                        print(f"\r[!] Error scanning {target}:{port} - {e}")
                    result['filtered_ports'].append(port)

        if total > 100:
            print(f"\r  [*] Progress: {total}/{total} ports (100%)  "
                  f"Open: {len(result['open_ports'])}   ")

        return result

    def _check_tcp_port(self, target: str, port: int) -> bool:
        """
        Windows-safe TCP port check using non-blocking socket + select().

        On Windows, settimeout() puts the socket into non-blocking mode.
        connect_ex() then returns WSAEWOULDBLOCK (10035) immediately for
        ports that are still connecting — NOT closed. We must use select()
        to wait for the connection to complete, then check for errors.

        Error code reference:
          0     -> connected (OPEN)
          10035 -> WSAEWOULDBLOCK: still connecting (use select to wait)
          10061 -> WSAECONNREFUSED: port closed
          10060 -> WSAETIMEDOUT: filtered / no response
          111   -> ECONNREFUSED (Linux): port closed
        """
        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setblocking(False)  # non-blocking so connect_ex returns immediately

            err = sock.connect_ex((target, port))

            # err == 0 means instant connect (rare but possible on loopback)
            # WSAEWOULDBLOCK (10035) / EINPROGRESS (115) means connecting
            if err == 0:
                return True

            if err not in (
                errno.EINPROGRESS,   # Linux/macOS: 115
                errno.EWOULDBLOCK,   # Linux: 11
                10035,               # Windows: WSAEWOULDBLOCK
                10036,               # Windows: WSAEINPROGRESS
            ):
                # Immediate refusal or other hard error → closed/filtered
                return False

            # Wait up to self.timeout seconds for the socket to become writable
            # (writable = connection completed or failed)
            _, writable, _ = select.select([], [sock], [], self.timeout)

            if not writable:
                # Timed out → filtered
                return False

            # Check if the connection actually succeeded
            so_error = sock.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
            return so_error == 0

        except Exception:
            return False
        finally:
            if sock:
                try:
                    sock.close()
                except Exception:
                    pass

    def _syn_scan(self, target: str, ports: List[int], result: Dict) -> Dict:
        try:
            from scapy.all import sr, IP, TCP, conf
            conf.verb = 0

            packets = IP(dst=target) / TCP(dport=ports, flags='S')
            answered, unanswered = sr(packets, timeout=self.timeout, verbose=0)

            for sent, received in answered:
                port = sent[TCP].dport
                flags = received[TCP].flags

                if flags == 0x12:  # SYN-ACK
                    port_info = {
                        'port': port,
                        'state': 'open',
                        'protocol': 'tcp',
                        'service': PORT_SERVICES.get(port, 'unknown'),
                        'version': ''
                    }

                    if self.service_detection:
                        detected = self.service_detector.detect(target, port)
                        port_info['service'] = detected.get('service', port_info['service'])
                        port_info['version'] = detected.get('version', '')

                    result['open_ports'].append(port_info)

                    if self.verbose:
                        print(f"[+] {target}:{port}/tcp  OPEN  {port_info['service']}")

                    # Send RST
                    from scapy.all import sr
                    rst = IP(dst=target) / TCP(dport=port, flags='R')
                    sr(rst, timeout=0.1, verbose=0)

                elif flags == 0x14:
                    result['closed_ports'].append(port)

            for sent in unanswered:
                result['filtered_ports'].append(sent[TCP].dport)

        except ImportError:
            raise ImportError("SYN scan requires scapy: pip install scapy")
        except PermissionError:
            raise PermissionError("SYN scan requires root/administrator privileges")

        return result

    def _udp_scan(self, target: str, ports: List[int], result: Dict) -> Dict:
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(self._check_udp_port, target, port): port
                       for port in ports}

            for future in concurrent.futures.as_completed(futures):
                port = futures[future]
                try:
                    state = future.result()
                    if state == 'open':
                        port_info = {
                            'port': port,
                            'state': 'open',
                            'protocol': 'udp',
                            'service': PORT_SERVICES.get(port, 'unknown'),
                            'version': ''
                        }
                        result['open_ports'].append(port_info)

                        if self.verbose:
                            print(f"[+] {target}:{port}/udp  OPEN  {port_info['service']}")
                    elif state == 'closed':
                        result['closed_ports'].append(port)
                    else:
                        result['filtered_ports'].append(port)
                except Exception as e:
                    if self.verbose:
                        print(f"[!] Error scanning {target}:{port}/udp - {e}")
                    result['filtered_ports'].append(port)

        return result

    def _check_udp_port(self, target: str, port: int) -> str:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(self.timeout)
            sock.sendto(b'', (target, port))
            try:
                sock.recvfrom(1024)
                sock.close()
                return 'open'
            except socket.timeout:
                sock.close()
                return 'open|filtered'
        except socket.error:
            return 'closed'
