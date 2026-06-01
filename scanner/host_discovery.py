"""
Host discovery functionality
"""

import socket
import concurrent.futures
from typing import List
import platform
import subprocess


class HostDiscovery:
    def __init__(self, timeout=1.0, threads=50):
        self.timeout = timeout
        self.threads = threads
    
    def ping_sweep(self, targets: List[str], verbose=False) -> List[str]:
        """Perform ping sweep to discover alive hosts"""
        alive_hosts = []
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(self._ping_host, target): target 
                      for target in targets}
            
            for future in concurrent.futures.as_completed(futures):
                target = futures[future]
                try:
                    is_alive = future.result()
                    if is_alive:
                        alive_hosts.append(target)
                        if verbose:
                            print(f"[+] Host {target} is up")
                except Exception as e:
                    if verbose:
                        print(f"[!] Error pinging {target}: {e}")
        
        return alive_hosts
    
    def _ping_host(self, target: str) -> bool:
        """Ping a single host"""
        # Try ICMP ping first
        if self._icmp_ping(target):
            return True
        
        # Fallback to TCP ping on common ports
        return self._tcp_ping(target)
    
    def _icmp_ping(self, target: str) -> bool:
        """ICMP ping using system ping command"""
        try:
            param = '-n' if platform.system().lower() == 'windows' else '-c'
            command = ['ping', param, '1', '-w' if platform.system().lower() == 'windows' else '-W', 
                      str(int(self.timeout * 1000)) if platform.system().lower() == 'windows' else str(int(self.timeout)),
                      target]
            
            result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, 
                                   timeout=self.timeout + 1)
            return result.returncode == 0
        except (subprocess.TimeoutExpired, Exception):
            return False
    
    def _tcp_ping(self, target: str, ports=[80, 443, 22, 21]) -> bool:
        """TCP ping on common ports"""
        for port in ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.timeout)
                result = sock.connect_ex((target, port))
                sock.close()
                if result == 0:
                    return True
            except socket.error:
                continue
        return False
