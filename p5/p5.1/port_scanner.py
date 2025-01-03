import concurrent.futures
import socket
import time
from scapy.all import *
from typing import List, Dict, Optional
import subprocess

class PortScanner:
    def __init__(self, max_workers: int = 50, timeout: float = 1.0):
        self.max_workers = max_workers
        self.timeout = timeout
        
    def tcp_connect_scan(self, target: str, port: int) -> Dict:
        """Perform TCP connect scan on a single port."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(self.timeout)
                result = sock.connect_ex((target, port))
                if result == 0:
                    banner = self.grab_banner(sock)
                    return {
                        'port': port,
                        'state': 'open',
                        'banner': banner
                    }
        except Exception as e:
            return {'port': port, 'state': 'error', 'error': str(e)}
        return {'port': port, 'state': 'closed'}

    def grab_banner(self, sock: socket.socket) -> Optional[str]:
        """Attempt to grab service banner from an open port."""
        try:
            # Send common protocol-specific probes
            probes = {
                'HTTP': b'HEAD / HTTP/1.1\r\nHost: localhost\r\n\r\n',
                'SMTP': b'HELO\r\n',
                'FTP': b'',  # FTP servers typically send banner automatically
                'SSH': b''   # SSH servers typically send banner automatically
            }
            
            for probe in probes.values():
                if probe:  # Only send non-empty probes
                    try:
                        sock.send(probe)
                    except:
                        continue
                        
            response = sock.recv(1024)
            return response.decode('utf-8', errors='ignore').strip()
        except:
            return None

    def scan_ports(self, target: str, ports: List[int]) -> List[Dict]:
        """Scan multiple ports in parallel using ThreadPoolExecutor."""
        results = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_port = {
                executor.submit(self.tcp_connect_scan, target, port): port 
                for port in ports
            }
            for future in concurrent.futures.as_completed(future_to_port):
                result = future.result()
                if result['state'] == 'open':
                    results.append(result)
        return results

    def run_nmap_comparison(self, target: str, ports: List[int]) -> Dict:
        """Run nmap scan for performance comparison."""
        port_range = f"{min(ports)}-{max(ports)}"
        start_time = time.time()
        
        try:
            nmap_output = subprocess.run(
                ['nmap', '-p', port_range, '-T4', target],
                capture_output=True,
                text=True,
                timeout=30
            )
            nmap_time = time.time() - start_time
            return {
                'success': True,
                'time': nmap_time,
                'output': nmap_output.stdout
            }
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }

def main():
    target = "upm.es"  
    ports = range(1, 1001)  # Scan first 1000 ports
    
    scanner = PortScanner()
    
    # Custom scanner timing
    start_time = time.time()
    results = scanner.scan_ports(target, ports)
    custom_time = time.time() - start_time
    
    # Run nmap comparison
    nmap_results = scanner.run_nmap_comparison(target, list(ports))
    
    # Print results and comparison
    print(f"\nScan Results for {target}")
    print("-" * 50)
    for result in results:
        print(f"Port {result['port']}: {result['state']}")
        if result.get('banner'):
            print(f"Banner: {result['banner']}\n")
    
    print("\nPerformance Comparison")
    print("-" * 50)
    print(f"Custom Scanner Time: {custom_time:.2f} seconds")
    if nmap_results['success']:
        print(f"Nmap Scan Time: {nmap_results['time']:.2f} seconds")

if __name__ == "__main__":
    main()