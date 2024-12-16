import subprocess
import socket
import ipaddress
import concurrent.futures
from scapy.all import IP, ICMP, sr1, traceroute
import json
import re
import logging

class GatewayEnumerationTool:
    def __init__(self, target='upm.es', max_hops=30):
        """
        Initialize the Gateway Enumeration Tool
        
        :param target: Target hostname or IP address
        :param max_hops: Maximum number of hops to trace
        """
        self.target = target
        self.max_hops = max_hops
        logging.basicConfig(level=logging.INFO, 
                            format='%(asctime)s - %(levelname)s: %(message)s')
        self.logger = logging.getLogger(__name__)

    def system_traceroute(self):
        """
        Perform traceroute using system's native traceroute/tracert command
        
        :return: List of IP addresses in the route
        """
        try:
            # Detect operating system and use appropriate traceroute command
            import platform
            
            if platform.system() == "Windows":
                command = ["tracert", self.target]
            else:
                command = ["traceroute", "-n", self.target]
            
            result = subprocess.run(command, 
                                    capture_output=True, 
                                    text=True, 
                                    timeout=60)
            
            # Parse IP addresses from traceroute output
            ip_pattern = re.compile(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')
            ips = ip_pattern.findall(result.stdout)
            
            self.logger.info(f"System Traceroute to {self.target}: {len(ips)} hops detected")
            return ips
        
        except subprocess.TimeoutExpired:
            self.logger.error("Traceroute timed out")
            return []
        except Exception as e:
            self.logger.error(f"Traceroute error: {e}")
            return []

    def scapy_traceroute(self):
        """
        Perform custom traceroute using Scapy
        
        :return: Detailed route information
        """
        route_data = []
        
        for ttl in range(1, self.max_hops + 1):
            # Create IP packet with incrementing TTL
            packet = IP(dst=self.target, ttl=ttl)/ICMP()
            
            try:
                # Send packet and receive response
                reply = sr1(packet, verbose=0, timeout=2)
                
                if reply is None:
                    continue
                
                hop_info = {
                    'hop': ttl,
                    'ip': reply.src,
                    'response_time': reply.time - packet.time,
                }
                
                # Attempt to resolve hostname
                try:
                    hop_info['hostname'] = socket.gethostbyaddr(reply.src)[0]
                except (socket.herror, socket.gaierror):
                    hop_info['hostname'] = 'Unknown'
                
                route_data.append(hop_info)
                
                if reply.src == socket.gethostbyname(self.target):
                    break
            
            except Exception as e:
                self.logger.error(f"Hop {ttl} error: {e}")
        
        return route_data

    def analyze_gateways(self, route_data):
        """
        Analyze route data to identify potential gateways
        
        :param route_data: List of route information
        :return: List of likely gateways with additional context
        """
        gateways = []
        
        for hop in route_data:
            ip = hop['ip']
            
            # Check if IP is in private address ranges (potential internal gateway)
            try:
                ip_obj = ipaddress.ip_address(ip)
                
                gateway_info = {
                    'ip': ip,
                    'hostname': hop.get('hostname', 'Unknown'),
                    'response_time': hop.get('response_time', 0),
                    'is_private': ip_obj.is_private,
                    'is_reserved': ip_obj.is_reserved
                }
                
                # Basic gateway detection heuristics
                if (ip_obj.is_private or 
                    gateway_info['response_time'] > 0.1):  # High latency might indicate gateway
                    gateways.append(gateway_info)
            
            except ValueError:
                continue
        
        return gateways

    def run(self):
        """
        Execute full gateway discovery process
        """
        self.logger.info(f"Starting gateway discovery for {self.target}")
        
        # Run multiple discovery methods
        system_route = self.system_traceroute()
        scapy_route = self.scapy_traceroute()
        
        # Analyze gateways
        gateways = self.analyze_gateways(scapy_route)
        
        # Output results
        print("\n--- Gateway Discovery Results ---")
        print(json.dumps(gateways, indent=2))
        
        return gateways

def main():
    # Example usage
    tool = GatewayEnumerationTool(target='upm.es')
    tool.run()

if __name__ == "__main__":
    main()