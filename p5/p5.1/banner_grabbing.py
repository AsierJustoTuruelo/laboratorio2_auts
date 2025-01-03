import socket
import sys
from typing import Tuple, Optional

class HTTPBannerGrabber:
    """HTTP Banner Grabber using raw sockets for server information gathering."""
    
    def __init__(self, timeout: int = 5):
        """Initialize banner grabber with configurable timeout.
        
        Args:
            timeout: Socket timeout in seconds
        """
        self.timeout = timeout
    
    def grab_banner(self, host: str, port: int = 80) -> Tuple[Optional[str], Optional[str]]:
        """Connect to target host and retrieve HTTP banner information.
        
        Args:
            host: Target hostname or IP address
            port: Target port number (default 80)
            
        Returns:
            Tuple containing (banner, error_message)
            Banner will be None if error occurs, error_message will be None on success
        """
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        
        try:
            # Establish connection
            sock.connect((host, port))
            
            # Construct and send HTTP HEAD request
            http_request = (
                f"HEAD / HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                f"User-Agent: BannerGrabber/1.0\r\n"
                f"Connection: close\r\n\r\n"
            )
            sock.send(http_request.encode())
            
            # Receive and decode response
            response = sock.recv(4096).decode('utf-8', errors='ignore')
            return response, None
            
        except socket.gaierror:
            return None, "Failed to resolve hostname"
        except socket.timeout:
            return None, "Connection timed out"
        except ConnectionRefusedError:
            return None, "Connection refused by host"
        except Exception as e:
            return None, f"Error: {str(e)}"
        finally:
            sock.close()

def main():
    """CLI entry point for banner grabber."""
    if len(sys.argv) < 2:
        print("Usage: python banner_grabber.py <host> [port]")
        sys.exit(1)
        
    host = sys.argv[1]
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 80
    
    grabber = HTTPBannerGrabber()
    banner, error = grabber.grab_banner(host, port)
    
    if error:
        print(f"Failed to grab banner: {error}")
    else:
        print("Server Response:")
        print("-" * 50)
        print(banner)

if __name__ == "__main__":
    main()