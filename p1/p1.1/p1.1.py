from scapy.all import IP, ICMP, sr1, conf
import time
import socket

def traceroute_scapy(target, max_hops=15, timeout=2):
    """
    Realiza un traceroute personalizado usando Scapy.
    """
    gateways = []
    print(f"\nTraceroute hacia {target} (máximo {max_hops} saltos)...")
    
    for ttl in range(1, max_hops + 1):
        pkt = IP(dst=target, ttl=ttl) / ICMP()
        start_time = time.time()
        reply = sr1(pkt, verbose=0, timeout=timeout)
        elapsed_time = round((time.time() - start_time) * 1000, 2)  # ms
        
        if reply is None:
            print(f"{ttl}: * (timeout)")
            continue
        
        try:
            hostname = socket.gethostbyaddr(reply.src)[0]
        except socket.herror:
            hostname = "Unknown"
        
        print(f"{ttl}: {reply.src} ({hostname}) - {elapsed_time} ms")
        
        gateways.append({
            'ttl': ttl,
            'ip': reply.src,
            'hostname': hostname,
            'latency': elapsed_time
        })
        
        # Si llegamos al destino, detenemos el traceroute
        if reply.src == socket.gethostbyname(target):
            break

    return gateways

def analyze_gateways(gateways):
    """
    Analiza la ruta para identificar posibles gateways y patrones.
    """
    print("\nAnalizando gateways...")
    analyzed = []
    
    if not gateways:
        return analyzed
    
    # Primer y último salto
    analyzed.append({'ip': gateways[0]['ip'], 'role': 'First public hop', 'latency': gateways[0]['latency']})
    analyzed.append({'ip': gateways[-1]['ip'], 'role': 'Destination', 'latency': gateways[-1]['latency']})
    
    # Identificar posibles cuellos de botella (latencia alta)
    threshold = 100  # ms arbitrario para detectar latencia alta
    for gw in gateways[1:-1]:
        if gw['latency'] > threshold:
            analyzed.append({'ip': gw['ip'], 'role': 'Potential bottleneck', 'latency': gw['latency']})
    
    return analyzed

def main():
    target = "upm.es"
    gateways = traceroute_scapy(target)
    analyzed_gateways = analyze_gateways(gateways)
    
    print("\nGateways identificados:")
    print("=" * 50)
    for gw in analyzed_gateways:
        print(f"IP: {gw['ip']} - Rol: {gw['role']} - Latencia: {gw['latency']} ms")

if __name__ == "__main__":
    main()
