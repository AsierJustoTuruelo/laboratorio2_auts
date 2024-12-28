#!/bin/bash

# Hay que instalar sudo apt install tcpdump iputils-arping

# Especifica el rango de IPs (por ejemplo, 192.168.1.0/24)
network="192.169.0"

echo "Realizando descubrimiento ARP en la red $network.0/24..."

for i in $(seq 1 254); do
    ip="$network.$i"

    # Construir y enviar un paquete ARP manualmente
    arping -c 1 -I eth0 $ip > /dev/null 2>&1

    # Verificar si hay respuesta usando tcpdump
    timeout 1 tcpdump -i eth0 arp and host $ip -c 1 -n > /dev/null 2>&1
    if [ $? -eq 0 ]; then
        echo "Host activo: $ip"
    fi
done

