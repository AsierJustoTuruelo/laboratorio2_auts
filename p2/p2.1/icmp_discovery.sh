#!/bin/bash

# Especifica el rango de IPs (por ejemplo, 192.168.1.x)
network="192.169.0"
start=1
end=254

echo "Realizando descubrimiento ICMP en la red $network.0/24..."

for i in $(seq $start $end); do
    ip="$network.$i"

    # Enviar un paquete ICMP tipo ECHO REQUEST (ping) manualmente
    (echo -ne '\x08\x00\x7d\x4b\x00\x00\x00\x00' > /dev/udp/$ip/0) 2>/dev/null

    # Verificar si el host respondió con ECHO REPLY
    timeout 1 tcpdump -i eth0 icmp and src $ip -c 1 -n > /dev/null 2>&1
    if [ $? -eq 0 ]; then
        echo "Host activo: $ip"
    fi
done
