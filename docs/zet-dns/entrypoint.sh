#!/bin/sh -e
# dns_host.c consulta el resolver del SO de ESTE netns via res_ninit -> /etc/resolv.conf.
# Conservamos el upstream original (para que dnsmasq forward-ee lo NO local, p.ej. el hostname
# del controller que el zet necesita resolver para conectar al overlay) y apuntamos el resolver
# del SO a dnsmasq (127.0.0.1).
cp /etc/resolv.conf /etc/resolv.conf.orig
echo "nameserver 127.0.0.1" > /etc/resolv.conf
# Explicit --conf-file (self-contained): no depende del conf-dir por defecto de debian; el
# pre-check §3.3a (dig @127.0.0.1 ... MX dentro del contenedor) valida que sirve. Falla RUIDOSO
# si :53 loopback ya está ocupado.
dnsmasq --conf-file=/etc/dnsmasq.d/wild.conf
# run-host (ziti-edge-tunnel.c:2882): solo hostea, sin tun ni root. -v 4 = DEBUG (loguea
# resolve_req, dns_host.c:251 — el discriminador anti-falso-verde de §6).
exec ziti-edge-tunnel run-host -i /opt/zet/zet-dns-host.json -v 4
