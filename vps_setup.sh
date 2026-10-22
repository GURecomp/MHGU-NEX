#!/usr/bin/env bash
# MHGU-NEX on a plain Linux VPS with a public IP (Ubuntu/Debian).
# Run from the directory holding nexcap.py:  sudo bash vps_setup.sh [PUBLIC_IP]
set -euo pipefail
[ "$(id -u)" -eq 0 ] || { echo "run as root: sudo bash $0"; exit 1; }
SRC="$(cd "$(dirname "$0")" && pwd)"
DEST=/opt/mhgu-nex
TCP_PORTS="443"
UDP_PORTS="10025 10125 33334 33335"

apt-get update -y
DEBIAN_FRONTEND=noninteractive apt-get install -y python3 openssl curl iptables iptables-persistent netfilter-persistent

mkdir -p "$DEST"
[ -f "$SRC/nexcap.py" ] || { echo "nexcap.py not found next to this script"; exit 1; }
cp "$SRC/nexcap.py" "$DEST/"
[ -d "$SRC/certs" ] && cp -rn "$SRC/certs" "$DEST/" || true   # else nexcap makes the cert with openssl on first run

PUBIP="${1:-$(curl -4 -fsS --max-time 10 https://api.ipify.org || curl -4 -fsS --max-time 10 https://ifconfig.me)}"
[ -n "$PUBIP" ] || { echo "could not detect public IP; pass it as argument"; exit 1; }

# -secure-host: the secure-server station URL handed to clients must be the public IP (default is 127.0.0.1).
# Clients are seen with their real IPs, so -public-ip / -url-address are NOT needed; UDP NAT-check replies use the observed source.
# -no-loopback-aliases: 127.0.0.2/.3 aliases are only for loopback emulator setups.
cat > /etc/systemd/system/mhgu-nex.service <<UNIT
[Unit]
Description=MHGU NEX server (nexcap.py)
After=network-online.target
Wants=network-online.target

[Service]
WorkingDirectory=$DEST
ExecStart=/usr/bin/python3 -u $DEST/nexcap.py -bind 0.0.0.0 -secure-host $PUBIP -secure-port 443 -no-loopback-aliases -log $DEST/capture.log
Restart=always
RestartSec=3
User=root
AmbientCapabilities=CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
UNIT

# Some cloud images ship iptables rules ending in REJECT; insert ACCEPTs before it.
for p in $TCP_PORTS; do
  iptables -C INPUT -p tcp --dport "$p" -j ACCEPT 2>/dev/null || iptables -I INPUT 1 -p tcp --dport "$p" -j ACCEPT
done
for p in $UDP_PORTS; do
  iptables -C INPUT -p udp --dport "$p" -j ACCEPT 2>/dev/null || iptables -I INPUT 1 -p udp --dport "$p" -j ACCEPT
done
netfilter-persistent save

systemctl daemon-reload
systemctl enable --now mhgu-nex
sleep 2
systemctl --no-pager --full status mhgu-nex | head -15 || true

echo
echo "=============================================================="
echo "MHGU-NEX running. Public IP: $PUBIP   (set 'Online Server IP' to this in the emulator)"
echo "REMINDER: also open these in your provider's cloud firewall / security group (inbound) (source 0.0.0.0/0):"
echo "  TCP 443"
echo "  UDP 10025, 10125, 33334, 33335"
echo "Logs: journalctl -u mhgu-nex -f   |   $DEST/capture.log"
echo "=============================================================="
