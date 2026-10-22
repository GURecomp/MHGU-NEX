# MHGU-NEX setup

A self-hosted NEX server so the Monster Hunter Generations Ultimate recompile can use the game's own online client. It never contacts Nintendo or Nextendo servers and has no logins.

## What you need
- **Python 3** (standard library only) and **openssl** on the machine running the server (openssl makes the self-signed cert on first run if `certs/` is empty).
- A machine that is **not one of the players**. The game drops UDP packets whose source IP equals the NAT-check server's IP, so the server and a player must not share an address.
- For play over the internet, a host with a **public IPv4** address. Inbound ports must be open:
  - TCP `443`
  - UDP `10025`, `10125`, `33334`, `33335`
- An emulator build with the **Online Server IP** field (F10 in-game menu, Multiplayer). It saves `online_server_host` under `[Multiplayer]` in `game_settings.ini`.

## Run locally (testing)
```
python nexcap.py
python selftest.py     # optional, should print ALL PASSED
```
Port 443 may need admin/root. Leave Online Server IP empty and use the `network_replacement_host = 127.0.0.1` config for same-PC tests.

## Host on a public server (Linux)
1. Create a Debian/Ubuntu VM with a public IP (use a fixed/static IP).
2. Open the ports above in the provider's firewall or security group, source `0.0.0.0/0`.
3. Copy `nexcap.py` and `vps_setup.sh` to the VM, then:
   ```
   sudo bash vps_setup.sh [PUBLIC_IP]
   ```
   It installs dependencies, opens the ports in iptables, and runs `nexcap.py` as the `mhgu-nex` systemd service on `0.0.0.0` with `-secure-host <public IP>`.
4. Check it: `journalctl -u mhgu-nex -f` (also `/opt/mhgu-nex/capture.log`).
5. On every player's emulator, set **Online Server IP** to the server's public IP, restart the game, then host first and joiners second.

Use an IP address, not a hostname. Set the field before booting the game.

## Notes
- Direct peer-to-peer play depends on the players' NATs. Tunnel services that hide client IPs are not supported.
- Protocol details and flags: see [README.md](README.md).
