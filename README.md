# 🧅 Toryfikator

Transparent IPv4 TCP routing through Tor for **Kali Linux / Debian**, using nftables.

![Dragon Eats Onion](dragoneatsonion.webp)

## Install

```bash
sudo apt install tor nftables curl util-linux pipx
pipx install git+https://github.com/h0ek/toryfikator.git
```

## Use

```bash
toryfikator start
toryfikator status
toryfikator status --check
toryfikator restart
toryfikator stop
toryfikator uninstall
```

Administrator privileges are requested automatically. Tor drops privileges to `debian-tor` using Debian service defaults, including during configuration validation. The service is `tor@default.service`.

- `start` installs protection before restarting Tor and verifies the exit through the Tor Project API. The check may take about two minutes. Failed startup keeps protection enabled: retry `start`, or explicitly use `stop` for direct networking.
- `restart` replaces rules atomically without opening direct Internet access. Existing direct Internet connections are blocked.
- `status` is offline; `status --check` contacts the Tor Project API.
- `stop` removes routing rules. `uninstall` also removes the managed torrc block; neither uninstalls the Python package.

## Scope

Uses `/etc/tor/torrc`, TCP `127.0.0.1:9040`, UDP DNS `127.0.0.1:9053`, and the `inet toryfikator` table. Existing conflicting Tor listener settings must be resolved first.

IPv6 outside loopback, non-DNS UDP (except DHCPv4), ICMP and forwarded traffic are blocked. Private/CGNAT/link-local IPv4 TCP remains direct; virtual `.onion` addresses take precedence. DNS UDP is redirected to Tor; public TCP DNS uses TransPort. Tor DNS supports only A/AAAA/PTR; TCP DNS to private/local resolvers is unsupported.

Rules are session-only: run `start` after reboot. Other firewall managers may remove or conflict with them. Containers/VMs are not torified: their forwarded IP traffic is blocked. This is not a sandbox for privileged/raw-packet tools or a replacement for Tor Browser, Tails or Whonix.

```bash
sudo systemctl status tor@default.service --no-pager
sudo journalctl -u tor@default.service -n 50 --no-pager
sudo nft list table inet toryfikator
python3 -m unittest discover -s tests -v
```
