# 🧅 Toryfikator

Transparent Tor routing using nftables. Automatically routes all outgoing traffic through Tor using `nftables`, with DNS leak protection and minimal configuration.

![Dragon Eats Onion](dragoneatsonion.webp)

## ✨ Features

- Transparent TCP routing → Tor (`TransPort`)
- DNS redirection → Tor (`DNSPort`)
- nftables
- Automatic IPv6 disable (temporary)
- Prevents UDP leaks
- Excludes local/private networks
- Auto-detects Tor user
- Auto-sudo (no need to run manually with sudo)
- Safe rollback on failure
- Simple CLI

## ⚙️ Requirements

- Linux (tested on Kali / Debian)
- `tor`
- `nftables`
- `systemd`
- `sudo`

## 📦 Installation

```bash
pipx install git+https://github.com/h0ek/toryfikator.git
```

## 🚀 Usage

No need to run with sudo — it will elevate automatically.

```bash
toryfikator start
toryfikator stop
toryfikator status
toryfikator restart
toryfikator uninstall
```

## 🔐 How it works

### Tor configuration

Automatically updates `/etc/tor/torrc`:

```
VirtualAddrNetworkIPv4 10.192.0.0/10
AutomapHostsOnResolve 1
TransPort 127.0.0.1:9040
DNSPort 127.0.0.1:5353
```

### nftables rules

Creates:

```
table inet toryfikator
```

#### NAT (output hook)
- Redirects all TCP → `9040`
- Redirects DNS → `5353`
- Excludes:
  - localhost
  - RFC1918 ranges
  - Tor process (`debian-tor`)

#### FILTER (output hook)
- Allows:
  - localhost
  - Tor DNS
- Blocks:
  - all other UDP (prevents leaks)

### Additional protections

- Disables IPv6 (temporary, restored on stop)
- Prevents DNS leaks
- Prevents direct UDP traffic

## 🔍 Status check

```bash
toryfikator status
```

Shows:
- Tor service state
- nftables state
- Public IP
- Tor exit detection

## 🧹 Cleanup

Stop routing:

```bash
toryfikator stop
```

Full cleanup:

```bash
toryfikator uninstall
```

## ⚠️ Notes

- Tor runs as `debian-tor` (not root)
- Script runs as root (required for nft/sysctl/systemctl)
- Warning:
  ```
  Tor is running as root
  ```
  during config check is expected and safely ignored

## 🛠 Troubleshooting

### No internet after start

```bash
systemctl status tor
nft list ruleset
```

## ⚠️ Disclaimer

This tool improves anonymity but **does not guarantee full anonymity**.

For stronger isolation consider:

- https://tails.net/
- https://www.whonix.org/

Alternative tools:

- https://github.com/Und3rf10w/kali-anonsurf
- https://github.com/brainfucksec/kalitorify
- https://github.com/Debajyoti0-0/ToriFY
