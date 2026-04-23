#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import urlopen

TORRC_PATH = Path("/etc/tor/torrc")
STATE_DIR = Path("/var/lib/toryfikator")
STATE_FILE = STATE_DIR / "state.json"

TOR_USER = "debian-tor"

TOR_TRANS_PORT = 9040
TOR_DNS_PORT = 5353
TOR_TRANS_ADDR = "127.0.0.1"
TOR_DNS_ADDR = "127.0.0.1"
TOR_VADDR_NET = "10.192.0.0/10"

TORRC_BEGIN = "# BEGIN TORYFIKATOR"
TORRC_END = "# END TORYFIKATOR"

TORRC_BLOCK = f"""{TORRC_BEGIN}
# Managed by Toryfikator
VirtualAddrNetworkIPv4 {TOR_VADDR_NET}
AutomapHostsOnResolve 1
TransPort {TOR_TRANS_ADDR}:{TOR_TRANS_PORT}
DNSPort {TOR_DNS_ADDR}:{TOR_DNS_PORT}
{TORRC_END}
"""

NFT = shutil.which("nft") or "/usr/sbin/nft"
SYSCTL = shutil.which("sysctl") or "/usr/sbin/sysctl"
SYSTEMCTL = shutil.which("systemctl") or "/usr/bin/systemctl"
TOR_BIN = shutil.which("tor") or "/usr/sbin/tor"

NFT_FAMILY = "inet"
NFT_TABLE = "toryfikator"

LOCAL_EXCLUDES_V4 = [
    "0.0.0.0/8",
    "10.0.0.0/8",
    "100.64.0.0/10",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "224.0.0.0/4",
    "240.0.0.0/4",
]


def info(msg: str) -> None:
    print(f"[+] {msg}")


def warn(msg: str) -> None:
    print(f"[!] {msg}")


def err(msg: str) -> None:
    print(f"[-] {msg}")


def die(msg: str, code: int = 1) -> None:
    err(msg)
    sys.exit(code)


def run(cmd: list[str], check: bool = True, capture: bool = False) -> subprocess.CompletedProcess:
    return subprocess.run(
        cmd,
        check=check,
        text=True,
        stdout=subprocess.PIPE if capture else None,
        stderr=subprocess.PIPE if capture else None,
    )


def command_exists(path_or_name: str) -> bool:
    if os.path.isabs(path_or_name):
        return os.path.exists(path_or_name) and os.access(path_or_name, os.X_OK)
    return shutil.which(path_or_name) is not None


def ensure_root() -> None:
    if os.geteuid() == 0:
        return

    if not shutil.which("sudo"):
        die("sudo not found. Please run this command as root.")

    info("Root privileges required, re-running with sudo...")

    script_path = Path(__file__).resolve()

    # If running from an installed package/entrypoint, prefer module execution.
    package_root = script_path.parent
    if package_root.name == "toryfikator":
        os.execvp("sudo", ["sudo", sys.executable, "-m", "toryfikator.cli", *sys.argv[1:]])

    # Fallback for direct script execution.
    os.execvp("sudo", ["sudo", sys.executable, str(script_path), *sys.argv[1:]])


def get_uid(username: str) -> str | None:
    try:
        import pwd
        return str(pwd.getpwnam(username).pw_uid)
    except Exception:
        return None


def ensure_dependencies() -> None:
    missing = []
    for dep in [NFT, SYSCTL, SYSTEMCTL, TOR_BIN]:
        if not command_exists(dep):
            missing.append(dep)
    if missing:
        die(f"Missing required binaries: {', '.join(missing)}")

    if not TORRC_PATH.exists():
        die(f"torrc not found: {TORRC_PATH}")

    if get_uid(TOR_USER) is None:
        die(f"Could not resolve required system user: {TOR_USER}")


def print_help() -> None:
    print("Usage: toryfikator [command] | python -m toryfikator.cli [command]")
    print("")
    print("Commands:")
    print("  help        Show this help message")
    print("  configure   Install or update Toryfikator block in /etc/tor/torrc")
    print("  start       Configure torrc, verify config, start/restart Tor, apply nftables rules")
    print("  stop        Remove nftables rules and restore IPv6 settings")
    print("  restart     Stop and then start torification")
    print("  status      Show Tor service status, torrc block status, nftables status, public IP")
    print("  uninstall   Stop torification and remove Toryfikator block from torrc")
    print("")
    print("Root privileges are requested automatically when needed.")


def load_state() -> dict:
    if not STATE_FILE.exists():
        return {}
    try:
        return json.loads(STATE_FILE.read_text())
    except Exception:
        return {}


def save_state(state: dict) -> None:
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    STATE_FILE.write_text(json.dumps(state, indent=2))


def backup_file(path: Path) -> Path:
    ts = time.strftime("%Y%m%d-%H%M%S")
    backup = path.with_suffix(path.suffix + f".bak.{ts}")
    shutil.copy2(path, backup)
    return backup


def restore_file(src: Path, dst: Path) -> None:
    shutil.copy2(src, dst)


def read_torrc() -> str:
    return TORRC_PATH.read_text()


def write_torrc(content: str) -> None:
    TORRC_PATH.write_text(content)


def has_managed_block(content: str) -> bool:
    return TORRC_BEGIN in content and TORRC_END in content


def remove_managed_block(content: str) -> str:
    if not has_managed_block(content):
        return content

    start = content.index(TORRC_BEGIN)
    end = content.index(TORRC_END) + len(TORRC_END)
    before = content[:start].rstrip()
    after = content[end:].lstrip("\n")
    rebuilt = before + ("\n\n" if before and after else "\n" if before or after else "") + after
    return rebuilt.rstrip() + "\n"


def install_managed_block() -> Path | None:
    content = read_torrc()
    new_content = remove_managed_block(content).rstrip() + "\n\n" + TORRC_BLOCK.strip() + "\n"

    if new_content == content:
        info("torrc already contains the current Toryfikator block.")
        return None

    backup = backup_file(TORRC_PATH)
    write_torrc(new_content)
    info(f"Updated torrc and created backup: {backup}")
    return backup


def uninstall_managed_block() -> Path | None:
    content = read_torrc()

    if not has_managed_block(content):
        info("No Toryfikator block found in torrc.")
        return None

    backup = backup_file(TORRC_PATH)
    new_content = remove_managed_block(content)
    write_torrc(new_content)
    info(f"Removed Toryfikator block from torrc. Backup: {backup}")
    return backup


def verify_tor_config() -> None:
    try:
        proc = run([TOR_BIN, "--verify-config", "-f", str(TORRC_PATH)], capture=True)
        stdout = (proc.stdout or "").strip()
        stderr = (proc.stderr or "").strip()

        if stdout:
            print(stdout)

        if stderr:
            for line in stderr.splitlines():
                if "You are running Tor as root" in line:
                    continue
                print(line)

        info("Tor configuration is valid.")
    except subprocess.CalledProcessError as e:
        stdout = (e.stdout or "").strip()
        stderr = (e.stderr or "").strip()
        details = "\n".join(x for x in [stdout, stderr] if x)
        die(f"Tor configuration verification failed.\n{details}")


def verify_tor_config_soft() -> bool:
    try:
        verify_tor_config()
        return True
    except SystemExit:
        return False


def systemctl_cmd(*args: str) -> None:
    run([SYSTEMCTL, *args])


def is_tor_active() -> bool:
    proc = run([SYSTEMCTL, "is-active", "tor"], check=False, capture=True)
    return proc.returncode == 0 and (proc.stdout or "").strip() == "active"


def ensure_tor_running() -> None:
    if is_tor_active():
        info("Tor service is active. Restarting it...")
        systemctl_cmd("restart", "tor")
    else:
        info("Tor service is not active. Starting it...")
        systemctl_cmd("start", "tor")

    if not is_tor_active():
        die("Tor service did not become active.")

    info("Tor service is active.")


def nft_table_exists() -> bool:
    proc = run([NFT, "list", "table", NFT_FAMILY, NFT_TABLE], check=False, capture=True)
    return proc.returncode == 0


def nft_backend() -> str:
    proc = run([NFT, "--version"], check=False, capture=True)
    return ((proc.stdout or "") + (proc.stderr or "")).strip() or "unknown"


def generate_nft_conf() -> str:
    tor_uid = get_uid(TOR_USER)
    if tor_uid is None:
        die(f"Could not resolve user: {TOR_USER}")

    excludes = ", ".join(LOCAL_EXCLUDES_V4)

    return f"""table {NFT_FAMILY} {NFT_TABLE} {{
    chain nat_output {{
        type nat hook output priority -100; policy accept;

        meta skuid {tor_uid} return
        ip daddr 127.0.0.0/8 return

        udp dport 53 redirect to {TOR_DNS_PORT}
        tcp dport 53 redirect to {TOR_DNS_PORT}

        ip daddr {{ {excludes} }} return

        meta l4proto tcp redirect to {TOR_TRANS_PORT}
    }}

    chain filter_output {{
        type filter hook output priority 0; policy accept;

        meta skuid {tor_uid} return
        oifname "lo" return
        ip daddr 127.0.0.0/8 return

        udp dport {TOR_DNS_PORT} ip daddr 127.0.0.1 return
        tcp dport {TOR_DNS_PORT} ip daddr 127.0.0.1 return

        meta l4proto udp reject with icmpx type port-unreachable
    }}
}}
"""


def apply_nft_rules() -> None:
    conf = generate_nft_conf()

    if nft_table_exists():
        run([NFT, "delete", "table", NFT_FAMILY, NFT_TABLE], check=False)

    subprocess.run([NFT, "-f", "-"], input=conf, text=True, check=True)
    info("nftables rules applied.")


def remove_nft_rules() -> None:
    if nft_table_exists():
        run([NFT, "delete", "table", NFT_FAMILY, NFT_TABLE], check=False)
        info("nftables rules removed.")
    else:
        info("No nftables table found, nothing to remove.")


def read_sysctl(key: str) -> str | None:
    proc = run([SYSCTL, "-n", key], check=False, capture=True)
    if proc.returncode != 0:
        return None
    return (proc.stdout or "").strip()


def write_sysctl(key: str, value: str) -> None:
    run([SYSCTL, "-w", f"{key}={value}"])


def disable_ipv6_temporarily() -> None:
    state = load_state()
    if "ipv6_previous" in state:
        info("IPv6 state already saved.")
        return

    keys = [
        "net.ipv6.conf.all.disable_ipv6",
        "net.ipv6.conf.default.disable_ipv6",
    ]

    previous = {}
    for key in keys:
        previous[key] = read_sysctl(key)

    state["ipv6_previous"] = previous
    save_state(state)

    for key in keys:
        write_sysctl(key, "1")

    info("IPv6 disabled temporarily for the torified session.")


def restore_ipv6() -> None:
    state = load_state()
    previous = state.get("ipv6_previous")
    if not previous:
        info("No saved IPv6 state found.")
        return

    for key, value in previous.items():
        if value is not None:
            write_sysctl(key, value)

    state.pop("ipv6_previous", None)
    save_state(state)
    info("IPv6 settings restored.")


def get_public_ip_info() -> dict:
    urls = [
        "https://check.torproject.org/api/ip",
        "https://api.ipify.org?format=json",
    ]

    for url in urls:
        try:
            with urlopen(url, timeout=10) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                if "check.torproject.org" in url:
                    return {
                        "source": "check.torproject.org",
                        "ip": data.get("IP", "Unknown"),
                        "is_tor": bool(data.get("IsTor", False)),
                    }
                return {
                    "source": "api.ipify.org",
                    "ip": data.get("ip", "Unknown"),
                    "is_tor": None,
                }
        except (URLError, HTTPError, TimeoutError, socket.timeout, ValueError, json.JSONDecodeError):
            continue

    return {
        "source": "unavailable",
        "ip": "Unknown",
        "is_tor": None,
    }


def show_status() -> None:
    print("=== Toryfikator status ===")
    print(f"Tor service active : {'yes' if is_tor_active() else 'no'}")
    print(f"torrc block present: {'yes' if has_managed_block(read_torrc()) else 'no'}")
    print(f"nft backend        : {nft_backend()}")
    print(f"nft table active   : {'yes' if nft_table_exists() else 'no'}")

    state = load_state()
    ipv6_saved = "ipv6_previous" in state
    print(f"ipv6 managed       : {'yes' if ipv6_saved else 'no'}")

    ip_info = get_public_ip_info()
    print(f"public ip source   : {ip_info['source']}")
    print(f"public ip          : {ip_info['ip']}")
    if ip_info["is_tor"] is None:
        print("is tor exit ip     : unknown")
    else:
        print(f"is tor exit ip     : {'yes' if ip_info['is_tor'] else 'no'}")


def cmd_configure() -> None:
    ensure_root()
    ensure_dependencies()
    install_managed_block()
    verify_tor_config()


def cmd_start() -> None:
    ensure_root()
    ensure_dependencies()

    backup = None
    try:
        backup = install_managed_block()
        verify_tor_config()
        ensure_tor_running()
        disable_ipv6_temporarily()
        apply_nft_rules()
        info("Torification started.")
    except Exception as e:
        warn(f"Start failed: {e}")
        warn("Rolling back nftables, IPv6 state, and torrc if needed.")
        try:
            remove_nft_rules()
        except Exception:
            pass
        try:
            restore_ipv6()
        except Exception:
            pass
        if backup and backup.exists():
            try:
                restore_file(backup, TORRC_PATH)
                warn(f"Restored torrc from backup: {backup}")
            except Exception as restore_error:
                warn(f"Failed to restore torrc backup: {restore_error}")
        raise


def cmd_stop() -> None:
    ensure_root()
    ensure_dependencies()
    remove_nft_rules()
    restore_ipv6()
    info("Torification stopped.")


def cmd_restart() -> None:
    cmd_stop()
    cmd_start()


def cmd_uninstall() -> None:
    ensure_root()
    ensure_dependencies()
    remove_nft_rules()
    restore_ipv6()
    uninstall_managed_block()

    if not verify_tor_config_soft():
        warn("Tor configuration verification failed after uninstall.")
        warn("This may be caused by unrelated existing issues in your torrc.")

    if is_tor_active():
        systemctl_cmd("restart", "tor")

    info("Toryfikator configuration uninstalled.")


def main() -> None:
    if len(sys.argv) < 2 or sys.argv[1] == "help":
        print_help()
        return

    cmd = sys.argv[1].strip().lower()

    try:
        if cmd == "configure":
            cmd_configure()
        elif cmd == "start":
            cmd_start()
        elif cmd == "stop":
            cmd_stop()
        elif cmd == "restart":
            cmd_restart()
        elif cmd == "status":
            ensure_root()
            ensure_dependencies()
            show_status()
        elif cmd == "uninstall":
            cmd_uninstall()
        else:
            die("Unknown command. Use 'help' to see available commands.")
    except subprocess.CalledProcessError as e:
        stdout = (e.stdout or "").strip()
        stderr = (e.stderr or "").strip()
        details = "\n".join(x for x in [stdout, stderr] if x)
        die(f"Command failed: {' '.join(e.cmd)}\n{details}")


def cli_main() -> None:
    main()


if __name__ == "__main__":
    main()
