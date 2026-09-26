from __future__ import annotations

import argparse
import contextlib
import fcntl
import ipaddress
import json
import os
import pwd
import shlex
import signal
import stat
import subprocess
import sys
import tempfile
import time
from pathlib import Path

VERSION = "0.4.2"
TORRC_PATH = Path("/etc/tor/torrc")
TOR_DEFAULTS = Path("/usr/share/tor/tor-service-defaults-torrc")
STATE_DIR = Path("/var/lib/toryfikator")
STATE_FILE = STATE_DIR / "state.json"
LOCK_PATH = Path("/run/toryfikator.lock")
PROC_ROOT = Path("/proc")
TOR_USER = "debian-tor"
TOR_SERVICE = "tor@default.service"
TOR_TRANS_PORT = 9040
TOR_DNS_PORT = 9053
TOR_SOCKS_PORT = 9050
TOR_VADDR_NET = "10.192.0.0/10"
TORRC_BEGIN = "# BEGIN TORYFIKATOR"
TORRC_END = "# END TORYFIKATOR"
TORRC_BLOCK = f"""{TORRC_BEGIN}
VirtualAddrNetworkIPv4 {TOR_VADDR_NET}
AutomapHostsOnResolve 1
AutomapHostsSuffixes .onion
TransPort 127.0.0.1:{TOR_TRANS_PORT}
DNSPort 127.0.0.1:{TOR_DNS_PORT}
{TORRC_END}
"""
NFT = "/usr/sbin/nft"
SYSTEMCTL = "/usr/bin/systemctl"
TOR_BIN = "/usr/bin/tor"
CURL = "/usr/bin/curl"
SUDO = "/usr/bin/sudo"
NFT_FAMILY = "inet"
NFT_TABLE = "toryfikator"
LOCAL_NETWORKS = ("10.0.0.0/8", "100.64.0.0/10", "169.254.0.0/16", "172.16.0.0/12", "192.168.0.0/16")


class ToryfikatorError(RuntimeError):
    pass


def info(message: str) -> None:
    print(f"[+] {message}", flush=True)


def warn(message: str) -> None:
    print(f"[!] {message}", file=sys.stderr, flush=True)


def run(cmd: list[str], *, check: bool = True, input: str | None = None,
        timeout: float = 30) -> subprocess.CompletedProcess:
    env = {key: value for key, value in os.environ.items()
           if key not in {"PYTHONPATH", "PYTHONHOME"} and not key.lower().endswith("_proxy")}
    env.update({"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"})
    try:
        proc = subprocess.run(cmd, input=input, text=True, capture_output=True,
                              timeout=timeout, env=env, check=False)
    except subprocess.TimeoutExpired as exc:
        raise ToryfikatorError(f"Command timed out: {cmd[0]}") from exc
    if check and proc.returncode:
        details = (proc.stderr or proc.stdout or "No diagnostic output").strip()
        raise ToryfikatorError(f"Command failed ({proc.returncode}): {shlex.join(cmd)}\n{details}")
    return proc


def ensure_root() -> None:
    if os.geteuid() != 0:
        if not os.access(SUDO, os.X_OK):
            raise ToryfikatorError("sudo is missing; run this command as root.")
        info("Requesting administrator privileges...")
        os.execv(SUDO, [SUDO, "--", sys.executable, "-I", str(Path(__file__).resolve()), *sys.argv[1:]])


def require_binaries(*paths: str) -> None:
    missing = [path for path in paths if not os.access(path, os.X_OK)]
    if missing:
        raise ToryfikatorError(f"Missing binaries: {', '.join(missing)}. Install tor nftables curl util-linux.")


def tor_uid() -> int:
    try:
        uid = pwd.getpwnam(TOR_USER).pw_uid
    except KeyError as exc:
        raise ToryfikatorError(f"System user {TOR_USER} is missing. Install the Debian/Kali tor package.") from exc
    if uid == 0:
        raise ToryfikatorError("Refusing to exempt UID 0 from the firewall.")
    return uid


@contextlib.contextmanager
def command_lock():
    fd = os.open(LOCK_PATH, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        metadata = os.fstat(fd)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != 0 or metadata.st_mode & 0o022:
            raise ToryfikatorError("Unsafe command lock file.")
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise ToryfikatorError("Another Toryfikator command is running.") from exc
        yield
    finally:
        os.close(fd)


def trusted_file(path: Path) -> os.stat_result:
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != 0 or metadata.st_mode & 0o022:
        raise ToryfikatorError(f"Expected a root-owned, non-writable regular file: {path}")
    return metadata


def atomic_write(path: Path, data: bytes, metadata: os.stat_result | None = None) -> None:
    fd, name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(name)
    try:
        with os.fdopen(fd, "wb") as stream:
            if metadata is not None:
                os.fchown(stream.fileno(), metadata.st_uid, metadata.st_gid)
                os.fchmod(stream.fileno(), stat.S_IMODE(metadata.st_mode))
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        temporary.unlink(missing_ok=True)


def remove_managed_block(content: str) -> str:
    lines = content.splitlines(keepends=True)
    begins = [i for i, line in enumerate(lines) if line.strip() == TORRC_BEGIN]
    ends = [i for i, line in enumerate(lines) if line.strip() == TORRC_END]
    if not begins and not ends:
        return content
    if len(begins) != 1 or len(ends) != 1 or begins[0] >= ends[0]:
        raise ToryfikatorError("Malformed Toryfikator markers in torrc; repair them before continuing.")
    return "".join(lines[:begins[0]] + lines[ends[0] + 1:])


def managed_content(content: str) -> str:
    clean = remove_managed_block(content).rstrip("\r\n")
    return (clean + "\n\n" if clean else "") + TORRC_BLOCK


def tor_command(action: str) -> list[str]:
    quiet = ["--quiet"] if action.startswith("--dump-config") else []
    return [TOR_BIN, *quiet, "--defaults-torrc", str(TOR_DEFAULTS),
            "-f", str(TORRC_PATH), "--RunAsDaemon", "0", *shlex.split(action)]


def effective_config() -> dict[str, list[str]]:
    output = run(tor_command("--dump-config full")).stdout
    values: dict[str, list[str]] = {}
    for line in output.splitlines():
        tokens = shlex.split(line, comments=True)
        if len(tokens) > 1:
            values.setdefault(tokens[0].lower(), []).append(" ".join(tokens[1:]))
    return values


def verify_tor_config(managed: bool = True) -> None:
    run(tor_command("--verify-config"))
    config = effective_config()
    if config.get("user") != [TOR_USER]:
        raise ToryfikatorError(f"Effective Tor User must be {TOR_USER}.")
    if managed:
        expected = {"transport": [f"127.0.0.1:{TOR_TRANS_PORT}"],
                    "dnsport": [f"127.0.0.1:{TOR_DNS_PORT}"],
                    "virtualaddrnetworkipv4": [TOR_VADDR_NET],
                    "automaphostsonresolve": ["1"], "automaphostssuffixes": [".onion"]}
        for key, value in expected.items():
            if config.get(key) != value:
                raise ToryfikatorError(f"Conflicting effective Tor option: {key}. Check torrc and included files.")
        if config.get("disablenetwork", ["0"]) != ["0"]:
            raise ToryfikatorError("DisableNetwork must be 0.")


@contextlib.contextmanager
def configuration_change(install: bool = True):
    metadata = trusted_file(TORRC_PATH)
    original = TORRC_PATH.read_bytes()
    content = original.decode("utf-8")
    updated = (managed_content(content) if install else remove_managed_block(content)).encode("utf-8")
    changed = updated != original
    if changed:
        backup = TORRC_PATH.with_name(f"{TORRC_PATH.name}.bak.{time.time_ns()}")
        atomic_write(backup, original, metadata)
        info(f"Configuration backup: {backup}")
    try:
        if changed:
            atomic_write(TORRC_PATH, updated, metadata)
        verify_tor_config(managed=install)
        yield changed
    except BaseException:
        if changed:
            atomic_write(TORRC_PATH, original, metadata)
            warn("Previous torrc restored.")
        raise


def service_properties() -> dict[str, str]:
    proc = run([SYSTEMCTL, "show", TOR_SERVICE, "--no-pager",
                "--property=LoadState,ActiveState,SubState,MainPID"])
    return dict(line.split("=", 1) for line in proc.stdout.splitlines() if "=" in line)


def service_pid() -> int:
    properties = service_properties()
    if properties.get("LoadState") != "loaded":
        raise ToryfikatorError(f"{TOR_SERVICE} is unavailable; install the standard Debian/Kali tor package.")
    if properties.get("ActiveState") != "active" or properties.get("SubState") != "running":
        raise ToryfikatorError(f"{TOR_SERVICE} is not running.")
    try:
        pid = int(properties.get("MainPID", "0"))
    except ValueError as exc:
        raise ToryfikatorError("Invalid MainPID returned by systemd.") from exc
    if pid <= 0:
        raise ToryfikatorError("Tor has no running main process.")
    status = (PROC_ROOT / str(pid) / "status").read_text()
    uids = next((line.split()[1:] for line in status.splitlines() if line.startswith("Uid:")), [])
    if len(uids) != 4 or any(int(uid) != tor_uid() for uid in uids):
        raise ToryfikatorError(f"Tor PID {pid} is not running exclusively as {TOR_USER}.")
    if (PROC_ROOT / str(pid) / "exe").resolve() != Path(TOR_BIN).resolve():
        raise ToryfikatorError("Tor MainPID does not point to the expected executable.")
    return pid


def listeners_ready(pid: int) -> bool:
    directory = PROC_ROOT / str(pid)
    inodes = set()
    for fd in (directory / "fd").iterdir():
        try:
            target = os.readlink(fd)
        except FileNotFoundError:
            continue
        if target.startswith("socket:["):
            inodes.add(target[8:-1])
    for protocol, port, state in (("tcp", TOR_TRANS_PORT, "0A"), ("udp", TOR_DNS_PORT, "07")):
        address = f"0100007F:{port:04X}"
        rows = [line.split() for line in (directory / "net" / protocol).read_text().splitlines()[1:]]
        if not any(len(row) > 9 and row[1] == address and row[3] == state
                   and row[9] in inodes for row in rows):
            return False
    return True


def wait_for_listeners(timeout: float = 15) -> None:
    deadline = time.monotonic() + timeout
    detail = "Tor listeners are unavailable."
    while time.monotonic() < deadline:
        try:
            if listeners_ready(service_pid()):
                return
        except (OSError, ToryfikatorError) as exc:
            detail = str(exc)
        time.sleep(0.25)
    raise ToryfikatorError(f"Tor did not expose its TCP/UDP listeners: {detail}")


def nft_table_exists() -> bool:
    data = json.loads(run([NFT, "-j", "list", "tables"]).stdout)
    return any(item.get("table", {}).get("family") == NFT_FAMILY
               and item.get("table", {}).get("name") == NFT_TABLE for item in data["nftables"])


def generate_nft_conf(uid: int | None = None) -> str:
    uid = tor_uid() if uid is None else uid
    if not isinstance(uid, int) or isinstance(uid, bool) or uid <= 0:
        raise ToryfikatorError("Invalid Tor UID.")
    local = ", ".join(LOCAL_NETWORKS)
    return f"""table inet toryfikator {{
    chain nat_output {{
        type nat hook output priority -100; policy accept;
        meta skuid {uid} return
        meta nfproto ipv4 udp dport 53 redirect to {TOR_DNS_PORT}
        meta nfproto ipv4 tcp dport 53 redirect to {TOR_TRANS_PORT}
        ip daddr {TOR_VADDR_NET} meta l4proto tcp redirect to {TOR_TRANS_PORT}
        ip daddr 127.0.0.0/8 return
        ip daddr {{ {local} }} return
        meta nfproto ipv4 meta l4proto tcp redirect to {TOR_TRANS_PORT}
    }}
    chain filter_output {{
        type filter hook output priority 0; policy drop;
        oifname "lo" accept
        meta nfproto ipv6 reject with icmpx type admin-prohibited
        meta skuid {uid} meta l4proto tcp accept
        ct status dnat meta nfproto ipv4 meta l4proto tcp accept
        ct status dnat meta nfproto ipv4 udp dport {TOR_DNS_PORT} accept
        ip daddr {TOR_VADDR_NET} reject with icmpx type admin-prohibited
        meta l4proto {{ tcp, udp }} th dport 53 reject with icmpx type admin-prohibited
        ip daddr {{ {local} }} meta l4proto tcp accept
        udp sport 68 udp dport 67 accept
        reject with icmpx type admin-prohibited
    }}
    chain filter_forward {{
        type filter hook forward priority 0; policy drop;
    }}
}}
"""


def apply_nft_rules() -> None:
    prefix = f"delete table {NFT_FAMILY} {NFT_TABLE}\n" if nft_table_exists() else ""
    batch = prefix + generate_nft_conf()
    run([NFT, "--check", "-f", "-"], input=batch)
    run([NFT, "-f", "-"], input=batch)


def remove_nft_rules() -> None:
    if nft_table_exists():
        run([NFT, "delete", "table", NFT_FAMILY, NFT_TABLE])


def load_state() -> dict:
    if not STATE_FILE.exists() and not STATE_FILE.is_symlink():
        return {}
    trusted_file(STATE_FILE)
    try:
        data = json.loads(STATE_FILE.read_text())
    except ValueError as exc:
        raise ToryfikatorError(f"Invalid state file: {STATE_FILE}; refusing to guess previous IPv6 settings.") from exc
    if not isinstance(data, dict):
        raise ToryfikatorError("Invalid state structure.")
    return data


def save_state(data: dict) -> None:
    STATE_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    metadata = STATE_DIR.lstat()
    if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != 0 or metadata.st_mode & 0o022:
        raise ToryfikatorError("Unsafe state directory.")
    if STATE_FILE.exists() or STATE_FILE.is_symlink():
        trusted_file(STATE_FILE)
    atomic_write(STATE_FILE, (json.dumps(data, indent=2) + "\n").encode())


def restore_legacy_ipv6() -> None:
    data = load_state()
    previous = data.get("ipv6_previous")
    if previous is None:
        return
    allowed = {"net.ipv6.conf.all.disable_ipv6", "net.ipv6.conf.default.disable_ipv6"}
    if not isinstance(previous, dict) or any(key not in allowed or value not in (None, "0", "1")
                                             for key, value in previous.items()):
        raise ToryfikatorError("Invalid legacy IPv6 state.")
    for key in sorted(previous):
        value = previous[key]
        path = PROC_ROOT / "sys" / Path(key.replace(".", "/"))
        if value is not None and path.exists():
            path.write_text(value + "\n")
    data.pop("ipv6_previous")
    save_state(data)
    info("Restored IPv6 settings recorded by version 0.3.0.")


def check_exit() -> dict:
    proc = run([
        CURL,
        "--disable",
        "--silent",
        "--show-error",
        "--fail",
        "--ipv4",
        "--noproxy",
        "",
        "--socks5-hostname",
        f"127.0.0.1:{TOR_SOCKS_PORT}",
        "--proto",
        "=https",
        "--connect-timeout",
        "5",
        "--max-time",
        "20",
        "--max-filesize",
        "8192",
        "https://check.torproject.org/api/ip",
    ], timeout=23)

    try:
        if len(proc.stdout) > 8192:
            raise ValueError("Oversized response")
        data = json.loads(proc.stdout)
        if not isinstance(data, dict) or not isinstance(data.get("IsTor"), bool):
            raise ValueError("Unexpected response")
        address = ipaddress.IPv4Address(data["IP"])
    except (ValueError, KeyError, TypeError) as exc:
        raise ToryfikatorError("Invalid response from the Tor exit check.") from exc

    return {"IP": str(address), "IsTor": data["IsTor"]}

def wait_for_exit(attempts: int = 6) -> dict:
    detail = "Tor has not bootstrapped yet."
    for attempt in range(attempts):
        if not nft_table_exists():
            raise ToryfikatorError("Toryfikator firewall was removed during startup.")
        service_pid()
        try:
            data = check_exit()
        except (OSError, ToryfikatorError) as exc:
            detail = str(exc)
        else:
            if not data["IsTor"]:
                raise ToryfikatorError("Exit check reports a non-Tor address. Check conflicting firewall/NAT rules.")
            return data
        if attempt + 1 < attempts:
            time.sleep(2)
    raise ToryfikatorError(f"Tor exit check failed. Retry start after checking Tor/network availability. {detail}")


def ensure_dependencies() -> None:
    require_binaries(NFT, SYSTEMCTL, TOR_BIN, CURL)
    trusted_file(TORRC_PATH)
    trusted_file(TOR_DEFAULTS)
    tor_uid()
    if service_properties().get("LoadState") != "loaded":
        raise ToryfikatorError(f"Required service is missing: {TOR_SERVICE}")


def cmd_configure() -> None:
    require_binaries(TOR_BIN)
    trusted_file(TOR_DEFAULTS)
    tor_uid()
    with configuration_change():
        pass
    info("Tor configuration validated as debian-tor. Run start to activate routing.")


def cmd_start() -> None:
    ensure_dependencies()
    load_state()
    info("Installing firewall protection before restarting Tor...")
    apply_nft_rules()
    try:
        restore_legacy_ipv6()
        with configuration_change():
            pass
        run([SYSTEMCTL, "restart", TOR_SERVICE], timeout=90)
        wait_for_listeners()
        info("Waiting for Tor bootstrap and checking the exit address...")
        result = wait_for_exit()
    except BaseException:
        warn("Startup failed. Firewall protection remains enabled; retry start or use stop to restore direct networking.")
        raise
    info(f"Torification started. Verified Tor exit: {result['IP']}")


def cmd_stop() -> None:
    require_binaries(NFT)
    restore_legacy_ipv6()
    remove_nft_rules()
    info("Torification stopped. Direct networking is enabled.")


def cmd_uninstall() -> None:
    require_binaries(NFT)
    restore_legacy_ipv6()
    if TORRC_PATH.exists():
        content = TORRC_PATH.read_text()
        if remove_managed_block(content) != content:
            require_binaries(TOR_BIN, SYSTEMCTL)
            trusted_file(TOR_DEFAULTS)
            tor_uid()
            with configuration_change(install=False) as changed:
                if changed and service_properties().get("ActiveState") == "active":
                    run([SYSTEMCTL, "restart", TOR_SERVICE], timeout=90)
    remove_nft_rules()
    info("Toryfikator configuration removed. Direct networking is enabled.")


def show_status(network_check: bool = False) -> None:
    require_binaries(NFT)
    active = nft_table_exists()
    print(f"Firewall table present: {'yes' if active else 'no'}")
    ready = False
    try:
        pid = service_pid()
        ready = listeners_ready(pid)
        print(f"Tor service: {TOR_SERVICE}, PID {pid}, user {TOR_USER}")
        print(f"Owned Tor listeners ready: {'yes' if ready else 'no'}")
    except (OSError, ToryfikatorError) as exc:
        print(f"Tor service: unavailable ({exc})")
    if not network_check:
        print("No network request made. Use status --check to verify the exit address.")
        return
    if not active:
        raise ToryfikatorError("Refusing an exit check without Toryfikator firewall rules. Run start first.")
    if not ready:
        raise ToryfikatorError("Tor listeners are not ready. Fix startup and retry start; use stop for direct networking.")
    require_binaries(CURL)
    result = check_exit()
    print(f"Public IP: {result['IP']}")
    print(f"Tor exit: {'yes' if result['IsTor'] else 'no'}")
    if not result["IsTor"]:
        raise ToryfikatorError("Exit address is not recognised as Tor.")


def interrupted(signum, frame) -> None:
    raise KeyboardInterrupt


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Transparent Tor routing for Kali Linux / Debian.")
    parser.add_argument("--version", action="version", version=VERSION)
    commands = parser.add_subparsers(dest="command")
    for name in ("start", "stop", "restart", "configure", "uninstall", "help"):
        commands.add_parser(name)
    status_parser = commands.add_parser("status")
    status_parser.add_argument("--check", action="store_true", help="Contact Tor Project to verify the exit IP")
    args = parser.parse_args(argv)
    if args.command in (None, "help"):
        parser.print_help()
        return 0
    previous_handler = signal.signal(signal.SIGTERM, interrupted)
    try:
        ensure_root()
        with command_lock():
            if args.command == "status":
                show_status(args.check)
            else:
                actions = {"start": cmd_start, "restart": cmd_start, "stop": cmd_stop,
                           "configure": cmd_configure, "uninstall": cmd_uninstall}
                actions[args.command]()
        return 0
    except KeyboardInterrupt:
        warn("Interrupted. Firewall rules were not removed; use stop to restore direct networking.")
        return 130
    except (OSError, ValueError, ToryfikatorError) as exc:
        warn(str(exc))
        return 1
    finally:
        signal.signal(signal.SIGTERM, previous_handler)


def cli_main() -> None:
    raise SystemExit(main())


if __name__ == "__main__":
    cli_main()
