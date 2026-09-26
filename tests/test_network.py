import os
import shutil
import socket
import subprocess
import sys
import threading
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def command(*args):
    return subprocess.run(args, check=True, capture_output=True, text=True, timeout=15)


def listen_tcp(address, port, message, ipv6=False):
    server = socket.socket(socket.AF_INET6 if ipv6 else socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((address, port))
    server.listen()

    def client(connection):
        with connection:
            try:
                while connection.recv(128):
                    connection.sendall(message)
            except OSError:
                pass

    def accept():
        while True:
            connection, _ = server.accept()
            threading.Thread(target=client, args=(connection,), daemon=True).start()

    threading.Thread(target=accept, daemon=True).start()
    return server


def listen_udp(address, port, message):
    server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server.bind((address, port))

    def serve():
        while True:
            _, peer = server.recvfrom(512)
            server.sendto(message, peer)

    threading.Thread(target=serve, daemon=True).start()
    return server


def peer_server():
    if os.readlink("/proc/self/ns/net") == sys.argv[2]:
        raise RuntimeError("Refusing network changes outside the isolated peer namespace")
    print("ready", flush=True)
    if sys.stdin.readline().strip() != "configure":
        raise RuntimeError("Missing test handshake")
    command("ip", "link", "set", "lo", "up")
    command("ip", "addr", "add", "198.18.0.2/24", "dev", "peer0")
    command("ip", "addr", "add", "10.23.0.2/24", "dev", "peer0")
    command("ip", "-6", "addr", "add", "fd42::2/64", "dev", "peer0", "nodad")
    command("ip", "link", "set", "peer0", "up")
    servers = [listen_tcp("0.0.0.0", 22222, b"DIRECT"), listen_tcp("::", 22223, b"DIRECT", True),
               listen_udp("0.0.0.0", 33333, b"UDP_DIRECT"), listen_udp("0.0.0.0", 53, b"DNS_DIRECT")]
    print("listening", flush=True)
    sys.stdin.read()
    for server in servers:
        server.close()


def tcp(address, port=22222):
    connection = socket.create_connection((address, port), timeout=1)
    connection.settimeout(1)
    connection.sendall(b"test")
    return connection


def tcp_message(address, port=22222):
    with tcp(address, port) as connection:
        return connection.recv(128)


def udp_message(address, port):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as connection:
        connection.settimeout(0.5)
        connection.connect((address, port))
        connection.send(b"test")
        return connection.recv(128)


def blocked(action):
    try:
        action()
    except OSError:
        return
    raise AssertionError("A connection that should be blocked succeeded")


def worker():
    if os.readlink("/proc/self/ns/net") == sys.argv[2]:
        raise RuntimeError("Refusing firewall changes outside an isolated network namespace")
    sys.path.insert(0, str(ROOT))
    from toryfikator import cli as c
    c.tor_uid = lambda: 65534
    command("ip", "link", "set", "lo", "up")
    peer = subprocess.Popen(["unshare", "--net", sys.executable, __file__, "--peer", os.readlink("/proc/self/ns/net")],
                            stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
    try:
        assert peer.stdout.readline().strip() == "ready"
        command("ip", "link", "add", "client0", "type", "veth", "peer", "name", "peer0")
        command("ip", "link", "set", "peer0", "netns", str(peer.pid))
        command("ip", "addr", "add", "198.18.0.1/24", "dev", "client0")
        command("ip", "addr", "add", "10.23.0.1/24", "dev", "client0")
        command("ip", "-6", "addr", "add", "fd42::1/64", "dev", "client0", "nodad")
        command("ip", "link", "set", "client0", "up")
        command("ip", "route", "add", "10.192.0.0/10", "via", "198.18.0.2")
        peer.stdin.write("configure\n")
        peer.stdin.flush()
        assert peer.stdout.readline().strip() == "listening"
        proxies = [listen_tcp("127.0.0.1", c.TOR_TRANS_PORT, b"TOR"),
                   listen_udp("127.0.0.1", c.TOR_DNS_PORT, b"TOR_DNS")]
        assert tcp_message("198.18.0.2") == b"DIRECT"
        assert tcp_message("fd42::2", 22223) == b"DIRECT"
        assert udp_message("198.18.0.2", 33333) == b"UDP_DIRECT"
        previous = tcp("198.18.0.2")
        assert previous.recv(128) == b"DIRECT"
        c.apply_nft_rules()
        assert tcp_message("198.18.0.2") == b"TOR"
        assert tcp_message("10.192.0.1") == b"TOR"
        assert tcp_message("10.23.0.2") == b"DIRECT"
        assert udp_message("198.18.0.2", 53) == b"TOR_DNS"
        assert udp_message("127.0.0.53", 53) == b"TOR_DNS"
        assert tcp_message("198.18.0.2", 53) == b"TOR"
        blocked(lambda: udp_message("198.18.0.2", 33333))
        blocked(lambda: tcp_message("fd42::2", 22223))

        def old_connection():
            previous.sendall(b"again")
            assert previous.recv(128) == b"DIRECT"

        blocked(old_connection)
        previous.close()
        direct = command(sys.executable, "-c", "import os,socket; os.setgid(65534); os.setuid(65534); s=socket.create_connection(('198.18.0.2',22222),2); s.sendall(b'test'); print(s.recv(128).decode())")
        assert direct.stdout.strip() == "DIRECT"
        malformed = "delete table inet toryfikator\ntable inet toryfikator { invalid syntax }\n"
        failed = subprocess.run([c.NFT, "-f", "-"], input=malformed, text=True, capture_output=True)
        assert failed.returncode != 0 and c.nft_table_exists()
        assert tcp_message("198.18.0.2") == b"TOR"
        c.apply_nft_rules()
        assert tcp_message("198.18.0.2") == b"TOR"
        c.remove_nft_rules()
        assert tcp_message("198.18.0.2") == b"DIRECT"
        assert udp_message("198.18.0.2", 33333) == b"UDP_DIRECT"
        assert tcp_message("fd42::2", 22223) == b"DIRECT"
        for proxy in proxies:
            proxy.close()
        print("Network namespace routing checks passed", flush=True)
    finally:
        peer.terminate()
        try:
            peer.wait(timeout=5)
        except subprocess.TimeoutExpired:
            peer.kill()
            peer.wait()


@unittest.skipUnless(os.environ.get("TORYFIKATOR_NETNS_TEST") == "1", "Opt-in root network namespace test")
class NetworkTests(unittest.TestCase):
    def test_real_kernel_routing(self):
        self.assertEqual(os.geteuid(), 0, "Run this opt-in test as root")
        for binary in ("nft", "ip", "unshare"):
            self.assertIsNotNone(shutil.which(binary), f"Missing {binary}")
        completed = subprocess.run(["unshare", "--net", sys.executable, __file__, "--worker", os.readlink("/proc/self/ns/net")],
                                   capture_output=True, text=True, timeout=60)
        self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--worker":
        worker()
    elif len(sys.argv) > 1 and sys.argv[1] == "--peer":
        peer_server()
    else:
        unittest.main()
