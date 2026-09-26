import contextlib
import io
import json
import os
import signal
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from toryfikator import cli as c


def result(output="", code=0, error=""):
    return subprocess.CompletedProcess([], code, output, error)


def config_output():
    return "\n".join((f"User {c.TOR_USER}", f"TransPort 127.0.0.1:{c.TOR_TRANS_PORT}",
                      f"DNSPort 127.0.0.1:{c.TOR_DNS_PORT}", f"VirtualAddrNetworkIPv4 {c.TOR_VADDR_NET}",
                      "AutomapHostsOnResolve 1", "AutomapHostsSuffixes .onion", "DisableNetwork 0"))


class ConfigurationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "torrc"
        self.original = b"SocksPort 9050\n"
        self.path.write_bytes(self.original)
        self.path.chmod(0o640)
        self.stack = contextlib.ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(patch.object(c, "TORRC_PATH", self.path))
        self.stack.enter_context(patch.object(c, "trusted_file", side_effect=lambda p: p.stat()))
        self.stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
        self.stack.enter_context(contextlib.redirect_stderr(io.StringIO()))

    def test_invalid_configuration_restores_exact_bytes(self):
        with patch.object(c, "verify_tor_config", side_effect=c.ToryfikatorError("invalid")):
            with self.assertRaises(c.ToryfikatorError):
                with c.configuration_change():
                    self.fail("invalid configuration accepted")
        self.assertEqual(self.path.read_bytes(), self.original)
        self.assertEqual(stat.S_IMODE(self.path.stat().st_mode), 0o640)

    def test_interrupt_restores_configuration(self):
        with patch.object(c, "verify_tor_config", side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt):
                with c.configuration_change():
                    pass
        self.assertEqual(self.path.read_bytes(), self.original)

    def test_valid_edit_is_idempotent_and_preserves_mode(self):
        with patch.object(c, "verify_tor_config"):
            with c.configuration_change() as changed:
                self.assertTrue(changed)
            first = self.path.read_bytes()
            with c.configuration_change() as changed:
                self.assertFalse(changed)
        self.assertEqual(self.path.read_bytes(), first)
        self.assertEqual(stat.S_IMODE(self.path.stat().st_mode), 0o640)
        self.assertEqual(len(list(self.path.parent.glob("torrc.bak.*"))), 1)

    def test_backups_do_not_collide(self):
        with patch.object(c, "verify_tor_config"):
            with c.configuration_change():
                pass
            with c.configuration_change(install=False):
                pass
        self.assertEqual(len(list(self.path.parent.glob("torrc.bak.*"))), 2)

    def test_remove_preserves_unmanaged_text(self):
        before = "SocksPort 9050\n\n"
        after = "\nHiddenServiceDir /var/lib/tor/test\n"
        self.assertEqual(c.remove_managed_block(before + c.TORRC_BLOCK + after), before + after)

    def test_malformed_markers_rejected(self):
        for text in (c.TORRC_BEGIN, c.TORRC_END, c.TORRC_END + "\n" + c.TORRC_BEGIN,
                     c.TORRC_BLOCK * 2):
            with self.subTest(text=text), self.assertRaises(c.ToryfikatorError):
                c.remove_managed_block(text)

    def test_comment_mention_is_not_marker(self):
        text = "# Notes: " + c.TORRC_BEGIN + "\n"
        self.assertEqual(c.remove_managed_block(text), text)

    def test_atomic_replace_failure_keeps_original(self):
        with patch.object(c.os, "replace", side_effect=OSError("failure")):
            with self.assertRaises(OSError):
                c.atomic_write(self.path, b"modified", self.path.stat())
        self.assertEqual(self.path.read_bytes(), self.original)
        self.assertEqual(list(self.path.parent.glob(".torrc.*")), [])

    def test_validation_uses_tor_privilege_drop_with_service_defaults(self):
        with patch.object(c, "run", side_effect=[result(), result(config_output())]) as run:
            c.verify_tor_config()
        args = run.call_args_list[0].args[0]
        self.assertEqual(args[0], c.TOR_BIN)
        self.assertNotIn("runuser", " ".join(args))
        self.assertNotIn("--User", args)
        self.assertEqual(args[args.index("--RunAsDaemon") + 1], "0")
        self.assertIn(str(c.TOR_DEFAULTS), args)
        self.assertIn("--verify-config", args)

    def test_wrong_user_or_duplicate_listener_rejected(self):
        for output in (config_output().replace("User debian-tor", "User root"),
                       config_output() + "\nTransPort 0.0.0.0:9040",
                       config_output().replace("DisableNetwork 0", "DisableNetwork 1")):
            with patch.object(c, "run", side_effect=[result(), result(output)]):
                with self.assertRaises(c.ToryfikatorError):
                    c.verify_tor_config()


class FirewallTests(unittest.TestCase):
    def test_rules_cover_onion_and_fail_closed(self):
        text = c.generate_nft_conf(123)
        self.assertLess(text.index(f"ip daddr {c.TOR_VADDR_NET} meta l4proto tcp redirect"),
                        text.index("ip daddr { 10.0.0.0/8"))
        self.assertIn("type filter hook output priority 0; policy drop;", text)
        self.assertIn("type filter hook forward priority 0; policy drop;", text)
        self.assertIn("meta nfproto ipv6 reject", text)
        self.assertNotIn("ct state established", text)
        self.assertIn("ct status dnat meta nfproto ipv4 meta l4proto tcp accept", text)
        self.assertIn(f"ct status dnat meta nfproto ipv4 udp dport {c.TOR_DNS_PORT} accept", text)
        self.assertIn(f"tcp dport 53 redirect to {c.TOR_TRANS_PORT}", text)
        self.assertNotIn(f"tcp dport 53 redirect to {c.TOR_DNS_PORT}", text)
        self.assertLess(text.index("udp dport 53 redirect"), text.index("ip daddr 127.0.0.0/8 return"))

    def test_zero_uid_rejected(self):
        for uid in (0, -1, True, "123"):
            with self.assertRaises(c.ToryfikatorError):
                c.generate_nft_conf(uid)

    def test_replacement_uses_one_transaction(self):
        with patch.object(c, "nft_table_exists", return_value=True), patch.object(c, "tor_uid", return_value=123), patch.object(c, "run") as run:
            c.apply_nft_rules()
        self.assertEqual(run.call_count, 2)
        checked, applied = run.call_args_list
        self.assertIn("--check", checked.args[0])
        self.assertEqual(checked.kwargs["input"], applied.kwargs["input"])
        self.assertTrue(applied.kwargs["input"].startswith("delete table inet toryfikator\ntable"))
        self.assertEqual(applied.args[0], [c.NFT, "-f", "-"])

    def test_failed_validation_does_not_apply(self):
        with patch.object(c, "nft_table_exists", return_value=True), patch.object(c, "tor_uid", return_value=123), patch.object(c, "run", side_effect=c.ToryfikatorError("invalid")) as run:
            with self.assertRaises(c.ToryfikatorError):
                c.apply_nft_rules()
        self.assertEqual(run.call_count, 1)
        self.assertIn("--check", run.call_args.args[0])

    def test_nft_permission_error_not_treated_as_absent_table(self):
        with patch.object(c, "run", side_effect=c.ToryfikatorError("permission denied")):
            with self.assertRaises(c.ToryfikatorError):
                c.nft_table_exists()

    def test_delete_failure_not_reported_as_success(self):
        with patch.object(c, "nft_table_exists", return_value=True), patch.object(c, "run", side_effect=c.ToryfikatorError("failed")):
            with self.assertRaises(c.ToryfikatorError):
                c.remove_nft_rules()

    def test_table_detection_requires_family_and_name(self):
        for family, name, expected in (("inet", "toryfikator", True), ("ip", "toryfikator", False), ("inet", "other", False)):
            with patch.object(c, "run", return_value=result(json.dumps({"nftables": [{"table": {"family": family, "name": name}}]}))):
                self.assertEqual(c.nft_table_exists(), expected)


class LifecycleTests(unittest.TestCase):
    def setUp(self):
        self.stack = contextlib.ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
        self.stack.enter_context(contextlib.redirect_stderr(io.StringIO()))

    def start_mocks(self):
        names = ("ensure_dependencies", "load_state", "apply_nft_rules", "restore_legacy_ipv6",
                 "configuration_change", "run", "wait_for_listeners", "wait_for_exit", "remove_nft_rules")
        return {name: self.stack.enter_context(patch.object(c, name)) for name in names}

    def test_failed_start_keeps_firewall(self):
        mocks = self.start_mocks()
        mocks["run"].side_effect = c.ToryfikatorError("service failed")
        with self.assertRaises(c.ToryfikatorError):
            c.cmd_start()
        mocks["apply_nft_rules"].assert_called_once()
        mocks["remove_nft_rules"].assert_not_called()

    def test_interrupted_start_keeps_firewall(self):
        mocks = self.start_mocks()
        mocks["wait_for_exit"].side_effect = KeyboardInterrupt
        with self.assertRaises(KeyboardInterrupt):
            c.cmd_start()
        mocks["remove_nft_rules"].assert_not_called()

    def test_protection_precedes_service_restart(self):
        mocks = self.start_mocks()
        order = []
        mocks["apply_nft_rules"].side_effect = lambda: order.append("firewall")
        mocks["run"].side_effect = lambda *a, **k: order.append("restart")
        mocks["wait_for_exit"].return_value = {"IP": "192.0.2.1", "IsTor": True}
        c.cmd_start()
        self.assertEqual(order, ["firewall", "restart"])
        mocks["run"].assert_called_once_with([c.SYSTEMCTL, "restart", "tor@default.service"], timeout=90)

    def test_restart_never_stops_protection(self):
        with patch.object(c, "ensure_root"), patch.object(c, "command_lock"), patch.object(c, "cmd_start") as start, patch.object(c, "cmd_stop") as stop:
            self.assertEqual(c.main(["restart"]), 0)
        start.assert_called_once()
        stop.assert_not_called()

    def test_stop_does_not_require_tor(self):
        with patch.object(c, "require_binaries") as require, patch.object(c, "restore_legacy_ipv6"), patch.object(c, "remove_nft_rules") as remove:
            c.cmd_stop()
        require.assert_called_once_with(c.NFT)
        remove.assert_called_once()

    def test_status_is_offline_by_default(self):
        with patch.object(c, "require_binaries"), patch.object(c, "nft_table_exists", return_value=False), patch.object(c, "service_pid", side_effect=c.ToryfikatorError("off")), patch.object(c, "check_exit") as check:
            c.show_status()
        check.assert_not_called()

    def test_status_check_refuses_unprotected_network(self):
        with patch.object(c, "require_binaries"), patch.object(c, "nft_table_exists", return_value=False), patch.object(c, "service_pid", side_effect=c.ToryfikatorError("off")), patch.object(c, "check_exit") as check:
            with self.assertRaises(c.ToryfikatorError):
                c.show_status(True)
        check.assert_not_called()

    def test_status_check_refuses_missing_listeners(self):
        with patch.object(c, "require_binaries"), patch.object(c, "nft_table_exists", return_value=True), patch.object(c, "service_pid", return_value=42), patch.object(c, "listeners_ready", return_value=False), patch.object(c, "check_exit") as check:
            with self.assertRaisesRegex(c.ToryfikatorError, "listeners are not ready"):
                c.show_status(True)
        check.assert_not_called()

    def test_status_check_refuses_stopped_service(self):
        with patch.object(c, "require_binaries"), patch.object(c, "nft_table_exists", return_value=True), patch.object(c, "service_pid", side_effect=c.ToryfikatorError("stopped")), patch.object(c, "check_exit") as check:
            with self.assertRaisesRegex(c.ToryfikatorError, "listeners are not ready"):
                c.show_status(True)
        check.assert_not_called()

    def test_exit_check_is_bounded(self):
        with patch.object(c, "nft_table_exists", return_value=True), patch.object(c, "service_pid", return_value=1), patch.object(c, "check_exit", side_effect=c.ToryfikatorError("offline")) as check, patch.object(c.time, "sleep"):
            with self.assertRaises(c.ToryfikatorError):
                c.wait_for_exit(3)
        self.assertEqual(check.call_count, 3)

    def test_non_tor_exit_is_fatal_without_retry(self):
        with patch.object(c, "nft_table_exists", return_value=True), patch.object(c, "service_pid", return_value=1), patch.object(c, "check_exit", return_value={"IP": "192.0.2.1", "IsTor": False}) as check:
            with self.assertRaises(c.ToryfikatorError):
                c.wait_for_exit()
        self.assertEqual(check.call_count, 1)

    def test_removed_firewall_aborts_exit_check(self):
        with patch.object(c, "nft_table_exists", return_value=False), patch.object(c, "check_exit") as check:
            with self.assertRaises(c.ToryfikatorError):
                c.wait_for_exit()
        check.assert_not_called()

    def test_help_and_version_do_not_elevate(self):
        with patch.object(c, "ensure_root") as root:
            self.assertEqual(c.main(["help"]), 0)
            with self.assertRaises(SystemExit) as caught:
                c.main(["--version"])
            self.assertEqual(caught.exception.code, 0)
        root.assert_not_called()

    def test_interrupt_exit_code(self):
        with patch.object(c, "ensure_root"), patch.object(c, "command_lock"), patch.object(c, "cmd_start", side_effect=KeyboardInterrupt):
            self.assertEqual(c.main(["start"]), 130)


class SystemTests(unittest.TestCase):
    def test_timeout_becomes_cli_error(self):
        with patch.object(c.subprocess, "run", side_effect=subprocess.TimeoutExpired("x", 1)):
            with self.assertRaises(c.ToryfikatorError):
                c.run(["x"], timeout=1)

    def test_environment_proxies_removed(self):
        with patch.dict(os.environ, {"HTTP_PROXY": "http://proxy", "https_proxy": "http://proxy", "PYTHONPATH": "/bad"}), patch.object(c.subprocess, "run", return_value=result()) as run:
            c.run(["x"])
        env = run.call_args.kwargs["env"]
        self.assertNotIn("HTTP_PROXY", env)
        self.assertNotIn("https_proxy", env)
        self.assertNotIn("PYTHONPATH", env)
        self.assertEqual(env["LC_ALL"], "C")

    def test_auto_sudo_uses_isolated_absolute_script(self):
        with patch.object(c.os, "geteuid", return_value=1000), patch.object(c.os, "access", return_value=True), patch.object(c.os, "execv", side_effect=RuntimeError) as execute, contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaises(RuntimeError):
                c.ensure_root()
        args = execute.call_args.args[1]
        self.assertIn("-I", args)
        self.assertIn(str(Path(c.__file__).resolve()), args)
        self.assertNotIn("-m", args)

    def test_curl_ignores_config_and_proxies(self):
        with patch.object(c, "run", return_value=result('{"IP":"192.0.2.1","IsTor":true}')) as run:
            self.assertTrue(c.check_exit()["IsTor"])
        args = run.call_args.args[0]
        self.assertEqual(args[1], "--disable")
        self.assertIn("--noproxy", args)
        self.assertIn("--ipv4", args)

    def test_invalid_exit_responses_rejected(self):
        for body in ('[]', '{}', '{"IP":"192.0.2.1","IsTor":"true"}', '{"IP":"nonsense","IsTor":true}', 'x' * 8193):
            with patch.object(c, "run", return_value=result(body)), self.assertRaises(c.ToryfikatorError):
                c.check_exit()

    def test_meta_service_is_not_accepted(self):
        with patch.object(c, "service_properties", return_value={"LoadState": "loaded", "ActiveState": "active", "SubState": "exited", "MainPID": "0"}):
            with self.assertRaises(c.ToryfikatorError):
                c.service_pid()

    def test_root_tor_process_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "42").mkdir()
            (root / "42" / "status").write_text("Uid:\t0\t0\t0\t0\n")
            with patch.object(c, "PROC_ROOT", root), patch.object(c, "tor_uid", return_value=123), patch.object(c, "service_properties", return_value={"LoadState": "loaded", "ActiveState": "active", "SubState": "running", "MainPID": "42"}):
                with self.assertRaises(c.ToryfikatorError):
                    c.service_pid()

    def test_listeners_must_belong_to_tor(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            process = root / "42"
            (process / "fd").mkdir(parents=True)
            (process / "net").mkdir()
            (process / "fd" / "3").symlink_to("socket:[111]")
            (process / "fd" / "4").symlink_to("socket:[222]")
            for name, port, state, inode in (("tcp", c.TOR_TRANS_PORT, "0A", "111"), ("udp", c.TOR_DNS_PORT, "07", "222")):
                (process / "net" / name).write_text(f"header\n0: 0100007F:{port:04X} 00000000:0000 {state} 0 0 0 123 0 {inode}\n")
            with patch.object(c, "PROC_ROOT", root):
                self.assertTrue(c.listeners_ready(42))
                (process / "fd" / "4").unlink()
                self.assertFalse(c.listeners_ready(42))


class StateTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.directory = Path(self.tmp.name)
        self.stack = contextlib.ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(patch.object(c, "STATE_FILE", self.directory / "state.json"))
        self.stack.enter_context(patch.object(c, "trusted_file", side_effect=lambda p: p.stat()))

    def test_corrupted_state_is_not_silently_ignored(self):
        c.STATE_FILE.write_text("{broken")
        with self.assertRaises(c.ToryfikatorError):
            c.load_state()

    def test_wrong_state_type_rejected(self):
        c.STATE_FILE.write_text("[]")
        with self.assertRaises(c.ToryfikatorError):
            c.load_state()

    def test_legacy_restore_uses_only_recorded_values(self):
        data = {"ipv6_previous": {"net.ipv6.conf.all.disable_ipv6": "0", "net.ipv6.conf.default.disable_ipv6": "1"}}
        for scope in ("all", "default"):
            path = self.directory / "sys/net/ipv6/conf" / scope / "disable_ipv6"
            path.parent.mkdir(parents=True)
            path.write_text("1\n")
        with patch.object(c, "load_state", return_value=data), patch.object(c, "save_state") as save, patch.object(c, "PROC_ROOT", self.directory), contextlib.redirect_stdout(io.StringIO()):
            c.restore_legacy_ipv6()
        self.assertEqual((self.directory / "sys/net/ipv6/conf/all/disable_ipv6").read_text(), "0\n")
        self.assertEqual((self.directory / "sys/net/ipv6/conf/default/disable_ipv6").read_text(), "1\n")
        save.assert_called_once_with({})

    def test_legacy_state_cannot_write_arbitrary_sysctl(self):
        with patch.object(c, "load_state", return_value={"ipv6_previous": {"kernel.randomize_va_space": "0"}}):
            with self.assertRaises(c.ToryfikatorError):
                c.restore_legacy_ipv6()

    def test_no_state_means_no_sysctl_write(self):
        with patch.object(c, "save_state") as save:
            c.restore_legacy_ipv6()
        save.assert_not_called()


class AdditionalSafetyTests(unittest.TestCase):
    def test_validation_retains_error_diagnostics(self):
        self.assertNotIn("--quiet", c.tor_command("--verify-config"))
        self.assertIn("--quiet", c.tor_command("--dump-config full"))

    def test_trusted_file_rejects_symlink(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "real").write_text("data")
            (root / "link").symlink_to(root / "real")
            with self.assertRaises(c.ToryfikatorError):
                c.trusted_file(root / "link")

    def test_trusted_file_rejects_writable_config(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config"
            path.write_text("data")
            path.chmod(0o666)
            with self.assertRaises(c.ToryfikatorError):
                c.trusted_file(path)

    @unittest.skipUnless(os.geteuid() == 0, "Root-owned lock test")
    def test_lock_prevents_concurrent_commands(self):
        with tempfile.TemporaryDirectory() as directory:
            with patch.object(c, "LOCK_PATH", Path(directory) / "lock"):
                with c.command_lock():
                    with self.assertRaises(c.ToryfikatorError):
                        with c.command_lock():
                            pass
                with c.command_lock():
                    pass

    def test_failed_uninstall_retains_firewall_and_config(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "torrc"
            original = "SocksPort 9050\n\n" + c.TORRC_BLOCK
            path.write_text(original)
            with contextlib.ExitStack() as stack:
                stack.enter_context(patch.object(c, "TORRC_PATH", path))
                stack.enter_context(patch.object(c, "TOR_DEFAULTS", path))
                stack.enter_context(patch.object(c, "trusted_file", side_effect=lambda p: p.stat()))
                stack.enter_context(patch.object(c, "require_binaries"))
                stack.enter_context(patch.object(c, "restore_legacy_ipv6"))
                stack.enter_context(patch.object(c, "tor_uid", return_value=123))
                stack.enter_context(patch.object(c, "verify_tor_config", side_effect=c.ToryfikatorError("invalid")))
                remove = stack.enter_context(patch.object(c, "remove_nft_rules"))
                stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
                stack.enter_context(contextlib.redirect_stderr(io.StringIO()))
                with self.assertRaises(c.ToryfikatorError):
                    c.cmd_uninstall()
            self.assertEqual(path.read_text(), original)
            remove.assert_not_called()


if __name__ == "__main__":
    unittest.main()
