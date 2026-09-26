import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from toryfikator import cli as c


@unittest.skipUnless(os.environ.get("TORYFIKATOR_TOR_TEST") == "1", "Opt-in Debian Tor package validation")
class TorPackageTests(unittest.TestCase):
    def test_real_package_accepts_config_as_debian_tor(self):
        self.assertEqual(os.geteuid(), 0)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            root.chmod(0o755)
            config = root / "torrc"
            config.write_text(c.TORRC_BLOCK)
            config.chmod(0o644)
            with patch.object(c, "TORRC_PATH", config):
                c.verify_tor_config()
                output = c.run(c.tor_command("--verify-config"))
                self.assertNotIn("running Tor as root", output.stdout + output.stderr)
