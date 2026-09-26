import unittest
from pathlib import Path

import toryfikator
from toryfikator import cli


ROOT = Path(__file__).resolve().parents[1]


class VersionTests(unittest.TestCase):
    def test_version_is_single_sourced(self):
        project = (ROOT / "pyproject.toml").read_text()
        self.assertIn('dynamic = ["version"]', project)
        self.assertIn('version = {attr = "toryfikator.__version__"}', project)
        self.assertEqual(cli.VERSION, toryfikator.__version__)


if __name__ == "__main__":
    unittest.main()
