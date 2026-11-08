import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock

from correo_limpio.config import load_config


class ConfigTest(unittest.TestCase):
    def test_defaults_use_xdg_paths(self):
        with TemporaryDirectory() as tmp, mock.patch.dict("os.environ", {"HOME": tmp}, clear=False):
            cfg = load_config()
            self.assertEqual(cfg.config_dir, Path(tmp) / ".config" / "correo-limpio")
            self.assertEqual(cfg.state_dir, Path(tmp) / ".local" / "state" / "correo-limpio")
            self.assertEqual(cfg.max_per_run, 200)
            self.assertEqual(cfg.inbox_lookback_days, 90)
            self.assertIsNone(cfg.client_id)


if __name__ == "__main__":
    unittest.main()
