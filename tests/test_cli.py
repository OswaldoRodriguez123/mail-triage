import io
import json
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest import mock

from correo_limpio import cli
from correo_limpio.auth import DeviceCode
from correo_limpio.cli import main
from correo_limpio.report import build_report


class StatusTest(unittest.TestCase):
    def test_status_prints_json(self):
        with TemporaryDirectory() as tmp, mock.patch.dict("os.environ", {"HOME": tmp}, clear=False):
            out = io.StringIO()
            with redirect_stdout(out):
                self.assertEqual(main(["status"]), 0)
            data = json.loads(out.getvalue())
            self.assertEqual(data["max_per_run"], 200)
            self.assertIn("config_dir", data)
            self.assertIn("state_dir", data)


class CliWiringTest(unittest.TestCase):
    def run_main(self, argv):
        out = io.StringIO()
        with redirect_stdout(out):
            rc = cli.main(argv)
        return rc, out.getvalue()

    def test_purge_requires_code_and_selection(self):
        self.assertEqual(self.run_main(["purge", "--run", "x"])[0], 2)
        self.assertEqual(self.run_main(["purge", "--run", "x", "--code", "ABC123"])[0], 2)

    def test_feedback_requires_verdict(self):
        self.assertEqual(self.run_main(["feedback", "run1", "1"])[0], 2)

    def test_login_prints_device_code(self):
        with TemporaryDirectory() as tmp, \
             mock.patch.object(cli, "load_config") as cfg, \
             mock.patch.object(cli, "Auth") as auth_cls:
            cfg.return_value = SimpleNamespace(
                client_id="cid", config_dir=Path(tmp), state_dir=Path(tmp),
                max_per_run=200, inbox_lookback_days=90, user_languages=("es", "en"))
            auth_cls.return_value.start_login.return_value = DeviceCode(
                "ABCD", "https://microsoft.com/devicelogin", "dc", 5, 900)
            rc, out = self.run_main(["login"])
        self.assertEqual(rc, 0)
        self.assertIn("ABCD", out)
        self.assertIn("devicelogin", out)

    def test_scan_prints_code(self):
        report, code = build_report([], False, "rules")
        with mock.patch.object(cli, "scan", return_value=(report, code)), \
             mock.patch.object(cli, "build_context", return_value=mock.Mock()):
            rc, out = self.run_main(["scan"])
        self.assertEqual(rc, 0)
        self.assertIn(code, out)
        self.assertIn("Código", out)


if __name__ == "__main__":
    unittest.main()
