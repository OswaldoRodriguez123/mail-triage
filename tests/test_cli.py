import io
import json
import unittest
from contextlib import redirect_stdout
from tempfile import TemporaryDirectory
from unittest import mock

from correo_limpio.cli import main


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


if __name__ == "__main__":
    unittest.main()
