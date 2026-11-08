import unittest
from unittest import mock

from mail_triage.keychain import MacKeychain, MemoryStore


class KeychainTest(unittest.TestCase):
    def test_memory_roundtrip(self):
        store = MemoryStore()
        self.assertIsNone(store.get("refresh-token"))
        store.set("refresh-token", "abc")
        self.assertEqual(store.get("refresh-token"), "abc")
        store.delete("refresh-token")
        self.assertIsNone(store.get("refresh-token"))

    def test_mac_keychain_uses_security_cli(self):
        run = mock.Mock(return_value=mock.Mock(stdout=b"secret\n", returncode=0))
        store = MacKeychain(run=run)
        self.assertEqual(store.get("refresh-token"), "secret")
        args = run.call_args.args[0]
        self.assertEqual(args[:3], ["security", "find-generic-password", "-s"])
        self.assertIn("mail-triage", args)

    def test_mac_keychain_missing_returns_none(self):
        run = mock.Mock(return_value=mock.Mock(stdout=b"", returncode=44))
        self.assertIsNone(MacKeychain(run=run).get("refresh-token"))


if __name__ == "__main__":
    unittest.main()
