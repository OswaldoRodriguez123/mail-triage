import sys
import unittest
import uuid
from unittest import mock

from mail_triage.keychain import MacKeychain, MemoryStore
from mail_triage import keychain

DARWIN = sys.platform == "darwin"


class KeychainTest(unittest.TestCase):
    def test_memory_roundtrip(self):
        store = MemoryStore()
        self.assertIsNone(store.get("refresh-token"))
        store.set("refresh-token", "abc")
        self.assertEqual(store.get("refresh-token"), "abc")
        store.delete("refresh-token")
        self.assertIsNone(store.get("refresh-token"))

    def test_mac_keychain_reads_through_the_framework(self):
        reader = mock.Mock(side_effect=[None, "secret"])
        store = MacKeychain(reader=reader)
        self.assertEqual(store.get("refresh-token"), "secret")
        self.assertEqual(
            [call.args for call in reader.call_args_list],
            [("mail-triage", "refresh-token"), ("correo-limpio", "refresh-token")],
        )

    def test_mac_keychain_missing_returns_none(self):
        store = MacKeychain(reader=mock.Mock(return_value=None))
        self.assertIsNone(store.get("refresh-token"))


class _FakeSecurity:
    def __init__(self, find_statuses, add_status=0, modify_status=0):
        self.find_statuses = list(find_statuses)
        self.add_status = add_status
        self.modify_status = modify_status
        self.add_args = None
        self.modified = False

    def SecKeychainFindGenericPassword(self, *args):
        return self.find_statuses.pop(0) if self.find_statuses else -25300

    def SecKeychainAddGenericPassword(self, *args):
        self.add_args = args
        return self.add_status

    def SecKeychainItemModifyAttributesAndData(self, *args):
        self.modified = True
        return self.modify_status


class KeychainWriteTest(unittest.TestCase):
    def write(self, fake, value, release=None):
        with mock.patch.object(keychain, "_security", return_value=fake), \
             mock.patch.object(keychain, "_cf_release", release or mock.Mock()):
            keychain._keychain_write("svc", "acct", value)

    def test_empty_value_does_not_crash(self):
        fake = _FakeSecurity([-25300])
        self.write(fake, "")
        self.assertEqual(fake.add_args[5], 0)

    def test_releases_the_item_after_update(self):
        fake = _FakeSecurity([0])
        release = mock.Mock()
        self.write(fake, "x", release)
        release.assert_called_once()

    def test_retries_as_update_when_add_hits_a_duplicate(self):
        fake = _FakeSecurity([-25300, 0], add_status=-25299)
        self.write(fake, "x")
        self.assertTrue(fake.modified)


@unittest.skipUnless(DARWIN, "usa el Keychain de macOS")
class KeychainLongSecretTest(unittest.TestCase):
    def setUp(self):
        self.account = f"roundtrip-{uuid.uuid4()}"
        self.store = MacKeychain(services=("mail-triage-test",))
        self.addCleanup(self._cleanup)

    def _cleanup(self):
        try:
            self.store.delete(self.account)
        except RuntimeError:
            pass

    def test_stores_secrets_longer_than_128_chars(self):
        # `security ... -w` reads at most 128 characters from stdin, which
        # silently truncated OAuth refresh tokens and broke the next refresh.
        secret = "Z" * 1500
        self.store.set(self.account, secret)
        self.assertEqual(self.store.get(self.account), secret)


if __name__ == "__main__":
    unittest.main()
