import unittest
from unittest import mock

from mail_triage.providers.factory import get_provider, list_providers
from mail_triage.providers.outlook import OutlookProvider


class ProviderTest(unittest.TestCase):
    def test_only_outlook_registered(self):
        self.assertIn("outlook", list_providers())

    def test_get_provider_returns_outlook(self):
        graph = mock.Mock()
        provider = get_provider("outlook", graph)
        self.assertIsInstance(provider, OutlookProvider)
        self.assertEqual(provider.name, "outlook")

    def test_unknown_provider_raises(self):
        with self.assertRaises(ValueError):
            get_provider("gmail", mock.Mock())

    def test_outlook_delegates_list_junk(self):
        graph = mock.Mock()
        graph.list_junk.return_value = ([], False)
        provider = OutlookProvider(graph)
        self.assertEqual(provider.list_junk(10, set()), ([], False))
        graph.list_junk.assert_called_once_with(10, set())


if __name__ == "__main__":
    unittest.main()
