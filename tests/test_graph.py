import unittest

from correo_limpio.graph import GraphClient, GraphError, DELETED
from correo_limpio.http import HttpResponse


class FakeHttp:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def request(self, method, url, headers=None, body=None, form=None, timeout=30):
        self.calls.append((method, url, body))
        return self.responses.pop(0)


class GraphTest(unittest.TestCase):
    def client(self, responses):
        self.http = FakeHttp(responses)
        return GraphClient(self.http, token_provider=lambda: "token")

    def test_list_junk_follows_pagination_and_skips_seen(self):
        g = self.client([
            HttpResponse(200, {"value": [{"id": "1"}, {"id": "2"}],
                               "@odata.nextLink": "https://graph.microsoft.com/v1.0/next"}, ""),
            HttpResponse(200, {"value": [{"id": "3"}]}, ""),
        ])
        messages, has_more = g.list_junk(max_items=10, skip_ids={"2"})
        self.assertEqual([m["id"] for m in messages], ["1", "3"])
        self.assertFalse(has_more)
        self.assertIn("junkemail", self.http.calls[0][1])

    def test_list_junk_reports_more_at_cap(self):
        g = self.client([HttpResponse(200, {"value": [{"id": "1"}],
                                           "@odata.nextLink": "next"}, "")])
        messages, has_more = g.list_junk(max_items=1, skip_ids=set())
        self.assertEqual(len(messages), 1)
        self.assertTrue(has_more)

    def test_move_posts_destination(self):
        g = self.client([HttpResponse(200, {}, "")])
        g.move("m1", DELETED)
        method, url, body = self.http.calls[0]
        self.assertEqual(method, "POST")
        self.assertTrue(url.endswith("/me/messages/m1/move"))
        self.assertEqual(body, {"destinationId": "deleteditems"})

    def test_http_error_raises_graph_error(self):
        g = self.client([HttpResponse(404, {"error": {"code": "ErrorItemNotFound"}}, "")])
        with self.assertRaises(GraphError) as ctx:
            g.move("gone", DELETED)
        self.assertEqual(ctx.exception.status, 404)


if __name__ == "__main__":
    unittest.main()
