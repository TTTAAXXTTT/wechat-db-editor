from __future__ import annotations

import json
import threading
import unittest
from http.server import ThreadingHTTPServer
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import app


class LocalServerTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        app.STATE.clear_session()
        cls.server = ThreadingHTTPServer(('127.0.0.1', 0), app.RequestHandler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.base = f'http://127.0.0.1:{cls.server.server_address[1]}'

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=5)
        app.STATE.clear_session()

    def test_api_requires_current_session_token(self):
        for headers in ({}, {'X-App-Token': 'incorrect'}):
            with self.assertRaises(HTTPError) as result:
                urlopen(Request(self.base + '/api/direct/status', headers=headers), timeout=5)
            self.assertEqual(result.exception.code, 403)
            result.exception.close()

    def test_status_endpoints_do_not_expose_publisher_contact(self):
        for endpoint in ('/api/status', '/api/direct/status'):
            request = Request(self.base + endpoint, headers={'X-App-Token': app.SESSION_TOKEN})
            with urlopen(request, timeout=5) as response:
                payload = json.loads(response.read())
            self.assertTrue(payload['ok'])
            self.assertNotIn('author_contact', payload['data'])
        self.assertFalse(hasattr(app, 'embedded_contact'))

    def test_direct_page_keeps_guide_without_contact_prompt(self):
        with urlopen(self.base + '/direct.html', timeout=5) as response:
            page = response.read().decode('utf-8')
            self.assertIn("frame-ancestors 'none'", response.headers['Content-Security-Policy'])
        self.assertIn('id="startupGuide"', page)
        self.assertNotIn('data-open-contact', page)
        self.assertNotIn('contactDialog', page)
        self.assertNotIn('作者联系方式', page)

    def test_static_path_cannot_escape_static_directory(self):
        with self.assertRaises(HTTPError) as result:
            urlopen(self.base + '/%2e%2e/app.py', timeout=5)
        self.assertEqual(result.exception.code, 404)
        result.exception.close()


if __name__ == '__main__':
    unittest.main()
