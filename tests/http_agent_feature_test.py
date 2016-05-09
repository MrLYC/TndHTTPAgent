#!/usr/bin/env python
# encoding: utf-8

import os
from urlparse import urljoin
from unittest import TestCase, main

import requests


class HttpAgentTestCase(TestCase):
    UrlPath = ""

    def setUp(self):
        self.base_url = "http://httpbin.org"
        self.url = urljoin(self.base_url, self.UrlPath)
        self.agent_port = int(os.environ["HttpAgentServerPort"])
        self.agent_url = "http://localhost:%s/request/" % self.agent_port
        self.request = (lambda x: requests.post(self.agent_url, json=x))


class TestHeaders(HttpAgentTestCase):
    UrlPath = "/headers"

    def test_headers(self):
        user_agent = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/50.0.2661.94 Safari/537.36"
        x_fake_header = "mrlyc"
        response = self.request({
            "url": self.url,
            "headers": {
                "User-Agent": user_agent,
                "X-Fake-Header": x_fake_header,
            }
        })

        result = response.json()
        headers = result["headers"]
        self.assertEqual(headers["X-Proxy-Agent"], "LYC-HTTP-Agent")
        self.assertEqual(headers["User-Agent"], user_agent)
        self.assertEqual(headers["X-Fake-Header"], x_fake_header)

    def test_cookies(self):
        cookies = {
            "integer": 123,
            "string": "456",
            "float": 78.9,
        }
        response = self.request({
            "url": self.url,
            "cookies": cookies,
        })
        result = response.json()
        headers = result["headers"]
        self.assertIn("integer=123", headers["Cookie"])
        self.assertIn("string=456", headers["Cookie"])
        self.assertIn("float=78.9", headers["Cookie"])


if __name__ == '__main__':
    main()
