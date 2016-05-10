#!/usr/bin/env python
# encoding: utf-8

import os
import urlparse
import urllib
from unittest import TestCase, main

import requests


class HttpAgentTestCase(TestCase):
    UrlPath = ""

    def setUp(self):
        self.base_url = "http://httpbin.org"
        self.url = urlparse.urljoin(self.base_url, self.UrlPath)
        self.agent_port = int(os.environ["HttpAgentServerPort"])
        self.agent_url = "http://localhost:%s/request/" % self.agent_port
        self.request = (lambda x: requests.post(self.agent_url, json=x))


class TestRequestHeaders(HttpAgentTestCase):
    UrlPath = "/headers"

    def test_headers(self):
        response = self.request({
            "url": self.url,
            "headers": {
                "Content-Length": "0",
            }
        })
        self.assertEqual(response.status_code, 400)

        user_agent = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/50.0.2661.94 Safari/537.36"
        x_fake_header = "mrlyc"
        response = self.request({
            "url": self.url,
            "timeout": 60,
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
        self.assertNotEqual(headers.get("Content-Length"), "0")


class TestResponseHeaders(HttpAgentTestCase):
    UrlPath = "/response-headers"

    def test_headers(self):
        x_fake_header = "mrlyc"
        forbidden_response_headers = {
            "Connection": "keep-alive",
        }
        allowed_response_headers = {
            "X-Fake-Header": x_fake_header,
        }

        response_headers = {}
        response_headers.update(forbidden_response_headers)
        response_headers.update(allowed_response_headers)

        response = self.request({
            "url": self.url,
            "timeout": 60,
            "data": response_headers,
        })
        result = response.json()
        self.assertDictContainsSubset(response_headers, result)
        self.assertDictContainsSubset(
            allowed_response_headers, response.headers
        )
        self.assertNotEqual(response.headers["Connection"], "keep-alive")


class TestCookies(HttpAgentTestCase):
    UrlPath = "/cookies"

    def test_cookies(self):
        raw_cookies = {
            "integer": 123,
            "string": "456",
            "float": 78.9,
        }
        response = self.request({
            "url": self.url,
            "timeout": 60,
            "cookies": raw_cookies,
        })
        result = response.json()
        cookies = result["cookies"]
        self.assertDictEqual(cookies, {
            k: str(v)
            for k, v in raw_cookies.items()
        })


class TestGetMethod(HttpAgentTestCase):
    UrlPath = "/get"

    def test_get_query_string(self):
        data = {
            "index": 0,
            "limit": 20,
            "preview": "",
        }
        query_string = urllib.urlencode(data)

        response = self.request({
            "url": self.url,
            "timeout": 60,
            "method": "GET",
            "data": data,
        })
        result = response.json()
        url, qs = result["url"].split("?")

        self.assertEqual(url, self.url)
        self.assertSetEqual(set(query_string.split("&")), set(qs.split("&")))

        args = result["args"]
        self.assertListEqual(data.keys(), args.keys())
        self.assertListEqual(args.values(), [str(i) for i in data.values()])


class TestPostMethod(HttpAgentTestCase):
    UrlPath = "/post"

    def test_post_form(self):
        data = {
            "key": "test",
            "value": "123",
        }
        response = self.request({
            "url": self.url,
            "timeout": 60,
            "method": "POST",
            "data": data,
            "post_type": "form",
        })
        result = response.json()
        form = result["form"]
        self.assertDictEqual(form, data)

    def test_post_json(self):
        data = {
            "key": "test",
            "value": 123,
        }
        response = self.request({
            "url": self.url,
            "timeout": 60,
            "method": "POST",
            "data": data,
            "post_type": "json",
        })
        result = response.json()
        json = result["json"]
        self.assertDictEqual(json, data)

    def test_post_string(self):
        data = "test"
        response = self.request({
            "url": self.url,
            "timeout": 60,
            "method": "POST",
            "data": data,
            "post_type": "string",
        })
        result = response.json()
        body = result["data"]
        self.assertEqual(body, data)


class TestDeleteMethod(HttpAgentTestCase):
    UrlPath = "/delete"

    def test_delete_query_string(self):
        data = {
            "id": 1,
        }
        response = self.request({
            "url": self.url,
            "timeout": 60,
            "method": "DELETE",
            "data": data,
        })
        result = response.json()
        args = result["args"]
        self.assertListEqual(data.keys(), args.keys())


class TestTimeOut(HttpAgentTestCase):
    UrlPath = "/delay/3"

    def test_timeout(self):
        response = self.request({
            "url": self.url,
            "timeout": 0.1,
        })
        self.assertEqual(response.status_code, 599)


class TestRedirect(HttpAgentTestCase):
    UrlPath = "/redirect/2"

    def test_redirect(self):
        response = self.request({
            "url": self.url,
            "timeout": 60,
            "max_http_redirects": 0,
        })
        self.assertEqual(response.status_code, 404)

        response = self.request({
            "url": self.url,
            "timeout": 60,
            "max_http_redirects": 1,
        })
        self.assertEqual(response.status_code, 302)

        response = self.request({
            "url": self.url,
            "timeout": 60,
            "max_http_redirects": 2,
        })
        self.assertEqual(response.status_code, 200)


class TestUTF8(HttpAgentTestCase):
    UrlPath = "/encoding/utf8"

    def test_utf8(self):
        raw_response = requests.get(self.url)
        response = self.request({
            "url": self.url,
            "timeout": 60,
        })
        self.assertEqual(raw_response.content, response.content)

if __name__ == '__main__':
    main()
