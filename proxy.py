#!/usr/bin/env python
# encoding: utf-8

import re
import logging
import logging.config
import functools

try:
    import simplejson as json
except ImportError:
    import json

try:
    from urllib.parse import urlencode
except ImportError:
    from urllib import urlencode

from tornado import (
    httpserver, web, ioloop,
)
from tornado.httpclient import AsyncHTTPClient
from tornado.httputil import HTTPHeaders, parse_response_start_line
from tornado.options import define, options
from tornado.escape import native_str

from jsonschema import Draft4Validator as Validator
from jsonschema.exceptions import ValidationError

logging.config.dictConfig({
    'version': 1,
    'disable_existing_loggers': True,
    'formatters': {
        'simple': {
            'format': '%(asctime)s %(name)s %(levelname)-8s %(message)s',
        },
        'long': {
            'format': '%(asctime)s %(name)s %(module)s %(process)d %(levelname)-8s %(message)s',
        },
    },
    'handlers': {
        'console': {
            'level': 'DEBUG',
            'class': 'logging.StreamHandler',
            'formatter': 'simple'
        },
        'file': {
            'level': 'INFO',
            'class': 'logging.FileHandler',
            'filename': '/data2/log/cloudmonitor/http_proxy.log',
            'mode': 'a',
            'formatter': 'long'
        },
    },
    'loggers': {
        '': {
            'handlers': ['console', 'file'],
            'level': 'DEBUG'
        }
    }
})

logger = logging.getLogger(__name__)
RequstDataValidator = Validator({
    "type": "object",
    "required": ["url"],
    "properties": {
        "version": {
            "type": "string",
            "enum": ["chp v1"],
            "default": "chp v1",
        },
        "method": {
            "type": "string",
            "enum": ["GET", "POST", "PUT", "DELETE", "HEAD"],
            "default": "GET",
        },
        "url": {
            "$ref": "#/definitions/uri",
        },
        "timeout": {
            "type": ["number", "string"],
            "minimum": 1,
            "maximum": 300,
            "exclusiveMaximum": False,
            "default": 30,
        },
        "post_type": {
            "type": ["string", "null"],
            "enum": ["form", "json", "string"],
            "default": "string",
        },
        "proxies": {
            "type": ["object", "null"],
            "minProperties": 1,
            "additionalProperties": False,
            "patternProperties": {
                r"^\w+$": {
                    "$ref": "#/definitions/uri",
                },
            },
        },
        "headers": {
            "type": ["object", "null"],
            "minProperties": 1,
            "patternProperties": {
                r"^[\w-]+$": {
                    "type": "string",
                },
            },
        },
        "data": {
            "type": ["object", "string", "null"],
            "default": "",
        },
        "verify_https": {
            "type": ["boolean", "string", "null"],
            "default": True,
        },
    },
    "definitions": {
        "uri": {
            "type": "string",
            "pattern": r"^(http|https):\/\/(\w+:{0,1}\w*@)?(\S+)(:[0-9]+)?(\/|\/([\w#!:.?+=&%@!\-\/]))?$",
        },
    },
})
REQUEST_ACCEPT_HEADERS = {
    'user-agent', 'accept', 'accept-encoding',
}
RESPONSE_EXCLUDE_HEADERS = {
    'connection', 'keep-alive', 'proxy-authenticate',
    'proxy-authorization', 'te', 'trailers', 'transfer-encoding',
    'upgrade', 'content-encoding', 'content-length', 'set-cookie',
}
X_Proxy_Agent = "YYCloudMonitor-HTTP-Proxy"
HTTP_Header_EndLine_Rex = re.compile("\r?\n\r?\n")


def log_exception(func):
    @functools.wraps(func)
    def wraps(*args, **kwg):
        try:
            return func(*args, **kwg)
        except Exception as err:
            logger.exception(err)
            raise
    return wraps


class ProxyHandler(web.RequestHandler):
    def __init__(self, *args, **kwargs):
        super(ProxyHandler, self).__init__(*args, **kwargs)
        self.proxy_headers = HTTPHeaders()
        self.http_client = AsyncHTTPClient()
        self.in_request_headers = False

    def get_request_data(self):
        if self.request.headers.get("X-Proxy-Agent") == X_Proxy_Agent:
            self.set_status(403, "recursion rejected")
            return

        try:
            request_data = json.loads(self.request.body.decode("utf-8"))
            RequstDataValidator.validate(request_data)
        except ValueError as err:
            self.set_status(400, str(err))
            return
        except ValidationError as err:
            self.set_status(400, "/%s: %s" % ("/".join(err.path), err.message))
            return
        return request_data

    def _set_proxy_headers(self):
        for k, v in self.proxy_headers.items():
            if k.lower() not in RESPONSE_EXCLUDE_HEADERS:
                self.set_header(k, v)

    def _streaming_callback(self, chunk):
        if not self._headers_written:
            self._set_proxy_headers()
        self.in_request_headers = False
        self.write(chunk)

    def _header_callback(self, header_line):
        if not self.in_request_headers:
            start_line = parse_response_start_line(header_line)
            self.set_status(start_line.code, start_line.reason)
            self.in_request_headers = True
        elif not HTTP_Header_EndLine_Rex.match(header_line):
            self.proxy_headers.parse_line(header_line)

    def _request_finished(self, response):
        if response.error:
            self.set_status(response.code, str(response.error))
        else:
            self.set_status(response.code, response.reason)
        self.finish()

    def _get_request_body(self, request_data):
        post_type = request_data.get("post_type")
        data = request_data.get("data")
        if post_type == "form":
            body = urlencode(data or {})
        elif post_type == "json":
            body = json.dumps(data)
        elif post_type == "string":
            body = native_str(data)
        else:
            body = None
        return body

    @web.asynchronous
    def post(self):
        request_data = self.get_request_data()
        if not request_data:
            self.finish()

        headers = {
            k: v for k, v in self.request.headers.items()
            if k.lower() in REQUEST_ACCEPT_HEADERS
        }
        headers.update(request_data.get("headers") or {})
        headers["X_Proxy_Agent"] = X_Proxy_Agent
        cookies = request_data.get("cookies")
        if cookies:
            headers["Cookie"] = cookies
        timeout = int(request_data.get("timeout", 0)) or None
        verify_https = bool(request_data.get("verify_https", True))

        self.in_request_headers = False
        self.http_client.fetch(
            request_data.get("url"), headers=headers,
            allow_nonstandard_methods=True,
            validate_cert=verify_https,
            body=self._get_request_body(request_data),
            connect_timeout=timeout, request_timeout=timeout,
            method=request_data.get("method", "GET"),
            streaming_callback=self._streaming_callback,
            header_callback=self._header_callback,
            callback=self._request_finished,
        )


if __name__ == '__main__':
    define("port", 8080, int, help="port to listen")
    define("debug", False, bool, help="debug mode")
    options.parse_command_line()

    application = web.Application([
        (r"/proxy/?", ProxyHandler),
    ], debug=options.debug)
    http_server = httpserver.HTTPServer(application)
    http_server.listen(options.port)
    instance = ioloop.IOLoop.instance()
    try:
        logger.info("server listen on %s", options.port)
        instance.start()
    except KeyboardInterrupt:
        logger.info("bye")
