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
    httpserver, web, ioloop, gen,
)
from tornado.httpclient import AsyncHTTPClient, HTTPRequest
from tornado.httputil import HTTPHeaders, parse_response_start_line
from tornado.options import define, options
from tornado.escape import native_str
from tornado.log import access_log as logger

from jsonschema import Draft4Validator as Validator
from jsonschema.exceptions import ValidationError


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
        "keystone": {
            "type": ["object", "null"],
            "default": None,
            "properties": {
                "auth_url": {
                    "type": "string",
                },
                "tenant_name": {
                    "type": "string",
                },
                "user_name": {
                    "type": "string",
                },
                "password": {
                    "type": "string",
                },
            },
        },
    },
    "definitions": {
        "uri": {
            "type": "string",
            "pattern": (
                r"^(http|https):\/\/(\w+:{0,1}\w*@)?(\S+)(:[0-9]+)?"
                r"(\/|\/([\w#!:.?+=&%@!\-\/]))?$"
            ),
        },
    },
})
REQUEST_ACCEPT_HEADERS = {
    "user-agent", "accept", "accept-encoding",
}
RESPONSE_EXCLUDE_HEADERS = {
    "connection", "keep-alive", "proxy-authenticate",
    "proxy-authorization", "te", "trailers", "transfer-encoding",
    "upgrade", "content-encoding", "content-length", "set-cookie",
}
X_Proxy_Agent = "YYCloudMonitor-HTTP-Agent"
HTTP_Header_EndLine_Rex = re.compile("\r?\n\r?\n")
DEFAULT_TIMEOUT = 60


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
        self.id = id(self)

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
        self.flush()
        logger.debug("[%s] chunk: %s", self.id, chunk)

    def _header_callback(self, header_line):
        if not self.in_request_headers:
            start_line = parse_response_start_line(header_line)
            self.set_status(start_line.code, start_line.reason)
            self.in_request_headers = True
        elif not HTTP_Header_EndLine_Rex.match(header_line):
            self.proxy_headers.parse_line(header_line)

    def _get_request_body(self, request_data):
        post_type = request_data.get("post_type")
        data = request_data.get("data")
        if data is None:
            return None

        if post_type == "form":
            body = urlencode(data or {})
        elif post_type == "json":
            body = json.dumps(data)
        elif post_type == "string":
            body = native_str(data)
        else:
            body = None
        return body

    @gen.coroutine
    def _get_keystone_auth_headers(self, auth_info, validate_cert=True):
        try:
            response = yield self.http_client.fetch(
                auth_info.get("auth_url"), method="POST",
                headers={"Content-Type": "application/json"},
                validate_cert=validate_cert,
                body=json.dumps({
                    "auth": {
                        "passwordCredentials": {
                            "username": auth_info.get("user_name"),
                            "password": auth_info.get("password"),
                        },
                        "tenantName": auth_info.get("tenant_name"),
                    }
                })
            )
        except Exception as err:
            logger.info(err)
            self.set_status(503, "keystone auth error")
            raise gen.Return()

        if response.error or response.code != 200:
            logger.info("keystone auth error")
            self.set_status(407, "keystone auth error")
            raise gen.Return()

        auth_info = json.loads(response.body.decode("utf-8"))
        try:
            raise gen.Return({
                "X-AUTH-TOKEN": auth_info["access"]["token"]["id"],
            })
        except KeyError:
            logger.info("keystone auth failed")
            self.set_status(407, "keystone auth failed")
        raise gen.Return()

    def _get_proxy_request_headers(self, request_data):
        headers = {
            k: v for k, v in self.request.headers.items()
            if k.lower() in REQUEST_ACCEPT_HEADERS
        }
        cookies = request_data.get("cookies")
        if cookies:
            headers["Cookie"] = cookies

        headers.update(request_data.get("headers") or {})
        headers["X_Proxy_Agent"] = X_Proxy_Agent
        return headers

    @web.asynchronous
    @gen.coroutine
    def post(self):
        request_data = self.get_request_data()
        logger.debug("[%s]agent request data: %s", self.id, request_data)
        if not request_data:
            raise gen.Return()

        timeout = int(request_data.get("timeout", DEFAULT_TIMEOUT))
        verify_https = bool(request_data.get("verify_https", True))
        url = request_data.get("url")

        logger.info("[%s]agent request url: %s", self.id, url)

        proxy_request = HTTPRequest(
            url, validate_cert=verify_https,
            headers=self._get_proxy_request_headers(request_data),
            method=request_data.get("method", "GET"),
            allow_nonstandard_methods=True, request_timeout=timeout,
            streaming_callback=self._streaming_callback,
            header_callback=self._header_callback,
        )

        keystone_auth_info = request_data.get("keystone")
        if keystone_auth_info:
            logger.warning(
                "[%s]agent request required keystone token",
            )
            auth_headers = yield self._get_keystone_auth_headers(
                keystone_auth_info, validate_cert=verify_https,
            )
            if not auth_headers:
                raise gen.Return()
            proxy_request.headers.update(auth_headers)

        body = self._get_request_body(request_data)
        if body:
            proxy_request.body = body

        self.in_request_headers = False
        try:
            response = yield self.http_client.fetch(proxy_request)
        except Exception as err:
            self.set_status(503, str(err))
            raise gen.Return()

        if response.error:
            self.set_status(response.code, str(response.error))
        else:
            self.set_status(response.code, response.reason)
        self.finish()

        logger.info(
            "[%s]agent response status: %s, reason: %s",
            self.id, response.code, response.reason,
        )

if __name__ == "__main__":
    define("port", 8080, int, help="port to listen")
    define("debug", False, bool, help="debug mode")
    define("logpath", "/var/log/http_agent.log", help="log file path")
    options.parse_command_line()

    logging.config.dictConfig({
        "version": 1,
        "disable_existing_loggers": True,
        "formatters": {
            "simple": {
                "format": (
                    r"%(asctime)s %(name)s %(levelname)-8s "
                    r"%(message)s"
                ),
            },
            "long": {
                "format": (
                    "%(asctime)s %(name)s %(module)s %(process)d %(levelname)-8s "
                    r"%(message)s"
                ),
            },
        },
        "handlers": {
            "console": {
                "level": "DEBUG",
                "class": "logging.StreamHandler",
                "formatter": "simple"
            },
            "file": {
                "level": "INFO",
                "class": "logging.FileHandler",
                "filename": options.logpath,
                "mode": "a",
                "formatter": "long"
            },
        },
        "loggers": {
            "tornado": {
                "handlers": ["console", "file"],
                "level": "DEBUG"
            }
        }
    })

    application = web.Application([
        (r"/request/?", ProxyHandler),
    ], debug=options.debug)
    http_server = httpserver.HTTPServer(application)
    http_server.listen(options.port)
    instance = ioloop.IOLoop.instance()
    try:
        logger.info("server listen on %s", options.port)
        instance.start()
    except KeyboardInterrupt:
        logger.info("bye")
