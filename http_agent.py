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
from tornado.httpclient import AsyncHTTPClient, HTTPRequest, HTTPError
from tornado.httputil import HTTPHeaders, parse_response_start_line
from tornado.options import define, options
from tornado.escape import native_str
from tornado.log import access_log as logger

from jsonschema import Draft4Validator as Validator
from jsonschema.exceptions import ValidationError


DEFAULT_TIMEOUT = 10
RAW_REQUEST_ACCEPT_HEADERS = {
    "User-Agent", "Accept", "Accept-Encoding", "Referer",
}
REQUEST_ACCEPT_HEADERS = {
    "Accept-Charset", "Accept-Language", "Accept-Datetime",
    "Content-Type", "Date", "Expect", "Forwarded", "Host",
    "If-Match", "If-Modified-Since", "If-None-Match", "From",
    "If-Range", "If-Unmodified-Since", "Origin", "Range",
} | RAW_REQUEST_ACCEPT_HEADERS
RESPONSE_EXCLUDE_HEADERS = {
    "Connection", "Proxy-Authenticate", "Transfer-Encoding",
    "Content-Encoding", "Content-Length",
}
X_Proxy_Agent = "LYC-HTTP-Agent"
HTTPHeaderEndLineRex = re.compile("\r?\n\r?\n")
RequstDataValidateSchema = {
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
            "minimum": 0,
            "maximum": 120,
            "exclusiveMaximum": False,
            "exclusiveMinimum": False,
            "default": DEFAULT_TIMEOUT,
        },
        "post_type": {
            "type": ["string", "null"],
            "enum": ["form", "json", "string"],
            "default": "string",
        },
        "max_http_redirects": {
            "type": ["integer", "null"],
            "minimum": 0,
            "maximum": 3,
            "exclusiveMinimum": False,
            "exclusiveMaximum": False,
            "default": 0,
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
            "additionalProperties": False,
            "patternProperties": {
                # header field starts with X- or in REQUEST_ACCEPT_HEADERS
                r"(?:X\-[\w\-]+)|%s" % "|".join(
                    "(?:%s)" % i.replace("-", r"\-")
                    for i in REQUEST_ACCEPT_HEADERS
                ): {
                    "type": "string",
                },
            },
        },
        "data": {
            "type": ["object", "string", "null"],
            "default": "",
        },
        "validate_cert": {
            "type": ["boolean", "string", "null"],
            "default": True,
        },
        "insecure_connection": {
            "type": ["boolean", "string", "null"],
            "default": False,
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
        "role": {
            "type": ["string", "null"],
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
}
RequstDataValidator = Validator(RequstDataValidateSchema)


class RequestParamsError(Exception):
    pass


class InterfaceRoleNotFoundError(RequestParamsError):
    pass


class InterfaceRoleManager(object):
    InterfaceRoles = None

    @classmethod
    def setup_roles(cls, roles):
        cls.InterfaceRoles = roles

    @classmethod
    def set_curl_interface_role(cls, request, role):
        if cls.InterfaceRoles is None:
            return

        interface = cls.InterfaceRoles.get(role)
        if not interface:
            raise InterfaceRoleNotFoundError("role %s not found" % role)
        request.network_interface = interface


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

    def initialize(self):
        self.proxy_headers = HTTPHeaders()
        # create a new client for each request
        self.http_client = AsyncHTTPClient(max_clients=1)
        self.in_request_headers = False
        self.id = id(self)
        self.request_data = None

    def validate_request(self, request_data):
        if self.request.headers.get("X-Proxy-Agent") == X_Proxy_Agent:
            self.set_status(403, "recursion rejected")
            return False

        try:
            RequstDataValidator.validate(request_data)
        except ValidationError as err:
            self.set_status(400, "/%s: %s" % (
                "::".join(err.path), err.message
            ))
            return False
        return True

    def get_post_request_data(self):
        try:
            request_data = json.loads(self.request.body.decode("utf-8"))
        except ValueError as err:
            self.set_status(400, str(err))
            return
        return request_data

    def _set_proxy_headers(self):
        for k, v in self.proxy_headers.items():
            if k not in RESPONSE_EXCLUDE_HEADERS:
                logger.debug(
                    "[%s] write header %s: %s", self.id, k, v,
                )
                self.set_header(k, v)

    def _streaming_callback(self, chunk):
        if self._finished:
            return

        if not self._headers_written:
            self._set_proxy_headers()
            self.flush()
        self.in_request_headers = False
        self.write(chunk)
        logger.debug("[%s] chunk length %s", self.id, len(chunk))

    def _header_callback(self, header_line):
        if not self.in_request_headers:
            start_line = parse_response_start_line(header_line)
            self.set_status(start_line.code, start_line.reason)
            self.in_request_headers = True
        elif not HTTPHeaderEndLineRex.match(header_line):
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
        elif post_type == "string" and isinstance(data, basestring):
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
            if k.lower() in RAW_REQUEST_ACCEPT_HEADERS
        }
        cookies = request_data.get("cookies")
        if cookies:
            headers["Cookie"] = "; ".join(
                "%s=%s" % i
                for i in cookies.items()
            )

        post_type = request_data.get("post_type")
        if post_type == "form":
            headers.setdefault(
                "Content-Type", "application/x-www-form-urlencoded"
            )
        elif post_type == "json":
            headers.setdefault(
                "Content-Type", "application/json"
            )
        elif post_type == "string":
            headers.setdefault(
                "Content-Type", "text/plain"
            )

        request_headers = request_data.get("headers") or {}
        for k, v in request_headers.items():
            if k in REQUEST_ACCEPT_HEADERS:
                headers[k] = v
            elif k.startswith("X-"):
                headers[k] = v
        headers["X-Proxy-Agent"] = X_Proxy_Agent
        return headers

    @gen.coroutine
    def handle_request(self, request_data):
        try:
            proxy_request = yield self._make_proxy_request(request_data)
            if not proxy_request:
                raise gen.Return()

            yield self._fetch_proxy_request(proxy_request)
        except RequestParamsError as err:
            self.set_status(400, str(err))
        except Exception as err:
            logger.exception(err)
        raise gen.Return()

    @web.asynchronous
    @gen.coroutine
    def get(self):
        url = self.get_query_argument("url")
        logger.debug("[%s]agent get url: %s", self.id, url)

        self.request_data = request_data = {"url": url}
        if not self.validate_request(request_data):
            raise gen.Return()

        yield self.handle_request(request_data)

    @web.asynchronous
    @gen.coroutine
    def post(self):
        request_data = self.get_post_request_data()
        logger.debug("[%s]agent request data: %s", self.id, request_data)
        if not request_data:
            raise gen.Return()

        self.request_data = request_data
        if not self.validate_request(request_data):
            raise gen.Return()

        yield self.handle_request(request_data)

    def prepare_curl_callback(self, curl):
        import pycurl

        if (
            "insecure_connection" in self.request_data and
            bool(self.request_data.get("insecure_connection"))
        ):
            curl.setopt(pycurl.SSL_VERIFYHOST, 0)

    @gen.coroutine
    def _make_proxy_request(self, request_data):
        timeout = float(request_data.get("timeout", DEFAULT_TIMEOUT))
        validate_cert = bool(request_data.get("validate_cert") or True)
        max_redirects = request_data.get("max_http_redirects") or 0
        follow_redirects = max_redirects > 0  # 0 means do not follow redirects

        url = request_data.get("url")
        params = request_data.get("data")
        post_type = request_data.get("post_type")
        if params and post_type is None:
            url = "%s?%s" % (url, urlencode(params))

        logger.info("[%s]agent request url: %s", self.id, url)

        proxy_request = HTTPRequest(
            url, validate_cert=validate_cert,
            headers=self._get_proxy_request_headers(request_data),
            method=request_data.get("method", "GET"),
            allow_nonstandard_methods=True,
            connect_timeout=timeout,
            request_timeout=timeout,
            streaming_callback=self._streaming_callback,
            header_callback=self._header_callback,
            follow_redirects=follow_redirects,
            max_redirects=max_redirects,
            prepare_curl_callback=self.prepare_curl_callback,
        )

        role_name = request_data.get("role")
        if role_name:
            InterfaceRoleManager.set_curl_interface_role(
                proxy_request, role_name,
            )

        keystone_auth_info = request_data.get("keystone")
        if keystone_auth_info:
            logger.warning(
                "[%s]agent request required keystone token",
            )
            auth_headers = yield self._get_keystone_auth_headers(
                keystone_auth_info, validate_cert=validate_cert,
            )
            if not auth_headers:
                raise gen.Return()
            proxy_request.headers.update(auth_headers)

        body = self._get_request_body(request_data)
        if body:
            proxy_request.body = body

        raise gen.Return(proxy_request)

    @gen.coroutine
    def _fetch_proxy_request(self, proxy_request):
        self.in_request_headers = False
        try:
            response = yield self.http_client.fetch(proxy_request)
        except HTTPError as err:
            self.set_status(err.code, err.message)
            raise gen.Return()
        except Exception as err:
            self.set_status(503, str(err))
            raise gen.Return()

        if response.error:
            self.set_status(response.code, str(response.error))
        else:
            self.set_status(response.code, response.reason)

        logger.info(
            "[%s]agent response status: %s, reason: %s",
            self.id, response.code, response.reason,
        )


class IndexHandler(web.RequestHandler):

    def get(self):
        self.write("ok")
        self.finish()

if __name__ == "__main__":
    define("port", 8080, int, help="port to listen")
    define("curl_httpclient", False, help="use curl httpclient")
    define("interface_roles", "", help="roles to chosen interface")
    define("debug", False, bool, help="debug mode")
    define("logpath", "http_agent.log", help="log file path")
    options.parse_command_line()

    logging.config.dictConfig({
        "version": 1,
        "disable_existing_loggers": True,
        "formatters": {
            "long": {
                "format": (
                    r"%(asctime)s %(name)s %(module)s %(process)d "
                    r"%(levelname)-8s %(message)s"
                ),
            },
        },
        "handlers": {
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
                "handlers": ["file"],
                "level": "DEBUG"
            }
        }
    })

    if options.interface_roles:
        InterfaceRoleManager.setup_roles(dict(
            i.split(":", 1)
            for i in options.interface_roles.split(",")
        ))

    application = web.Application([
        (r"/?", IndexHandler),
        (r"/request/?", ProxyHandler),
    ], debug=options.debug)

    if options.curl_httpclient:
        AsyncHTTPClient.configure(
            "tornado.curl_httpclient.CurlAsyncHTTPClient"
        )

    http_server = httpserver.HTTPServer(application)
    http_server.listen(options.port)
    instance = ioloop.IOLoop.instance()
    try:
        logger.info("server listen on %s", options.port)
        instance.start()
    except KeyboardInterrupt:
        logger.info("bye")
