#!/usr/bin/env python
# coding: utf-8

import urlparse

from tornado import (
    httpserver, ioloop, options, web, httpclient,
)
from tornado.options import define, options
from tornado.simple_httpclient import (
    SimpleAsyncHTTPClient as AsyncHTTPClient,
)


class ProxyHandler(web.RequestHandler):
    ExcludedHeaders = {
        'connection', 'keep-alive', 'proxy-authenticate',
        'proxy-authorization', 'te', 'trailers', 'transfer-encoding',
        'content-encoding', 'content-length',
    }

    def _make_method(method):
        @web.asynchronous
        def do(self):
            real_url = urlparse.urljoin(
                options.proxy_target, self.request.uri,
            )
            base_url = urlparse.urlparse(options.proxy_target)
            headers = self.request.headers.copy()
            headers["Host"] = base_url.netloc

            http_client = AsyncHTTPClient()
            try:
                http_client.fetch(httpclient.HTTPRequest(
                    real_url, method, headers, self.request.body or None,
                    follow_redirects=True,
                ), self._on_proxy_response)
            except httpclient.HTTPError as err:
                self._on_proxy_response(err.response)
            except err:
                raise httpclient.HTTPError(500)
        return do

    def _on_proxy_response(self, response):
        self.set_status(response.code)
        for h in self.ExcludedHeaders:
            v = response.headers.get(h)
            if v:
                self.set_header(h, v)

        if response.body:
            self.write(response.body)
        self.finish()

    get = _make_method("GET")
    post = _make_method("POST")


if __name__ == "__main__":
    define("proxy_target")
    define("port", 8080, int)

    options.parse_command_line()
    application = web.Application([
        (r"/.*", ProxyHandler),
    ])
    http_server = httpserver.HTTPServer(application)
    http_server.listen(options.port)

    instance = ioloop.IOLoop.instance()

    try:
        instance.start()
    except KeyboardInterrupt:
        pass
