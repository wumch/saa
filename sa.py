#!/usr/bin/env python
# -*- coding:utf-8 -*-

import sys
import os
import socket
import ssl
import select
import httplib
import urlparse
import threading
import gzip
import zlib
import time
import json
import re
import shutil
from BaseHTTPServer import HTTPServer, BaseHTTPRequestHandler
from SocketServer import ThreadingMixIn
import xml.dom.minidom as Dom
from cStringIO import StringIO
from HTMLParser import HTMLParser


class ThreadingHTTPServer(ThreadingMixIn, HTTPServer):

    address_family = socket.AF_INET6
    daemon_threads = True

    def handle_error(self, request, client_address):
        return HTTPServer.handle_error(self, request, client_address)


class ProxyRequestHandler(BaseHTTPRequestHandler):

    aliases = {}

    def __init__(self, *args, **kwargs):
        self.keep_alive = False
        self.us_request_timeout = 30
        self.us_connect_timeout = 30
        self.us_rbuf = 256 << 10
        print(self.aliases)
        BaseHTTPRequestHandler.__init__(self, *args, **kwargs)

    def relay(self):
        try:
            dest = self.headers.get('Host')
            if not dest:
                raise ValueError
            addr = dest.split(':')
            port = int(addr[1]) if len(addr) == 2 else 80
            upstream = httplib.HTTPConnection(host=addr[0], port=port,
                timeout=self.us_request_timeout)

            req_content_length = int(self.headers.get('Content-Length', 0))
            req_body = self.rfile.read(req_content_length) \
                if req_content_length else None

            if 'Proxy-Connection' in self.headers:
                self.keep_alive = 'keep-alive' == \
                    self.headers.get('Proxy-Connection', '').lower()
            self.filter_headers(self.headers)

            upstream.request(self.command, self.path, req_body, dict(self.headers))
            rep = upstream.getresponse()

            rep_body_transed = False
            rep_body = None
            if self.should_trans(req_body, rep):
                rep_body = rep.read()
                if rep_body:
                    rep_body_transed = self.trans(req_body, rep, rep_body)
                    if rep_body_transed is not None:
                        rep.msg['Content-Length'] = str(len(rep_body_transed))

            self.wfile.write('%s %d %s\r\n' %
                (self.protocol_version, rep.status, rep.reason))
            for header in rep.msg.headers:
                self.wfile.write(header)
            self.end_headers()

            if rep_body_transed is False:
                print(rep_body)
                if rep_body is None:
                    rep_body = rep.read()
                    print('content-length:[%s]' % rep.msg.get('Content-Length'))
                    print('rep_body.length: [%d]' % len(rep_body))
                    self.wfile.write(rep_body)
                else:
                    self.wfile.write(rep_body)
                # while True:
                #     segment = rep.read(self.us_rbuf)
                #     if not segment:
                #         break
                #     self.wfile.write(segment)
            elif rep_body_transed is None:
                if rep_body:
                    self.wfile.write(rep_body)
            else:
                self.wfile.write(rep_body_transed)
            self.wfile.flush()

            if not self.keep_alive:
                self.wfile.close()

            print 'req.command:[%s]\nreq.headers:[%s]\nreq.body:[%s]\nrep.headers:[%s]\nrep.body:[%s]\n' % \
            (self.command, self.headers, req_body, rep.msg.headers, rep_body_transed or rep_body)

        except ValueError, e:
            self.send_error(400)
        except Exception, e:
            self.send_error(500)

    def filter_headers(self, headers):
        for name in ('connection', 'keep-alive', 'proxy-authenticate',
                'proxy-authorization', 'Proxy-Connection', 'te', 'trailers',
                'transfer-encoding', 'upgrade'):
            if name in headers:
                del headers[name]

    def log_error(self, format, *args):
        self.log_message(format, *args)

    def trans(self, req_body, rep, rep_body):
        transer = self.get_transer(req_body, rep, rep_body)
        return None if transer is None else transer(rep_body)

    def get_transer(self, req_body, rep, rep_body):
        transer = None
        content_type = rep.msg.get('Content-Type').lower()
        if content_type:
            if content_type.startswith('text/xml'):
                transer = self.trans_xml
            elif content_type.startswith('text/plain'):
                transer = self.trans_text

            if transer is not None:
                info = content_type.split('charset=', 1)
                charset = info[1].strip().lower() if len(info) == 2 else 'utf-8'
                return lambda content: transer(content, charset)

    def should_trans(self, req_body, rep):
        if self.command in ('REPORT', 'PROPFIND')  and req_body:   # maybe blame
            content_type = rep.msg.get('Content-Type').lower()
            return content_type.startswith('text/xml') or \
                content_type.startswith('text/plain')

    def trans_text(self, text, charset):
        return text

    rules = [
        {'name': 'S:author'},
        {'name': 'S:set-prop', 'prop': ('name', 'svn:entry:last-author')},
        {'name': 'S:rev-prop', 'prop': ('name', 'svn:author')},
        {'name': 'lp1:creator-displayname'},
        {'name': 'D:creator-displayname'}
    ]

    def trans_xml(self, xml, charset):
        try:
            dom = Dom.parseString(xml)  # TODO: sax..
            for rule in self.rules:
                if 'prop' in rule:
                    self.trans_by_name_prop(dom, rule['name'], *rule['prop'])
                else:
                    self.trans_by_name(dom, rule['name'])
            transed = dom.toxml(charset)
            return transed.replace('encoding=""utf-8""', 'encoding="utf-8"', 1) \
                if 'encoding=""utf-8""' in transed else transed
        except Exception, e:
            pass

    def trans_by_name(self, dom, name):
        for element in dom.getElementsByTagName(name):
            if element.firstChild.nodeType == element.TEXT_NODE:
                element.firstChild.nodeValue = self.aliases.get(
                    element.firstChild.nodeValue,
                    element.firstChild.nodeValue)

    def trans_by_name_prop(self, dom, name, prop_name, prop_value):
        for element in dom.getElementsByTagName(name):
            if element.getAttribute(prop_name) == prop_value and \
                    element.firstChild.nodeType == element.TEXT_NODE:
                element.firstChild.nodeValue = self.aliases.get(
                    element.firstChild.nodeValue,
                    element.firstChild.nodeValue)


    @classmethod
    def set_aliases(cls, aliases):
        cls.aliases = aliases

    do_GET = do_POST = do_OPTIONS = do_PUT = do_DELETE = \
        do_PROPFIND = do_REPORT = do_MERGE = relay


if __name__ == '__main__':
    ProxyRequestHandler.set_aliases({
        u'wu261': u'吴哥'
    })
    ThreadingHTTPServer(('', 3128), ProxyRequestHandler).serve_forever()
