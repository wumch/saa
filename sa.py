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
        self.ds_rbuf = 256 << 10
        print(self.aliases)
        BaseHTTPRequestHandler.__init__(self, *args, **kwargs)

    def relay(self):
        try:
            dest = self.headers.get('Host')
            if not dest:
                raise ValueError
            addr = dest.split(':')
            port = int(addr[1]) if len(addr) == 2 else 80
            return self.send_request(addr[0], port)
        except ValueError, e:
            print('ValueError(%s)' % e.message)
            self.send_error(402)
        except Exception, e:
            print('Exception(%s)' % e.message)
            self.send_error(500)

    def filter_headers(self, headers):
        for name in ('connection', 'keep-alive', 'proxy-authenticate',
                'proxy-authorization', 'proxy-connection', 'te', 'trailers',
                'upgrade', 'Proxy-Connection'):
            if name in headers:
                del headers[name]

    def log_error(self, format, *args):
        self.log_message(format, *args)

    def trans(self, content_type, rep_body, charset):
        if content_type == 'text/xml':
            return self.trans_xml(rep_body, charset)
        elif content_type == 'text/plain':
            return self.trans_text(rep_body, charset)

    def send_request(self, host, port):
        """
        :type conn: httplib.HTTPConnection
        :param req: ProxyRequestHandler
        """
        conn = socket.create_connection((host, port), timeout=self.us_connect_timeout)
        buffer = []
        url = urlparse.urlsplit(self.path)
        path = (url.path + '?' + url.query) if url.query else url.path
        buffer.append('%s %s %s\r\n' % (self.command, path, self.protocol_version))
        line = ''
        for line in self.headers.headers:
            if not line.startswith('Proxy-Connection: ') and not line.startswith('Transfer-Encoding: '):
                buffer.append(line)
        if not line.endswith('\r\n\r\n'):
            if line.endswith('\r\n'):
                buffer.append('\r\n')
            else:
                buffer.append('\r\n\r\n')
        conn.send(''.join(buffer))
        del buffer[:]
        content_length = int(self.headers.get('Content-Length', 0))
        print('request-headers(%s):\n[%s]' % (self.command, ''.join(self.headers.headers)))
        if content_length:
            if content_length < self.ds_rbuf:
                conn.send(self.rfile.read(content_length))
            else:
                while content_length > 0:
                    conn.send(self.rfile.read(min(content_length, self.ds_rbuf)))
                    content_length -= self.ds_rbuf

        content = ''
        header_end = -1
        while header_end == -1:     # 接收 header
            segment = conn.recv(self.us_rbuf)
            if not segment:
                header_end = content.find('\r\n\r\n')
                break
            else:
                content += segment
                header_end = content.find('\r\n\r\n')

        headers = content[:header_end]
        content_length = self.get_content_length(headers)
        info = self.get_content_type(headers)
        content_type = charset = None
        if info:
            content_type, charset = info
            should_trans = self.should_trans(content_type, content_length, headers)
        else:
            should_trans = False
        remain = content_length - (len(content) - (header_end + 4))

        body = ''
        if should_trans:
            body = content[header_end+4:]
        else:
            self.wfile.write(content)

        while remain > 0:
            segment = conn.recv(self.us_rbuf if remain == -1 else min(self.us_rbuf, remain))
            if not segment:
                break
            remain -= len(segment)
            if should_trans:
                body += segment
            else:
                self.wfile.write(segment)
            conn.close()

        if should_trans:
            if content_type is not None:
                body = self.trans(content_type, body, charset) or body
            self.wfile.write(headers)
            self.wfile.write('\r\n\r\n')
            self.wfile.write(body)
            self.wfile.close()

    def should_trans(self, content_type, content_length, headers):
        return (self.command in ('REPORT', 'PROPFIND')) and content_length > 0 \
            and (content_type in ('text/xml', 'text/plain')) \
            and ('\r\nTransfer-Encoding: chunked' not in headers)

    def get_content_type(self, headers):
        begin = headers.find('\r\nContent-Type: ')
        if begin != -1:
            begin += 16
            end = headers.find('\r\n', begin)
            content_type = headers[begin:len(headers) if end == -1 else end].lower()
            info = content_type.split('charset=')
            content_type = info[0].strip('; ')
            charset = info[1].strip(' "\'') if len(info) == 2 else 'utf-8'
            return content_type, charset
        return None

    def get_content_length(self, content):
        content_length = -1
        begin = content.find('\r\nContent-Length: ')
        if begin != -1:
            begin += 18
            end = content.find('\r\n', begin)
            if end != -1:
                content_length = int(content[begin:end])
        return content_length


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
