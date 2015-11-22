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


            # req_content_length = int(self.headers.get('Content-Length', 0))
            # req_body = self.rfile.read(req_content_length) \
            #     if req_content_length else None
            #
            # if 'Proxy-Connection' in self.headers:
            #     self.keep_alive = 'keep-alive' == \
            #         self.headers.get('Proxy-Connection', '').lower()
            # self.filter_headers(self.headers)

            self.send_request(addr, port)

            # upstream.request(self.command, self.path, req_body, dict(self.headers))
            rep = upstream.getresponse()
            print("status-code:[%d]" % rep.status)

            rep_body_transed = False
            rep_body = None
            if self.should_trans(rep):
                rep_body = rep.read()
                if rep_body:
                    rep_body_transed = self.trans(rep, rep_body)
                    if rep_body_transed is not None and rep.msg.get('Conten'):
                        rep.msg['Content-Length'] = str(len(rep_body_transed))

            self.wfile.write('%s %d %s\r\n' %
                (self.protocol_version, rep.status, rep.reason))
            for header in rep.msg.headers:
                self.wfile.write(header)
            self.end_headers()

            if rep_body_transed is False:
                while True:
                    segment = rep.read(self.us_rbuf)
                    if not segment:
                        break
                    self.wfile.write(segment)
            elif rep_body_transed is None:
                if rep_body:
                    self.wfile.write(rep_body)
            else:
                self.wfile.write(rep_body_transed)
            self.wfile.flush()

            if not self.keep_alive:
                self.wfile.close()

            # print 'req.command:[%s]\nreq.headers:[%s]\nreq.body:[%s]\nrep.headers:[%s]\nrep.body:[%s]\n' % \
            # (self.command, self.headers, req_body, rep.msg.headers, rep_body_transed or rep_body)

        except ValueError, e:
            self.send_error(400)
        except Exception, e:
            self.send_error(500)

    def filter_headers(self, headers):
        # for name in ('connection', 'keep-alive', 'proxy-authenticate',
        #         'proxy-authorization', 'proxy-connection', 'te', 'trailers',
        #         'upgrade'):
        for name in ('proxy-connection', 'Proxy-Connection'):
            if name in headers:
                del headers[name]

    def log_error(self, format, *args):
        self.log_message(format, *args)

    def trans(self, content_type, rep_body, charset):
        if content_type == 'text/xml':
            return self.trans_xml(rep_body, charset)
        elif content_type == 'text/plain':
            return self.trans_text(rep_body, charset)

    def should_trans_(self, rep):
        return False
        if self.command in ('REPORT', 'PROPFIND'):   # maybe blame
            content_type = rep.msg.get('Content-Type').lower()
            return content_type.startswith('text/xml') or \
                content_type.startswith('text/plain')

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
        for line in self.headers.headers:
            if not line.startswith('Proxy-Connection:'):
                buffer.append(line)
        buffer.append('\r\n')
        conn.send(''.join(buffer))
        del buffer[:]
        content_length = int(self.headers.get('Content-Length', 0))
        if content_length:
            if content_length < self.ds_rbuf:
                conn.send(self.rfile.read(content_length))
            else:
                while content_length > 0:
                    conn.send(self.rfile.read(min(content_length, self.ds_rbuf)))
                    content_length -= self.ds_rbuf

        content_length = -1
        remain = -1
        content = ''
        headers = ''
        body = ''
        should_trans = -1
        header_end = -1
        header_sent = False
        content_type = charset = None

        while header_end == -1:     # 接收 header
            content += conn.recv(self.us_rbuf if remain == -1 else min(self.us_rbuf, remain))
            header_end = content.find('\r\n\r\n')

        headers = content[:header_end]
        content_length = self.get_content_length(headers)
        content_type, charset = self.get_content_type(headers)
        should_trans = self.should_trans(content_type, content_length)
        if not should_trans:
            self.wfile.write(content)



        while True:
            rep = conn.recv(self.us_rbuf if remain == -1 else min(self.us_rbuf, remain))
            if rep:
                if content_length == -1:
                    content += rep
                    content_length = self.get_content_length(content)
                if header_end == -1:
                    header_end = content.find('\r\n\r\n')
                    if header_end > 0:
                        if content_type is None:
                            content_type = self.get_content_type(headers)
                    elif header_end == 0:
                        self.wfile.close()
                        break

                if content_length == -1:
                    if header_end != -1:
                        self.wfile.write(content)
                        self.wfile.close()
                        break
                else:
                    if header_end != -1:
                        if headers == '':
                            headers = content[:header_end]
                            if content_type is None:
                                content_type, charset = self.get_content_type(headers)
                            should_trans = self.should_trans(content_type, content_length)
                            if should_trans > 0:
                                body += content[header_end+4:]
                            else:
                                self.wfile.write(headers)
                                self.wfile.write('\r\n\r\n')
                                self.wfile.write(content[header_end+4:])
                            remain = content_length - (len(content) - (header_end + 4))
                            del content
                        else:
                            remain -= len(rep)
                            if should_trans > 0:
                                body += rep
                            else:
                                self.wfile.write(rep)
                        if remain == 0:
                            break
                    else:   # content_length 已知， header 没有结束
                        pass
            else:
                break
        if should_trans > 0:
            content_type = self.get_content_type(headers)
            if content_type is not None:
                body = self.trans(content_type, body, charset) or body
            self.wfile.write(headers)
            self.wfile.write('\r\n\r\n')
            self.wfile.write(body)
            self.wfile.close()

    def should_trans(self, content_type, content_length):
        return (self.command in ('REPORT', 'PROPFIND')) and content_length > 0 \
               and (content_type in ('text/xml', 'text/plain'))

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
