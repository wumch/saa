#!/usr/bin/env python
# -*- coding:utf-8 -*-

import sys
sys.path.append('/data/code/wumch')
import socket
import urlparse
import time
from BaseHTTPServer import HTTPServer, BaseHTTPRequestHandler
from SocketServer import ThreadingMixIn, ThreadingTCPServer
import xml.dom.minidom as Dom
from pyage.tracer import Tracer


class StatusError(Exception):

    def __init__(self, code):
        self.code = code


class Relayer(ThreadingTCPServer):

    aliases = {}

    def __init__(self, *args, **kwargs):
        self.close_connection = 0
        self.keep_alive = False
        self.us_request_timeout = 30
        self.us_connect_timeout = 30
        self.us_rbuf = 256 << 10
        self.ds_rbuf = 256 << 10
        self.upconn = None
        ThreadingTCPServer.__init__(self, *args, **kwargs)

    def relay(self):
        try:
            dest = self.headers.get('Host')
            if not dest:
                raise ValueError
            addr = dest.split(':')
            port = int(addr[1]) if len(addr) == 2 else 80
            return self._relay(addr[0], port)
        except StatusError, e:
            print('error, status code:[%d]' % e.code)
            print(Tracer().trace_exception())
            self.send_error(e.code)
        except ValueError, e:
            print('ValueError(%s)' % e.message)
            print(Tracer().trace_exception())
            self.send_error(402)
        except socket.timeout, e:
            print('socket timeout(%s)' % e.message)
            print(Tracer().trace_exception())
            self.send_error(500)
        except Exception, e:
            print('Exception(%s)' % e.message)
            print(Tracer().trace_exception())
            self.send_error(500)

    def filter_headers(self, headers):
        for name in ('connection', 'keep-alive', 'proxy-authenticate',
                'proxy-authorization', 'proxy-connection', 'te', 'trailers',
                'upgrade', 'Proxy-Connection'):
            if name in headers:
                del headers[name]

    def log_error(self, format, *args):
        self.log_message(format, *args)

    def trans(self, mime, body, charset):
        if mime == 'text/xml':
            return self.trans_xml(body, charset)
        elif mime == 'text/plain':
            return self.trans_text(body, charset)

    def _relay(self, host, port):
        """
        :param req: ProxyRequestHandler
        """
        self.close_connection = 0
        self.upconn = socket.create_connection((host, port), timeout=self.us_connect_timeout)
        req_headers = []
        url = urlparse.urlsplit(self.path)
        path = (url.path + '?' + url.query) if url.query else url.path
        req_headers.append('%s %s %s\r\n' % (self.command, path, self.protocol_version))
        for line in self.headers.headers:
            if line.startswith('Proxy-Connection: '):
                if line[18:].strip().lower() == 'keep-alive':
                    req_headers.append('Connection: keep-alive')
            else:
                req_headers.append(line)
        self.upconn.send(''.join(req_headers))
        self.upconn.send('\r\n')   # for simple
        # del req_headers[:]
        chunked = self.headers.get('Transfer-Encoding') == 'chunked'
        content_length = int(self.headers.get('Content-Length', 0))
        print('request-headers(%s):\n[%s]' % (self.command, ''.join(self.headers.headers)))
        if content_length:
            if content_length < self.ds_rbuf:
                self.upconn.send(self.rfile.read(content_length))
            else:
                while content_length > 0:
                    self.upconn.send(self.rfile.read(min(content_length, self.ds_rbuf)))
                    content_length -= self.ds_rbuf
        elif chunked:
            MAX_TIME = 600
            begin = time.time()
            while time.time() - begin < MAX_TIME:
                length = self.rfile.readline()
                size = length.rstrip()
                size = int(size, 16)
                self.upconn.send(length)
                if size <= 0:
                    tail = self.rfile.readline()
                    if tail != '\r\n':
                        raise StatusError(400)
                    self.upconn.send(tail)
                    break
                chunk = self.rfile.read(size + 2)
                if not chunk or len(chunk) != size + 2:
                    raise StatusError(500)
                self.upconn.send(chunk)

        usrfile = self.upconn.makefile('rb', self.us_rbuf)
        MAX_TIME = 600
        begin = time.time()
        headers = []
        while time.time() - begin < MAX_TIME:     # 接收 header
            line = usrfile.readline()
            if not line:
                raise StatusError(500)
            elif line == '\r\n':
                headers.append(line)
                break
            headers.append(line)

        status, mime, charset, chunked, content_length, content_length_index, \
            keep_alive, keep_alive_index = self.analysis_header(headers)
        should_trans = self.should_trans(mime, content_length, chunked) if mime else False
        # if keep_alive:
        #     headers[keep_alive_index] = 'Connection: close'

        if content_length:
            if should_trans:
                origin_body = usrfile.read(content_length)
                body = self.trans(mime, origin_body, charset)
                if body is not None:
                    headers[content_length_index] = 'Content-Length: ' + str(len(body)) + '\r\n'
                self.wfile.write(''.join(headers))
                self.wfile.write(body)
            else:
                self.wfile.write(''.join(headers))
                self.wfile.write(usrfile.read(content_length))
        elif chunked:   # NOTE: 暂时要求 每个chunk 必须是一个完整的xml
            self.wfile.write(''.join(headers))
            MAX_TIME = 600
            begin = time.time()
            while time.time() - begin < MAX_TIME:
                length = usrfile.readline()
                size = length.rstrip()
                size = int(size, 16)
                if size <= 0:
                    tail = usrfile.readline()
                    if tail != '\r\n':
                        raise StatusError(500)
                    self.wfile.write(tail)
                    break
                chunk = usrfile.read(size)
                if not chunk or len(chunk) != size:
                    break
                if should_trans:
                    chunk = self.trans(mime, chunk, charset)
                    if chunk is not None:
                        length = str(len(chunk)) + '\r\n'
                self.wfile.write(length)
                self.wfile.write(chunk) + '\r\n'
        if not keep_alive:
            self.upconn.close()

    def should_trans(self, content_type, content_length, chunked):
        return (self.command in ('REPORT', 'PROPFIND'))         \
            and (content_type in ('text/xml', 'text/plain'))    \
            and ((content_length <= 4 << 20) if content_length else chunked)

    def parse_content_type(self, line):
        content_type = line[14:].lower()
        info = content_type.split('charset=')
        content_type = info[0].lstrip(' ').rstrip('; \r\n')
        charset = info[1].strip(' "\'\r\n') if len(info) == 2 else 'utf-8'
        return content_type, charset

    def analysis_header(self, headers):
        index = 0
        info = [None, None, 'utf-8', None, None, None, None, None]
        for line in headers:
            if line.startswith('HTTP/'):
                status = line.split(' ', 2)
                if len(status) == 3:
                    if status[1].isdigit():
                        info[0] = int(status[1])
            if line.startswith('Content-Type: '):
                info[1], info[2] = self.parse_content_type(line)
            elif line.startswith('Transfer-Encoding: chunked'):
                info[3] = True
            elif line.startswith('Content-Length: '):
                info[4] = int(line[16:].strip())
                info[5] = index
            elif line.startswith('Connection: ') and line[12:22].lower() == 'keep-alive':
                info[6] = True
                info[7] = index
            index += 1
        return info

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
    Relayer.set_aliases({
        u'wu261': u'吴哥'
    })
    import thre
    ThreadingTCPServer(('', 3128), Relayer).serve_forever()
