#!/usr/bin/env python
# -*- coding:utf-8 -*-

import sys
sys.path.append('/data/code/wumch')
import string
import urlparse
import time
import socket
from SocketServer import ThreadingTCPServer, BaseRequestHandler
import xml.dom.minidom as Dom
from pyage.tracer import Tracer


class StatusError(Exception):

    def __init__(self, code):
        self.code = code


class Relayer(BaseRequestHandler):

    aliases = {}

    def __init__(self, ds, ds_addr, server):
        """
        :param ds: socket._socketobject
        :param ds_addr: tuple
        :param server:
        :return:
        """
        self.keep_alive = False
        self.us_request_timeout = 30
        self.us_connect_timeout = 30
        self.us_rbuf = 256 << 10
        self.us_wbuf = 256 << 10
        self.ds_rbuf = 256 << 10
        self.ds_wbuf = 256 << 10
        self.us = None
        self.ds = ds
        BaseRequestHandler.__init__(self, ds, ds_addr, server)

    def handle(self):
        try:
            return self.relay()
        except StatusError, e:
            print('error, status code:[%d]' % e.code)
            print(Tracer().trace_exception())
            # self.send_error(e.code)
        except ValueError, e:
            print('ValueError(%s)' % e.message)
            print(Tracer().trace_exception())
            # self.send_error(402)
        except socket.timeout, e:
            print('socket timeout(%s)' % e.message)
            print(Tracer().trace_exception())
            # self.send_error(500)
        except Exception, e:
            print('Exception(%s)' % e.message)
            print(Tracer().trace_exception())
            # self.send_error(500)

    def log_error(self, format, *args):
        print(Tracer().trace())
        # self.log_message(format, *args)

    def trans(self, mime, body, charset):
        if mime == 'text/xml':
            return self.trans_xml(body, charset)
        elif mime == 'text/plain':
            return self.trans_text(body, charset)

    def relay(self):
        """
        :param req: ProxyRequestHandler
        """
        dsr = self.ds.makefile('rb', self.ds_rbuf)
        dsw = self.ds.makefile('wb', self.ds_wbuf)

        MAX_TIME = 600
        begin = time.time()
        req_headers = []
        while time.time() - begin < MAX_TIME:     # 接收 header
            line = dsr.readline()
            if not line:
                raise StatusError(500)
            req_headers.append(line)
            if line == '\r\n':
                break

        req = self.analysis_header(req_headers)
        if req['host'] is None:
            raise StatusError(400)

        self.us = socket.create_connection((req['host'], req['port']), timeout=self.us_connect_timeout)
        usr = self.us.makefile('rb', self.us_rbuf)
        usw = self.us.makefile('wb', self.us_rbuf)

        url = urlparse.urlsplit(req['path'])
        path = (url.path + '?' + url.query) if url.query else url.path
        req_headers[0] = ('%s %s %s\r\n' % (req['method'], path, req['version']))
        if req['keep-alive']:
            req_headers[req['keep-alive-index']] = 'Connection: keep-alive\r\n'
        usw.write(''.join(req_headers))
        # del req_headers[:]
        content_length = req['content-length']
        if content_length:
            if content_length < self.ds_rbuf:
                usw.write(dsr.read(content_length))
            else:
                while req['content-length'] > 0:
                    usw.write(dsr.read(min(content_length, self.ds_rbuf)))
                    content_length -= self.ds_rbuf
        elif req['chunked']:
            MAX_TIME = 600
            begin = time.time()
            while time.time() - begin < MAX_TIME:
                length = dsr.readline()
                usw.write(length)
                if length == '\r\n':
                    break
                size = int(length.rstrip, 16)
                if size <= 0:
                    tail = dsr.readline()
                    if tail != '\r\n':
                        raise StatusError(400)
                    usw.write(tail)
                    break
                chunk = dsr.read(size + 2)
                if not chunk or len(chunk) != size + 2:
                    raise StatusError(500)
                usw.write(chunk)
        usw.flush()

        MAX_TIME = 600
        begin = time.time()
        rep_headers = []
        while time.time() - begin < MAX_TIME:     # 接收 header
            line = usr.readline()
            if not line:
                raise StatusError(500)
            elif line == '\r\n':
                rep_headers.append(line)
                break
            rep_headers.append(line)

        rep = self.analysis_header(rep_headers)
        should_trans = self.should_trans(req['method'], rep['mime'], rep['content-length'], rep['chunked'])
        # if keep_alive:
        #     rep_headers[keep_alive_index] = 'Connection: close'
        content_length = rep['content-length']
        if content_length:
            if should_trans:
                origin_body = usr.read(content_length)
                body = self.trans(rep['mime'], origin_body, rep['charset'])
                if body is not None:
                    rep_headers[rep['content-length-index']] = 'Content-Length: ' + str(len(body)) + '\r\n'
                dsw.write(''.join(rep_headers))
                dsw.write(body)
            else:
                dsw.write(''.join(rep_headers))
                dsw.write(usr.read(content_length))
        elif rep['chunked']:   # NOTE: 暂时要求 每个chunk 必须是一个完整的xml
            dsw.write(''.join(rep_headers))
            MAX_TIME = 600
            begin = time.time()
            while time.time() - begin < MAX_TIME:
                length = usr.readline()
                if length == '\r\n':
                    dsw.write(length)
                    break
                size = int(length.rstrip(), 16)
                if size <= 0:
                    tail = usr.readline()
                    if tail != '\r\n':
                        raise StatusError(500)
                    dsw.write(tail)
                    break
                chunk = usr.read(size)
                if not chunk or len(chunk) != size:
                    break
                if should_trans:
                    chunk = self.trans(rep['mime'], chunk, rep['charset'])
                    if chunk is not None:
                        length = str(len(chunk)) + '\r\n'
                dsw.write(length)
                dsw.write(chunk + '\r\n')
        dsw.flush()

        if not rep['keep-alive']:
            self.us.close()
        if not req['keep-alive']:
            self.ds.close()

    def should_trans(self, method, mime, content_length, chunked):
        return (method in ('REPORT', 'PROPFIND'))         \
            and (mime in ('text/xml', 'application/xml', 'text/plain', 'application/text'))    \
            and ((content_length <= 4 << 20) if content_length else chunked)

    def parse_content_type(self, line):
        content_type = line[14:].lower()
        info = content_type.split('charset=')
        content_type = info[0].lstrip(' ').rstrip('; \r\n')
        charset = info[1].strip(' "\'\r\n') if len(info) == 2 else 'utf-8'
        return content_type, charset

    def analysis_header(self, headers):
        info = {
            'status': None,
            'mime': None,
            'charset': 'utf-8',
            'chunked': None,
            'content-length': None,
            'content-length-index': None,
            'keep-alive': None,
            'keep-alive-index': None,
            'host': None,
            'port': 80,
            'method': None,
            'path': None,
            'version': None,
        }
        if len(headers) < 1:
            return info
        line = headers[0]
        if line.startswith('HTTP/') or line.startswith('HTTPS/'):
            status = line.split(' ', 2)
            if len(status) == 3:
                if status[1].isdigit():
                    info['status'] = int(status[1])
        else:
            req = line.rstrip().split(' ', 2)
            if len(req) == 3:
                info['method'], info['path'], info['version'] = req
        index = 1
        for line in headers[1:]:
            if line.startswith('Content-Type: '):
                info['mime'], info['charset'] = self.parse_content_type(line)
            elif line.startswith('Transfer-Encoding: chunked'):
                info['chunked'] = True
            elif line.startswith('Content-Length: '):
                info['content-length'] = int(line[16:].strip())
                info['content-length-index'] = index
            elif line.startswith('Connection: ') and line[12:22].lower() == 'keep-alive':
                info['keep-alive'] = True
                info['keep-alive-index'] = index
            elif line.startswith('Proxy-Connection: ') and line[18:28].lower() == 'keep-alive':
                info['keep-alive'] = True
                info['keep-alive-index'] = index
            elif line.startswith('Host: '):
                addr = line[6:].strip().split(':')
                info['host'] = addr[0]
                if len(addr) == 2:
                    info['port'] = int(addr[1])
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
    ThreadingTCPServer(('', 3128), Relayer).serve_forever()
