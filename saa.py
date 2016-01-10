#!/usr/bin/env python
# -*- coding:utf-8 -*-

import os
import sys
import time
import socket
from SocketServer import ThreadingTCPServer, BaseRequestHandler
import urlparse
import codecs
from xml import sax
from xml_handler import XmlHandler
from tracer import Tracer


class StatusError(Exception):

    def __init__(self, code, message=''):
        self.code = code
        self.message = message


class Relayer(BaseRequestHandler):

    aliases = {}

    def __init__(self, ds, ds_addr, server):
        """
        :type ds: socket._socketobject
        :type ds_addr: tuple
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
            print('error, status code:[%d]: %s' % (e.code, e.message))
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

    def relay(self):
        dsr = self.ds.makefile('rb', self.ds_rbuf)
        dsw = self.ds.makefile('wb', self.ds_wbuf)

        max_time = 600
        begin = time.time()
        req_headers = []
        while time.time() - begin < max_time:     # 接收 header
            line = dsr.readline()
            if not line:
                raise StatusError(500, 'line is empty')
            req_headers.append(line)
            if line == '\r\n':
                break

        req = self.analysis_header(req_headers)
        if req['host'] is None:
            raise StatusError(400, 'http header HOST miss')

        if self.us is None:
            self.us = socket.create_connection((req['host'], req['port']),
                timeout=self.us_connect_timeout)
        usr = self.us.makefile('rb', self.us_rbuf)
        usw = self.us.makefile('wb', self.us_rbuf)

        url = urlparse.urlsplit(req['path'])
        path = (url.path + '?' + url.query) if url.query else url.path
        req_headers[0] = ('%s %s %s\r\n' % (req['method'], path,
            req['version']))
        if req['keep-alive']:
            if req['keep-alive-index']:
                del req_headers[req['keep-alive-index']]
            if req['connection-index']:
                req_headers[req['connection-index']] = 'Connection: close\r\n'
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
            max_time = 600
            begin = time.time()
            while time.time() - begin < max_time:
                length = dsr.readline()
                usw.write(length)
                if length == '\r\n':
                    break
                size = int(length.rstrip(), 16)
                if size <= 0:
                    tail = dsr.readline()
                    if tail != '\r\n':
                        raise StatusError(400, 'bad chunked tail')
                    usw.write(tail)
                    break
                chunk = dsr.read(size + 2)
                if not chunk or len(chunk) != size + 2:
                    raise StatusError(500, 'bad chunk')
                usw.write(chunk)
        usw.flush()

        max_time = 600
        begin = time.time()
        rep_headers = []
        while time.time() - begin < max_time:     # 接收 header
            line = usr.readline()
            if not line:
                raise StatusError(500, 'need more line')
            elif line == '\r\n':
                rep_headers.append(line)
                break
            rep_headers.append(line)

        rep = self.analysis_header(rep_headers)
        if rep['keep-alive']:
            if rep['keep-alive-index']:
                del rep_headers[rep['keep-alive-index']]
            if rep['connection-index']:
                rep_headers[rep['connection-index']] = 'Connection: close\r\n'

        should_trans = self.should_trans(req['method'], rep['mime'],
            rep['content-length'], rep['chunked'])

        parser = None
        if should_trans:
            parser = sax.make_parser()
            handler = XmlHandler(out=dsw, chunked=not not rep['chunked'],
                 aliases=self.aliases, headers=rep_headers,
                 content_length_index=rep['content-length-index'],
                 encoding=rep['charset'])
            parser.setContentHandler(handler)

        # if keep_alive:
        #     rep_headers[keep_alive_index] = 'Connection: close'
        content_length = rep['content-length']
        if content_length is not None:
            if should_trans:
                origin_body = usr.read(content_length)
                # parser.feed(origin_body.decode(rep['charset']))
                parser.feed(origin_body)
                parser.getContentHandler().flush()
            else:
                dsw.write(''.join(rep_headers))
                if content_length > 0:
                    dsw.write(usr.read(content_length))
        elif rep['chunked']:
            dsw.write(''.join(rep_headers))
            max_time = 600
            begin = time.time()
            while time.time() - begin < max_time:
                length = usr.readline()
                size = int(length.rstrip(), 16)
                if size <= 0:
                    tail = usr.readline()
                    if tail != '\r\n':
                        raise StatusError(500, 'bad chunked tail')
                    dsw.write(length + tail)
                    break
                chunk = usr.read(size + 2)
                if not chunk or len(chunk) != size + 2:
                    break
                if should_trans:
                    parser.feed(chunk)
                    parser.getContentHandler().flush()
                else:
                    dsw.write(length)
                    dsw.write(chunk)
        dsw.flush()

    def should_trans(self, method, mime, content_length, chunked):
        return not not self.aliases and (method in ('REPORT', 'PROPFIND'))     \
            and (mime in ('text/xml', 'application/xml', 'text/plain',
                'application/text'))    \
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
            'connection-index': None,
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
            elif line.startswith('Connection: ') and line[12:22].lower() \
                    == 'keep-alive':
                info['keep-alive'] = True
                info['connection-index'] = index
            elif line.startswith('Keep-Alive: '):
                info['keep-alive'] = True
                info['keep-alive-index'] = index
            elif line.startswith('Proxy-Connection: ') and line[18:28].lower() \
                    == 'keep-alive':
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

    @classmethod
    def set_aliases(cls, aliases):
        cls.aliases = aliases

    do_GET = do_POST = do_OPTIONS = do_PUT = do_DELETE = \
        do_PROPFIND = do_REPORT = do_MERGE = relay


def get_config():
    import optparse
    parser = optparse.OptionParser(
        usage='%s [-a aliases-file] [-h host] [-p port] [aliases-file]' \
            % sys.argv[0], add_help_option=False)
    parser.add_option('--help', action='help',
        help='show this help and exit')
    parser.add_option('-h', '--host', dest='host', default='0.0.0.0',
        help='host to listen')
    parser.add_option('-p', '--port', dest='port', default=3128,
        help='port to listen')
    parser.add_option('-a', '--aliases', dest='aliases',
        help='svn author aliases file')
    options, args = parser.parse_args()
    if options.aliases is None:
        options.aliases = args[0] if len(args) == 1 else \
            os.path.join(os.path.dirname(__file__), 'aliases')
    options.port = int(options.port)
    return options


def get_aliases(alias_file=None):
    res = {}
    if os.path.isfile(alias_file):
        for line in codecs.open(alias_file, encoding='utf-8'):
            line = line.strip()
            if not line.startswith('#'):
                pair = line.split('=')
                if len(pair) == 2:
                    res[pair[0].strip()] = pair[1].strip(' \'"')
    return res


if __name__ == '__main__':
    options = get_config()
    aliases = get_aliases(options.aliases)
    Relayer.set_aliases(aliases)
    ThreadingTCPServer((options.host, options.port), Relayer).serve_forever()
