#!/usr/bin/env python
# -*- coding:utf-8 -*-

import re
import xml.dom.minidom as Dom
from proxy2 import ProxyRequestHandler, ThreadingHTTPServer


class SvnAuthorAlias(ProxyRequestHandler):

    aliases = {
        'A1361': u'wumch'
    }
    regexp = re.compile(r'^\s*\d+\s*(A\d+)(?=\s*)')

    def response_handler(self, req, req_body, res, res_body):
        print('req.command: ', req.command)
        print('req.headers: ', req.headers)
        print('req.path: ', req.path)
        print('req.body: ', req_body)
        print('res.contentLength: ', res.headers.get('Content-Length'))
        print('res.body: ', res_body)
        return self.trans(req, req_body, res, res_body)

    def trans(self, req, req_body, res, res_body):
        transer = self.get_transer(req, req_body, res, res_body)
        return res_body if transer is None else transer(res_body)

    def save_handler(self, req, req_body, res, res_body):
        pass

    def get_transer(self, req, req_body, res, res_body):
        if self.is_blame(req, req_body):
            transer = None

            content_type = res.headers.get('Content-Type')
            if content_type:
                if content_type.startswith('text/xml'):
                    transer = self.trans_xml
                elif content_type.startswith('text/html') or \
                    content_type.startswith('text/plain'):
                    transer = self.trans_text

                if transer is not None:
                    info = content_type.split('charset=', 1)
                    charset = info[1].strip().lower() if len(info) == 2 else 'utf-8'
                    return lambda content: transer(content, charset)

    def is_blame(self, req, req_body):
        return False

    def trans_text(self, text, charset):
        return text

    def trans_xml(self, xml, charset):
        try:
            dom = Dom.parseString(xml)
            for element in dom.getElementsByTagName('author'):
                if element.firstChild.nodeType == element.TEXT_NODE:
                    element.firstChild.nodeValue = self.aliases.get(
                        element.firstChild.nodeValue,
                        element.firstChild.nodeValue)
            return dom.toxml(charset)
        except Exception, e:
            print(e.message)
            return xml


if __name__ == '__main__':
    import sys
    if sys.argv[1:]:
        port = int(sys.argv[1])
    else:
        port = 3128
    server_address = ('', port)

    SvnAuthorAlias.protocol_version = "HTTP/1.1"
    httpd = ThreadingHTTPServer(server_address, SvnAuthorAlias)

    sa = httpd.socket.getsockname()
    print "Serving HTTP Proxy on", sa[0], "port", sa[1], "..."
    httpd.serve_forever()
