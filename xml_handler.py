# -*- coding:utf-8 -*-

import xml.sax as sax
from xml.sax.saxutils import XMLGenerator


class XmlHandler(XMLGenerator):

    tags = [
        {'name': 'author'},
        {'name': 'set-prop', 'attrs': {'name': 'svn:entry:last-author'}},
        {'name': 'rev-prop', 'attrs': {'name': 'svn:author'}},
        {'name': 'creator-displayname'},
        {'name': 'creator-displayname'},
    ]

    def __init__(self, out, chunked, aliases, headers, content_length_index=None, encoding='utf-8'):
        self.aliases = aliases
        self.rules = self.build_rules()
        self.trans = False
        self.chunked = chunked
        self.headers= headers
        self.content_length_index = content_length_index
        XMLGenerator.__init__(self, out=out, encoding=encoding)
        self.out = out
        self._write = self.write
        self._flush = self.flush
        self.content = ''
        self.doc_tag = None

    # todo: 为了性能，这里暂时只支持 name => attr,
    # 而且不允许 同名tag不同rule，但是配置支持这种rule
    def build_rules(self):
        rules = {}
        for tag in self.tags:
            attrs = tag.get('attrs', {})
            keys = attrs.keys()
            rule = True
            if len(keys) == 1:
                rule = (keys[0], attrs[keys[0]])
            elif len(keys) > 1:
                raise ValueError(u'暂时不支持复杂规则，这是为你好')
            rules[tag['name']] = rule
        return rules

    def startElement(self, name, attrs):
        if self.doc_tag is None:
            self.doc_tag = name
        pos = name.find(':')
        tag = name if pos == -1 else name[pos+1:]
        attr = self.rules.get(tag, False)
        XMLGenerator.startElement(self, name, attrs)
        if attr is not False:
            if attr is True:
                self.trans = True
            else:
                self.trans = attrs.get(attr[0]) == attr[1]
        else:
            self.trans = False

    def characters(self, content):
        XMLGenerator.characters(self, self.aliases.get(content.strip(), content)
            if self.trans else content)

    def write(self, content):
        self.content += content.encode(self._encoding) \
            if isinstance(content, unicode) else content

    def flush(self):
        if self.chunked:
            self.out.write(hex(len(self.content)) + '\r\n')
        else:
            if self.content and self.content[-1] != '\n':
                self.content += '\n'
            self.headers[self.content_length_index] = 'Content-Length: %d\r\n' \
                % len(self.content)
            self.out.write(''.join(self.headers))
        self.out.write(self.content)


if __name__ == '__main__':
    xml = '''
<?xml version="1.0" encoding="utf-8"?>
<D:merge xmlns:D="DAV:">
    <D:source>
        <D:href>/svn/!svn/txn/21-x</D:href>
    </D:source>
    <D:no-auto-merge></D:no-auto-merge>
    <D:no-checkout></D:no-checkout>
    <D:prop>
        <D:checked-in></D:checked-in>
        <D:version-name></D:version-name>
        <D:resourcetype></D:resourcetype>
        <D:creationdate></D:creationdate>
        <D:creator-displayname>wu261</D:creator-displayname>
    </D:prop>
</D:merge>
    '''
    handler = XmlHandler(out=open('/tmp/a.xml', 'w+'), aliases={'wu261': u'吴哥'})
    parser = sax.make_parser()
    parser.setContentHandler(handler)
    parser.feed(xml.strip())
    print
