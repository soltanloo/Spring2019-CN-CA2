import pprint
COLON = ':'
CRLF = '\r\n'
bCRLF = b'\r\n'


class HTTPPacket:
    def __init__(self, line, header, body):
        self.line = line
        self.header = header
        self.body = body

    def pack(self):
        ret = self.line + CRLF
        for field in self.header:
            ret += field + ': ' + self.header[field] + CRLF
        ret += CRLF
        ret = ret.encode()
        ret += self.body
        return ret

    def getHeader(self, field):
        return self.header.get(field.lower(), "")

    def setHeader(self, field, value):
        self.header[field.lower()] = value
        if value == '':
            self.header.pop(field.lower(), None)

    def getURL(self):
        return self.line.split(' ')[1]

    def getBodySize(self):
        return len(self.body)

    def getBody(self):
        return self.body

    def setBody(self, body):
        self.body = body

    def getMethod(self):
        return self.line.split(' ')[0].upper()

    def getResponseCode(self):
        return int(self.line.split(' ')[1])

    def printPacket(self):
        ret = self.line + CRLF
        for field in self.header:
            ret += field + ': ' + self.header[field] + CRLF
        ret += CRLF
        pprint.pprint(ret)
        print(self.body)

    def getHeaders(self):
        ret = self.line + '\n'
        for field in self.header:
            ret += field + ': ' + self.header[field] + '\n'
        return ret.rstrip()


class HTTPResponsePacket(HTTPPacket):
    def __init__(self, line, header, body):
        super().__init__(line, header, body)


class HTTPRequestPacket(HTTPPacket):
    def __init__(self, line, header, body):
        super().__init__(line, header, body)
        self.cacheURL = self.cacheURL = self.line.split(' ')[1]

    def getFullURL(self):
        return self.cacheURL

    def getWebServerAddress(self):
        hostAddress = self.getHeader('Host')
        portPos = hostAddress.find(COLON)
        if portPos == -1:
            webServerAddress = hostAddress
        else:
            webServerAddress = hostAddress[:portPos]

        return webServerAddress

    def getPort(self):
        hostAddress = self.getHeader('Host')
        portPos = hostAddress.find(':')
        if portPos == -1:
            port = 80
        else:
            port = int(hostAddress[(portPos + 1):])
        return port

    def removeHostname(self):
        url = self.getWebServerAddress()
        new_line = self.line.split(' ')
        new_line[1] = new_line[1].replace('http://' + url, '')
        new_line[1] = new_line[1].replace(url, '')
        self.line = ' '.join(new_line)

    def setHTTPVersion(self, ver):
        new_line = self.line.split(' ')
        new_line[2] = ver
        self.line = ' '.join(new_line)
