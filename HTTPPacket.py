import pprint
COLON = ':'
CRLF = '\r\n'
bCRLF = b'\r\n'


class HTTPPacket:
    def __init__(self, line, header, body):
        self.line = line  # Packet first line(String)
        self.header = header  # Headers(Dict.{Field:Value})
        self.body = body  # Body(Bytes)

    # Make encoded packet data
    def pack(self):
        ret = self.line + CRLF
        for field in self.header:
            ret += field + ': ' + self.header[field] + CRLF
        ret += CRLF
        ret = ret.encode()
        ret += self.body
        return ret

    # Get HTTP header value
    # If does not exist, return empty string
    def getHeader(self, field):
        return self.header.get(field.lower(), "")

    # Set HTTP header value
    # If not exist, add new field
    # If value is empty string, remove field
    def setHeader(self, field, value):
        self.header[field.lower()] = value
        if value == '':
            self.header.pop(field.lower(), None)

    # Get URL from request packet line
    def getURL(self):
        return self.line.split(' ')[1]

    def getBodySize(self):
        return len(self.body)

    def getMethod(self):
        return self.line.split(' ')[0].upper()

    def getResponseCode(self):
        return int(self.line.split(' ')[1])

    # Remove hostname from request packet line
    def setURL(self, url):
        new_line = self.line.split(' ')
        new_line[1] = new_line[1].replace('http://' + url.netloc, '')
        new_line[1] = new_line[1].replace(url.netloc, '')
        self.line = ' '.join(new_line)

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
        return ret


class HTTPResponsePacket(HTTPPacket):
    def __init__(self, line, header, body):
        super().__init__(line, header, body)


class HTTPRequestPacket(HTTPPacket):
    def __init__(self, line, header, body):
        super().__init__(line, header, body)

    def getWebServerAddress(self):
        hostAddress = self.getHeader('Host')
        portPos = hostAddress.find(COLON)  # find the port pos (if any)
        if portPos == -1:  # default port
            webServerAddress = hostAddress
        else:
            webServerAddress = hostAddress[:portPos]

        return webServerAddress

    def getPort(self):
        hostAddress = self.getHeader('Host')
        portPos = hostAddress.find(':')  # find the port pos (if any)
        if portPos == -1:
            port = 80
        else:
            port = int(hostAddress[(portPos + 1):])
        return port

    def setHTTPVersion(self, ver):
        new_line = self.line.split(' ')
        new_line[2] = ver
        self.line = ' '.join(new_line)
