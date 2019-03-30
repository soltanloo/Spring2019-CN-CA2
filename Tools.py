from HTTPPacket import HTTPRequestPacket, HTTPResponsePacket

BUFSIZE = 8192
TIMEOUT = 5
COLON = ':'
CRLF = '\r\n'
bCRLF = b'\r\n'


class Tools:
    @staticmethod
    def recvData(conn):
        conn.settimeout(TIMEOUT)
        data = conn.recv(BUFSIZE)
        if not data:
            return None
        while b'\r\n\r\n' not in data:
            data += conn.recv(BUFSIZE)
        packet = Tools.parseHTTP(data, 'response')
        body = packet.body

        if packet.getHeader('Content-Length'):
            received = 0
            expected = packet.getHeader('Content-Length')
            if expected is None:
                expected = '0'
            expected = int(expected)
            received += len(body)

            while received < expected:
                d = conn.recv(BUFSIZE)
                received += len(d)
                body += d

        packet.body = body
        return packet.pack()

    @staticmethod
    def parseHTTP(data, packType):
        if not data:
            return None
        line, data = data[0:data.index(bCRLF)], data[data.index(bCRLF) + len(bCRLF):]
        data, body = data[0:data.index(bCRLF + bCRLF)], data[data.index(bCRLF + bCRLF) + len(bCRLF + bCRLF):]
        data = data.split(bCRLF)
        line = line.decode()

        header = dict()
        for field in [elt.decode() for elt in data]:
            idx = field.index(':')
            key = field[0:idx]
            value = field[idx + 2:]
            header[key.lower()] = value

        if packType == 'request':
            return HTTPRequestPacket(line, header, body)
        elif packType == 'response':
            return HTTPResponsePacket(line, header, body)

    @staticmethod
    def deserializeHTTPRequest(request):
        parsedRequest = {
            'webserver': {},
            'method': "",
            'url': "",
            'httpVersion': "",
            'headers': {},
            'body': ""
        }
        startLine = request.split('\r\n')[0].split(' ')
        parsedRequest['method'] = startLine[0]
        parsedRequest['url'] = startLine[1]
        parsedRequest['httpVersion'] = startLine[2]

        restOfRequest = request.split('\r\n', 1)[1].split('\r\n\r\n')
        headers = restOfRequest[0].split('\r\n')
        for header in headers:
            splitHeader = header.split(': ', 1)
            parsedRequest['headers'][splitHeader[0]] = splitHeader[1]
        if len(restOfRequest) > 1:
            parsedRequest['body'] = restOfRequest[1]

        portPos = parsedRequest['headers']['Host'].find(':')  # find the port pos (if any)
        if portPos == -1:  # default port
            port = 80
            webserver = parsedRequest['headers']['Host']
        else:  # specific port
            port = int(parsedRequest['headers']['Host'][(portPos + 1):])
            webserver = parsedRequest['headers']['Host'][:portPos]

        parsedRequest['webserver']['address'] = webserver
        parsedRequest['webserver']['port'] = port

        return parsedRequest

    @staticmethod
    def serializeHTTPRequest(request):
        pass

    @staticmethod
    def deserializeHTTPResponse(response):
        parsedResponse = {
            'statusCode': "",
            'statusMessage': "",
            'httpVersion': "",
            'headers': {},
            'body': ""
        }
        startLine = response.split('\r\n')[0].split(' ', 2)
        parsedResponse['httpVersion'] = startLine[0]
        parsedResponse['statusCode'] = startLine[1]
        parsedResponse['statusMessage'] = startLine[2]

        restOfResponse = response.split('\r\n', 1)[1].split('\r\n\r\n')
        headers = restOfResponse[0].split('\r\n')
        for header in headers:
            splitHeader = header.split(': ', 1)
            parsedResponse['headers'][splitHeader[0]] = splitHeader[1]
        if len(restOfResponse) > 1:
            parsedResponse['body'] = restOfResponse[1]
        return parsedResponse

    @staticmethod
    def serializeHTTPResponse(response):
        pass
