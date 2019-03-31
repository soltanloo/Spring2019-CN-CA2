from HTTPPacket import HTTPRequestPacket, HTTPResponsePacket
import gzip
from bs4 import BeautifulSoup

BUFSIZE = 8192
TIMEOUT = 10
COLON = ':'
CRLF = '\r\n'
bCRLF = b'\r\n'


class Tools:
    @staticmethod
    def recvData(conn):
        conn.settimeout(TIMEOUT)
        data = conn.recv(BUFSIZE)
        if not data:
            return ""
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
    def handleHTTPInjection(parsedResponse, config):
        if 'text/html' in parsedResponse.getHeader('content-type'):
            if 'gzip' in parsedResponse.getHeader('content-encoding'):
                body = gzip.decompress(parsedResponse.getBody()).decode(encoding='UTF-8')
            else:
                body = parsedResponse.getBody().decode('UTF-8')
            soup = BeautifulSoup(body, 'lxml')
            navbar = soup.new_tag('div')
            navbar.string = config['HTTPInjection']['post']['body']
            navbar['style'] = 'position: fixed;' \
                              'z-index:1000;' \
                              'top: 0;' \
                              'height: 30px;' \
                              'width: 100%;' \
                              'background-color: green;' \
                              'display: flex;' \
                              'justify-content: center;' \
                              'align-items: center;'
            soup.body.insert(0, navbar)
            if 'gzip' in parsedResponse.getHeader('content-encoding'):
                body = gzip.compress(soup.encode())
            else:
                body = soup.encode()
            parsedResponse.setBody(body)
        return parsedResponse
