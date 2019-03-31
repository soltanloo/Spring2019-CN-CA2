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
