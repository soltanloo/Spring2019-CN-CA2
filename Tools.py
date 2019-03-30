from HTTPPacket import HTTPRequestPacket, HTTPResponsePacket

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
