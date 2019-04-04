import socket
from threading import Thread, Lock
import json
from bs4 import BeautifulSoup
import logging
import gzip
import datetime
from HTTPPacket import HTTPRequestPacket, HTTPResponsePacket


BUFSIZE = 1000000
TIMEOUT = 10
BACKLOG = 50
MAX_DATA_RECV = 4096
DEBUG = False
HTTP_PORT = 80
COLON = ':'
CRLF = '\r\n'
bCRLF = b'\r\n'
SEND_ADDR = b''
SEND_NAME = b''
RCPT_ADDR = b'hossein.soltanloo@gmail.com'
RCPT_NAME = b'Hossein Soltanloo'
MAIL_USER = b''
MAIL_PASS = b''
lock = Lock()


class ProxyServer:
    __instance = None
    config = {}

    def __init__(self):
        if ProxyServer.__instance is not None:
            raise Exception("This class is a singleton!")
        else:
            ProxyServer.__instance = self
        with open('config.json') as f:
            ProxyServer.config = json.load(f)

        logging.basicConfig(filename=self.config['logging']['logFile'], level=logging.DEBUG,
                            format='[%(asctime)s] %(message)s', datefmt='%d/%b/%Y:%H:%M:%S')
        if not ProxyServer.config['logging']['enable']:
            logging.disable(level=logging.INFO)

        logging.info("Proxy launched")
        logging.info("Creating server socket")
        self.serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.serverSocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        logging.info("Binding socket to port %d", ProxyServer.config['port'])
        self.serverSocket.bind(('localhost', ProxyServer.config['port']))
        logging.info("Listening for incoming requests")
        self.serverSocket.listen(BACKLOG)
        self.cache = {}

    @staticmethod
    def getInstance():
        if ProxyServer.__instance is None:
            ProxyServer()
        return ProxyServer.__instance

    def run(self):
        while 1:
            clientSocket, clientAddress = self.serverSocket.accept()
            logging.info("Accepted a request from client!")
            logging.info("Connection to [%s] from [%s] %s", self.serverSocket.getsockname()[0],
                         clientAddress[0], clientAddress[1])
            if clientAddress[0] not in [u['IP'] for u in self.config['accounting']['users']]:
                clientSocket.close()
                logging.info("User with ip [%s] has no permission no use proxy.", clientAddress[0])
                return
            else:
                Thread(target=self.handlerThread, args=(clientSocket, clientAddress)).start()

    @staticmethod
    def handleHTTPInjection(parsedResponse, config):
        if 'text/html' in parsedResponse.getHeader('content-type') and parsedResponse.getBody() != b'':
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
            if navbar not in soup.body:
                soup.body.insert(0, navbar)
            if 'gzip' in parsedResponse.getHeader('content-encoding'):
                body = gzip.compress(soup.encode())
            else:
                body = soup.encode()
            parsedResponse.setBody(body)
            parsedResponse.setHeader('content-length', str(len(body)))
        return parsedResponse

    @staticmethod
    def recvData(conn):
        conn.settimeout(TIMEOUT)
        data = conn.recv(BUFSIZE)
        if not data:
            return ""
        while b'\r\n\r\n' not in data:
            data += conn.recv(BUFSIZE)
        packet = ProxyServer.parseHTTP(data, 'response')
        body = packet.getBody()

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

        packet.setBody(body)
        return packet.pack()

    @staticmethod
    def alertAdministrator(packet):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(('mail.ut.ac.ir', 25))
        s.recv(1024)
        s.send(b'HELO mail.ut.ac.ir\r\n')
        s.recv(2048)
        s.send(b'MAIL FROM: <%b>\r\n' % SEND_ADDR)
        s.recv(2048)
        s.send(b'AUTH LOGIN\r\n')
        s.recv(2048)
        s.send(b'%b\r\n' % MAIL_USER)
        s.recv(2048)
        s.send(b'%b\r\n' % MAIL_PASS)
        s.recv(2048)
        s.send(b'RCPT TO: <%b>\r\n' % RCPT_ADDR)
        s.recv(2048)
        s.send(b'DATA\r\n')
        s.recv(2048)
        s.send(b'To: %b' % RCPT_NAME + b' <%b>\r\n' % RCPT_ADDR)
        s.send(b'From: %b' % SEND_NAME + b' <%b>\r\n' % SEND_ADDR)
        s.send(b'Subject: Unauthorized access detected\r\n')
        s.send(packet)
        s.send(b'\r\n')
        s.send(b'.\r\n')
        s.recv(2048)
        s.send(b'QUIT\r\n')
        pass

    @staticmethod
    def canCache(response):
        if len(response.getHeaders()) == 0:
            return False
        if response.getResponseCode() != 200:
            return False
        if 'cache-control' in response.getHeaders():
            value = response.getHeader('cache-control')
            if "private" in value or "no-cache" in value:
                return False
        if 'pragma' in response.getHeaders():
            value = response.getHeader('pragma')
            if "private" in value or "no-cache" in value:
                return False
        return True

    def handlerThread(self, clientSocket, clientAddress):
        request = self.recvData(clientSocket)
        user = self.findUser(clientAddress)
        if len(request) > 0:
            parsedRequest = ProxyServer.parseHTTP(request, 'request')
            logging.info('Client sent request to proxy with headers:\n'
                         + '----------------------------------------------------------------------\n'
                         + parsedRequest.getHeaders()
                         + '\n----------------------------------------------------------------------\n')
            parsedRequest.setHTTPVersion('HTTP/1.0')
            if self.handleRestriction(parsedRequest):
                clientSocket.close()
                return
            self.handlePrivacy(parsedRequest)

            response = self.getServerResponse(parsedRequest)
            if len(response):
                parsedResponse = ProxyServer.parseHTTP(response, 'response')
                if self.config['HTTPInjection']['enable'] and parsedRequest.getURL() is "/":
                    parsedResponse = self.handleHTTPInjection(parsedResponse, self.config)

                if self.canCache(parsedResponse) \
                        and parsedRequest.getFullURL() not in self.cache \
                        and 'text/html' not in parsedResponse.getHeader('content-type') \
                        and self.config['caching']['enable'] \
                        and 'no-cache' not in parsedRequest.getHeader('pragma') \
                        and 'no-cache' not in parsedRequest.getHeader('cache-control'):
                    logging.info('Caching response of ' + parsedRequest.getFullURL())
                    self.cacheResponse(parsedRequest, parsedResponse)
                else:
                    if parsedRequest.getFullURL() in self.cache:
                        logging.info('URL ' + parsedRequest.getFullURL() + ' is already cached')
                    logging.info('Not caching response of ' + parsedRequest.getFullURL())

                if parsedResponse.getHeader('content-length') != "":
                    contentLength = int(parsedResponse.getHeader('content-length'))
                else:
                    contentLength = parsedResponse.getBodySize()
                if int(user['volume']) < contentLength:
                    logging.info("User with IP " + user['IP'] + "ran out of traffic.")
                    clientSocket.close()
                else:
                    newTraffic = int(user['volume']) - contentLength
                    for u in self.config['accounting']['users']:
                        if u['IP'] == clientAddress[0]:
                            u['volume'] = str(newTraffic)
                            break
                    logging.info('Server sent response to proxy with headers:\n'
                                 + '----------------------------------------------------------------------\n'
                                 + parsedResponse.getHeaders().rstrip()
                                 + '\n----------------------------------------------------------------------\n')
                    clientSocket.send(parsedResponse.pack())
                    logging.info('Proxy sent response to client with headers:\n'
                                 + '----------------------------------------------------------------------\n'
                                 + parsedResponse.getHeaders().rstrip()
                                 + '\n----------------------------------------------------------------------\n')

                    clientSocket.close()

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

    def cacheResponse(self, parsedRequest, parsedResponse):
        if len(self.cache) < self.config['caching']['size']:
            logging.info("Caching URL: " + parsedRequest.getFullURL())
            lock.acquire()
            self.cache[parsedRequest.getFullURL()] = {}
            self.cache[parsedRequest.getFullURL()]['packet'] = parsedResponse
            self.cache[parsedRequest.getFullURL()]['lastUsage'] = datetime.datetime.now()
            lock.release()
        else:
            logging.info("Cache capacity is full, Deleting least recently used URL")
            lru = {'lastUsage': datetime.datetime.now(), 'packet': None}
            lruKey = ''
            for key in self.cache:
                if self.cache[key]['lastUsage'] < lru['lastUsage']:
                    lru = self.cache[key]
                    lruKey = key
            logging.info("Least recently used URL: " + lruKey)
            lock.acquire()
            self.cache.pop(lruKey)
            self.cache[parsedRequest.getFullURL()] = {}
            self.cache[parsedRequest.getFullURL()]['packet'] = parsedResponse
            self.cache[parsedRequest.getFullURL()]['lastUsage'] = datetime.datetime.now()
            lock.release()

    def getServerResponse(self, parsedRequest):
        if not self.config['caching']['enable'] \
                or 'no-cache' in parsedRequest.getHeader('pragma') \
                or 'no-cache' in parsedRequest.getHeader('cache-control'):
            logging.info("Caching is disabled or user wants no cache")
            response = self.sendRequestAndReceiveResponse(parsedRequest)
        else:
            logging.info("Cache will be used for " + parsedRequest.getFullURL())
            response = self.useCache(parsedRequest)
        return response

    def useCache(self, parsedRequest):
        url = parsedRequest.getFullURL()
        if url in self.cache:
            logging.info("HIT: URL " + url + " found in cached urls")
            if self.cache[url]['packet'].getHeader('expires') != "":
                expTime = datetime.datetime.strptime(self.cache[url]['packet'].getHeader('expires'),
                                                     '%a, %d %b %Y %H:%M:%S GMT')
                currTime = datetime.datetime.now()
                if expTime < currTime:
                    logging.info("Cached response for" + url + " is expired")
                    response = self.handleExpiredCache(parsedRequest, url)
                else:
                    logging.info("Cached response for" + url + " is still valid")
                    response = self.cache[url]['packet'].pack()
                    lock.acquire()
                    self.cache[url]['lastUsage'] = datetime.datetime.now()
                    lock.release()
            elif self.cache[url]['packet'].getHeader('last-modified') != "":
                logging.info("Expiration date is not set for " + url)
                lastMod = datetime.datetime.strptime(self.cache[url]['packet'].getHeader('last-modified'),
                                                     '%a, %d %b %Y %H:%M:%S GMT')
                currTime = datetime.datetime.now()
                if lastMod < currTime:
                    response = self.handleExpiredCache(parsedRequest, url)
                else:
                    logging.info("Cached response for" + url + " is still valid")
                    response = self.cache[url]['packet'].pack()
                    lock.acquire()
                    self.cache[url]['lastUsage'] = datetime.datetime.now()
                    lock.release()
            else:
                response = self.cache[url]['packet'].pack()
                lock.acquire()
                self.cache[url]['lastUsage'] = datetime.datetime.now()
                lock.release()
        else:
            logging.info("MISS: URL " + url + " not found in cache")
            response = self.sendRequestAndReceiveResponse(parsedRequest)
        return response

    def handleExpiredCache(self, parsedRequest, url):
        cachedResponse = self.cache[url]['packet']
        newRequest = parsedRequest.setHeader('if-modified-since', cachedResponse.getHeader('date'))
        response = self.sendRequestAndReceiveResponse(newRequest)
        newResponse = ProxyServer.parseHTTP(response, 'response')
        if newResponse.getResponseCode() == 304:
            logging.info("Response code is 304; Has not been modified since last time.\n URL: " + url)
            lock.acquire()
            self.cache[url]['packet'] = cachedResponse.setHeader('date', newResponse.getHeader('date'))
            self.cache[url]['lastUsage'] = datetime.datetime.now()
            lock.release()
        if newResponse.getResponseCode() == 200:
            logging.info("Response code is 200; Replacing new response.\n URL: " + url)
            lock.acquire()
            self.cache[url]['packet'] = newResponse
            self.cache[url]['lastUsage'] = datetime.datetime.now()
            lock.release()
        response = self.cache[url]['packet']
        return response

    def sendRequestAndReceiveResponse(self, parsedRequest):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((parsedRequest.getWebServerAddress(), parsedRequest.getPort()))
        logging.info("Proxy opening connection to server %s [%s]... Connection opened.",
                     parsedRequest.getWebServerAddress(),
                     socket.gethostbyname(parsedRequest.getWebServerAddress()))
        parsedRequest.removeHostname()
        s.sendall(parsedRequest.pack())
        logging.info('Proxy sent request to server with headers:\n'
                     + '----------------------------------------------------------------------\n'
                     + parsedRequest.getHeaders().rstrip()
                     + '\n----------------------------------------------------------------------\n')
        response = self.recvData(s)
        s.close()
        return response

    def handlePrivacy(self, parsedRequest):
        if self.config['privacy']['enable']:
            parsedRequest.setHeader('user-agent', self.config['privacy']['userAgent'])

    def findUser(self, clientAddress):
        return next((u for u in self.config['accounting']['users'] if u['IP'] == clientAddress[0]), None)

    def handleRestriction(self, parsedRequest):
        if self.config['restriction']['enable']:
            for target in self.config['restriction']['targets']:
                if target['URL'] in parsedRequest.getFullURL():
                    if target['notify'] == 'true':
                        self.alertAdministrator(parsedRequest.pack())
                    return True
        return False


if __name__ == '__main__':
    proxyServer = ProxyServer()
    proxyServer.run()
