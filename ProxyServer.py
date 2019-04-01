import sys
from Tools import Tools
import socket
from threading import Thread, Lock
import json
import pprint
from bs4 import BeautifulSoup
import logging
import gzip
import datetime

BUFSIZE = 8192
TIMEOUT = 10
BACKLOG = 50
MAX_DATA_RECV = 4096
DEBUG = False
HTTP_PORT = 80
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
            Thread(target=self.handlerThread, args=(clientSocket, clientAddress)).start()
            # HandlerThread(clientSocket, clientAddress, name=str(clientAddress[1])).start()

    @staticmethod
    def handleHTTPInjection(parsedResponse, config):
        # TODO: increase content-length
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
            if navbar not in soup.body:
                soup.body.insert(0, navbar)
            if 'gzip' in parsedResponse.getHeader('content-encoding'):
                body = gzip.compress(soup.encode())
            else:
                body = soup.encode()
            parsedResponse.setBody(body)
        return parsedResponse

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
    def alertAdministrator(packet):
        # TODO: handle errors
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
        if clientAddress[0] not in [u['IP'] for u in self.config['accounting']['users']]:
            clientSocket.close()
            logging.info("User with ip [%s] has no permission no use proxy.", clientAddress[0])
            # TODO: send response and show an error message
            return
        else:
            user = next((u for u in self.config['accounting']['users'] if u['IP'] == clientAddress[0]), None)
        if len(request) > 0:
            parsedRequest = Tools.parseHTTP(request, 'request')
            logging.info('Client sent request to proxy with headers:\n'
                         + '----------------------------------------------------------------------\n'
                         + parsedRequest.getHeaders()
                         + '\n----------------------------------------------------------------------\n')

            parsedRequest.setHTTPVersion('HTTP/1.0')
            if self.config['restriction']['enable']:
                for target in self.config['restriction']['targets']:
                    if target['URL'] in parsedRequest.getURL():
                        clientSocket.close()
                        if target['notify'] == 'true':
                            self.alertAdministrator(parsedRequest.pack())
                        return
            if self.config['privacy']['enable']:
                parsedRequest.setHeader('user-agent', self.config['privacy']['userAgent'])

            if 'no-cache' in parsedRequest.getHeader('pragma') or 'no-cache' in parsedRequest.getHeader('cache-control'):
                print('doesn\'t want to use cache')
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.connect((parsedRequest.getWebServerAddress(), parsedRequest.getPort()))
                logging.info("Proxy opening connection to server %s [%s]... Connection opened.",
                             parsedRequest.getWebServerAddress(),
                             socket.gethostbyname(parsedRequest.getWebServerAddress()))
                s.sendall(parsedRequest.pack())
                logging.info('Proxy sent request to server with headers:\n'
                             + '----------------------------------------------------------------------\n'
                             + parsedRequest.getHeaders().rstrip()
                             + '\n----------------------------------------------------------------------\n')
                response = self.recvData(s)
                s.close()
            else:
                print('wants to use cache')
                url = parsedRequest.getURL()
                if url in self.cache:
                    print('url in cache', url)
                    if self.cache[url]['packet'].getHeader('expires') != "":
                        expTime = datetime.datetime.strptime(self.cache[url]['packet'].getHeader('expires'), '%a, %d %b %Y %H:%M:%S GMT')
                        currTime = datetime.datetime.now()
                        if expTime < currTime:
                            response = self.cache[url]['packet'].pack()
                        else:
                            print("Using cache")
                            response = self.cache[url]['packet'].pack()
                    else:
                        lastMod = datetime.datetime.strptime(self.cache[url]['packet'].getHeader('last-modified'),
                                                             '%a, %d %b %Y %H:%M:%S GMT')
                        currTime = datetime.datetime.now()
                        if lastMod < currTime:
                            response = self.cache[url]['packet'].pack()
                        else:
                            print("Using cache")
                            response = self.cache[url]['packet'].pack()
                else:
                    print('url not in cache', url)
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.connect((parsedRequest.getWebServerAddress(), parsedRequest.getPort()))
                    logging.info("Proxy opening connection to server %s [%s]... Connection opened.",
                                 parsedRequest.getWebServerAddress(),
                                 socket.gethostbyname(parsedRequest.getWebServerAddress()))
                    s.sendall(parsedRequest.pack())
                    logging.info('Proxy sent request to server with headers:\n'
                                 + '----------------------------------------------------------------------\n'
                                 + parsedRequest.getHeaders().rstrip()
                                 + '\n----------------------------------------------------------------------\n')
                    response = self.recvData(s)
                    s.close()

            if len(response):
                parsedResponse = Tools.parseHTTP(response, 'response')
                if self.config['HTTPInjection']['enable']:
                    # TODO: check if the index page is requested
                    parsedResponse = self.handleHTTPInjection(parsedResponse, self.config)
                if self.canCache(parsedResponse) and parsedRequest.getURL() not in self.cache:
                    print('caching', parsedRequest.getURL())
                    self.cache[parsedRequest.getURL()] = {}
                    self.cache[parsedRequest.getURL()]['packet'] = parsedResponse
                else:
                    print('not caching', parsedRequest.getURL())
                if parsedResponse.getHeader('content-length') != "":
                    contentLength = int(parsedResponse.getHeader('content-length'))
                else:
                    contentLength = parsedResponse.getBodySize()
                if int(user['volume']) < contentLength:
                    logging.info("User ran out of traffic.")
                    clientSocket.close()
                else:
                    # TODO: check response status before reducing traffic
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


if __name__ == '__main__':
    proxyServer = ProxyServer()
    proxyServer.run()
