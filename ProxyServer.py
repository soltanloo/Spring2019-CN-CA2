import sys
from Tools import Tools
import socket
from threading import Thread, Lock
import json
import pprint
from bs4 import BeautifulSoup
import logging
import gzip

BACKLOG = 50
MAX_DATA_RECV = 4096
DEBUG = False
HTTP_PORT = 80
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
            HandlerThread(clientSocket, clientAddress, name=str(clientAddress[1])).start()


class HandlerThread(Thread):

    def __init__(self, clientSocket, clientAddress, name):
        super(HandlerThread, self).__init__(name=name)
        self.clientSocket = clientSocket
        self.clientAddress = clientAddress

    def run(self):
        request = Tools.recvData(self.clientSocket)
        if len(request) > 0:
            parsedRequest = Tools.parseHTTP(request, 'request')
            logging.info('Client sent request to proxy with headers:\n'
                         + '----------------------------------------------------------------------\n'
                         + parsedRequest.getHeaders()
                         + '\n----------------------------------------------------------------------\n')

            parsedRequest.setHTTPVersion('HTTP/1.0')
            if ProxyServer.config['privacy']['enable']:
                parsedRequest.setHeader('user-agent', ProxyServer.config['privacy']['userAgent'])

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
            response = Tools.recvData(s)
            if len(response):
                parsedResponse = Tools.parseHTTP(response, 'response')
                if ProxyServer.config['HTTPInjection']['enable']:
                    # TODO: check if the index page is requested
                    parsedResponse = Tools.handleHTTPInjection(parsedResponse, ProxyServer.config)

                logging.info('Server sent response to proxy with headers:\n'
                             + '----------------------------------------------------------------------\n'
                             + parsedResponse.getHeaders().rstrip()
                             + '\n----------------------------------------------------------------------\n')
                self.clientSocket.send(parsedResponse.pack())
                logging.info('Proxy sent response to client with headers:\n'
                             + '----------------------------------------------------------------------\n'
                             + parsedResponse.getHeaders().rstrip()
                             + '\n----------------------------------------------------------------------\n')

                s.close()
                self.clientSocket.close()


if __name__ == '__main__':
    proxyServer = ProxyServer()
    proxyServer.run()
