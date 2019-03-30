import sys
from Tools import Tools
import socket
import threading
from threading import Thread, Lock
import json
import pprint

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

        self.serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.serverSocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.serverSocket.bind(('localhost', ProxyServer.config['port']))
        self.serverSocket.listen(BACKLOG)
        self.cache = {}

    @staticmethod
    def getInstance():
        if ProxyServer.__instance is None:
            ProxyServer()
        return ProxyServer.__instance

    def run(self):
        while 1:
            conn, client_addr = self.serverSocket.accept()
            HandlerThread(conn).start()


class HandlerThread(Thread):

    def __init__(self, clientSocket):
        Thread.__init__(self)
        self.clientSocket = clientSocket

    def run(self):
        request = Tools.recvData(self.clientSocket)
        if len(request) > 0:
            parsedRequest = Tools.parseHTTP(request, 'request')
            parsedRequest.setHTTPVersion('HTTP/1.0')
            parsedRequest.printPacket()

            # create a socket to connect to the web server
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((parsedRequest.getWebServerAddress(),
                       parsedRequest.getPort()))
            s.sendall(request)  # send request to webserver

            data = Tools.recvData(s)
            parsedRequest = Tools.parseHTTP(data, 'response')
            parsedRequest.printPacket()
            self.clientSocket.send(data)
            s.close()
            self.clientSocket.close()


if __name__ == '__main__':
    proxyServer = ProxyServer()
    proxyServer.run()
