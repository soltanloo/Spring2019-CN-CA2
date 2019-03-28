import sys
from Tools import Tools
import socket
import threading
from threading import Thread
import json
import pprint

BACKLOG = 50
MAX_DATA_RECV = 9192
DEBUG = False


class ProxyServer:
    def __init__(self):
        with open('config.json') as f:
            self.config = json.load(f)

        self.serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.serverSocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.serverSocket.bind(('localhost', self.config['port']))
        self.serverSocket.listen(BACKLOG)
        self.cache = {}

    def run(self):
        while 1:
            conn, client_addr = self.serverSocket.accept()
            HandlerThread(conn).start()


class HandlerThread(Thread):
    handlersLock = threading.RLock()

    def __init__(self, clientSocket):
        Thread.__init__(self)
        self.clientSocket = clientSocket

    def run(self):
        request = self.clientSocket.recv(MAX_DATA_RECV)
        # decodedRequest = request.decode('utf-8')
        # print(request)
        if len(request) > 0:
            parsedRequest = Tools.deserializeHTTPRequest(request)
            parsedRequest['httpVersion'] = 'HTTP/1.0'
            print(parsedRequest)
            if 'Proxy-Connection' in parsedRequest['headers']:
                parsedRequest['headers'].pop('Proxy-Connection')

            # create a socket to connect to the web server
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((parsedRequest['webserver']['address'], parsedRequest['webserver']['port']))
            s.send(request)  # send request to webserver

            while 1:
                # receive data from web server
                try:
                    data = s.recv(MAX_DATA_RECV)
                except ConnectionResetError as e:
                    pass

                if len(data) > 0:
                    # send to browser
                    try:
                        self.clientSocket.sendall(data)
                    except BrokenPipeError as e:
                        pass
                else:
                    break
            s.close()
            self.clientSocket.close()


if __name__ == '__main__':
    proxyServer = ProxyServer()
    proxyServer.run()
