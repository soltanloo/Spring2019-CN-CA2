import sys
from Tools import Tools
import socket
import threading
from threading import Thread
import json
import pprint

BACKLOG = 50
MAX_DATA_RECV = 4096
DEBUG = False


class ProxyServer:
    def __init__(self):
        with open('config.json') as f:
            self.config = json.load(f)

        self.serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.serverSocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.serverSocket.bind(('localhost', self.config['port']))
        self.serverSocket.listen(BACKLOG)
        self.__clients = {}

    def run(self):
        while 1:
            conn, client_addr = self.serverSocket.accept()
            threading.Thread(target=proxy_thread, args=(conn, client_addr)).start()


class HandlerThread(Thread):
    def __init__(self):
        Thread.__init__(self)

    def run(self):
        pass


def proxy_thread(conn, client_addr):
    # get the request from browser
    request = conn.recv(MAX_DATA_RECV)
    # decodedRequest = request.decode('utf-8')
    # print(request)

    parsedRequest = Tools.deserializeHTTPRequest(request.decode('UTF-8'))
    pprint.pprint(parsedRequest)

    # create a socket to connect to the web server
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((parsedRequest['webserver']['address'], parsedRequest['webserver']['port']))
    s.send(request)  # send request to webserver

    while 1:
        # receive data from web server
        data = s.recv(MAX_DATA_RECV)

        if len(data) > 0:
            # send to browser
            conn.send(data)
        else:
            break
    s.close()
    conn.close()


if __name__ == '__main__':
    proxyServer = ProxyServer()
    proxyServer.run()
