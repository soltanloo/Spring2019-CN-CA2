import socket
import threading
import json
from scipy import signal


class ProxyServer:
    def __init__(self, config):
        with open('config.json') as f:
            self.config = json.load(f)

        signal.signal(signal.SIGINT, self.shutdown)

        self.serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.serverSocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.serverSocket.bind(('127.0.0.1', config['port']))

        self.serverSocket.listen(10)
        self.__clients = {}