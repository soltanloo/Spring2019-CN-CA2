import logging


class Logger:
    @staticmethod
    def logRequestAccept():
        logging.info("Accepted a request from client!")