from socket import *
from threading import Thread
import logging
from .client import Client
from message import Message


class Server:
    PORT = 1999

    def __init__(self, log_file=None):
        logging.basicConfig(filename=log_file,
                            filemode='a',
                            format='%(message)s',
                            level=logging.DEBUG)

        self.socket = socket(AF_INET, SOCK_STREAM)
        self.socket.bind(('localhost', self.PORT))
        self.clients = []
        self.messages: list[Message] = []

    def is_name_taken(self, name):
        for client in self.clients:
            if client.name == name:
                return True
        return False

    def get_new_id(self):
        if len(self.clients) == 0:
            return 1
        return max(client.id for client in self.clients) + 1

    def send_message_to_all(self, message: Message):
        self.messages.append(message)
        for client in self.clients:
            client.send_message(message)

    def start(self):
        self.socket.listen()
        while True:
            connection, address = self.socket.accept()
            client = Client(self, connection, address)
            self.clients.append(client)
            Thread(target=client.start).start()
