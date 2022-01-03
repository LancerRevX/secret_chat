from socket import *
from threading import Thread
from enum import Enum, auto, unique
import logging


@unique
class MessageCode(Enum):
    REFUSE = 13
    DIFFIE_HELLMAN_STEP_1 = auto()
    DIFFIE_HELLMAN_STEP_2 = auto()


class Client():
    def __init__(self, connection: socket, address: str):
        self.connection, self.address = connection, address
        logging.info(f'Client connected: {address}')

    def receive_int(self) -> int:
        bytes_number = int.from_bytes(self.connection.recv(1), 'big')
        int_bytes = bytearray()
        for i in range(bytes_number):
            int_bytes += self.connection.recv(1)
        return int.from_bytes(int_bytes, 'big')

    def send_int(self, value: int):
        int_bytes = value.to_bytes((value.bit_length() + 7) // 8, 'big')
        self.connection.send(len(int_bytes).to_bytes(1, 'big'))
        for byte in int_bytes:
            self.connection.send(byte)

    def send_message_code(self, message_code: int):
        self.connection.send(message_code.to_bytes(1, 'big'))

    def start(self):
        while True:
            message_code = int.from_bytes(self.connection.recv(1), 'big')
            logging.debug(f'Received message code {message_code}')
            if message_code == MessageCode.DIFFIE_HELLMAN_STEP_1:
                p = self.receive_int()
                g = self.receive_int()


class Server():
    PORT = 1999

    def __init__(self, log_file=None):
        logging.basicConfig(filename=log_file,
                            filemode='a',
                            format='%(levelname)s - %(message)s',
                            level=logging.DEBUG)

        self.socket = socket(AF_INET, SOCK_STREAM)
        self.socket.bind(('localhost', self.PORT))

    def start(self):
        self.socket.listen()
        while True:
            connection, address = self.socket.accept()
            Thread(target=Client, args=(connection, address)).start()


if __name__ == '__main__':
    Server('log.txt').start()
