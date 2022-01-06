from socket import *
from typing import Callable
from secret_chat_server.errors import *
import logging


def receive_data_package(connection: socket):
    encrypted = bool.from_bytes(connection.recv(1), 'big')
    data_size = int.from_bytes(connection.recv(4), 'big')
    data = bytearray()
    while len(data) != data_size:
        data += connection.recv(1)
    return DataPackage(data, encrypted)


class DataPackage:
    def __init__(self, data: bytes, encrypted: bool = False):
        self.encrypted = encrypted
        self.data = data

    def encrypt(self, encryption_function: Callable[[bytes], bytes]):
        try:
            self.data = encryption_function(self.data)
        except AssertionError:
            raise InvalidPackageError
        self.encrypted = True

    def decrypt(self, decryption_function: Callable[[bytes], bytes]):
        try:
            self.data = decryption_function(self.data)
        except AssertionError:
            raise InvalidPackageError
        self.encrypted = False

    def message_code(self):
        if self.encrypted:
            raise PackageEncryptedError
        return self.data[0]

    def int_array(self, expected_int_number=None):
        if self.encrypted:
            raise PackageEncryptedError
        if len(self.data) < 2:
            logging.debug('Invalid data length')
            raise InvalidPackageError
        int_array = list()
        i = 1
        while i < len(self.data):
            int_size = self.data[i]
            if i + 1 + int_size > len(self.data):
                logging.debug('Invalid number of bytes')
                raise InvalidPackageError
            int_array.append(int.from_bytes(self.data[i+1:i+1+int_size], 'big'))
            i += int_size + 1
        if expected_int_number is not None and len(int_array) != expected_int_number:
            logging.debug('Unexpected number of ints')
            raise InvalidPackageError
        return int_array

    def string(self):
        if self.encrypted:
            raise PackageEncryptedError
        if len(self.data) < 2:
            raise InvalidPackageError
        return self.data[1:].decode('utf-8')

    def message_data(self) -> tuple[int, str]:
        if self.encrypted:
            raise PackageEncryptedError
        if len(self.data) < 6:
            raise InvalidPackageError
        recipient_id = int.from_bytes(self.data[1:5], 'big')
        message = self.data[5:].decode('utf-8')
        return recipient_id, message

    def set_message_code(self, message_code: int):
        self.data = message_code.to_bytes(1, 'big')

    def set_int_array(self, int_array: list[int]):
        for item in int_array:
            int_length = (item.bit_length() + 7) // 8
            self.data += int_length.to_bytes(1, 'big')
            self.data += item.to_bytes(int_length, 'big')

    def send(self, connection: socket):
        connection.send(self.encrypted.to_bytes(1, 'big'))
        connection.send(len(self.data).to_bytes(4, 'big'))
        bytes_sent = 0
        while bytes_sent != len(self.data):
            bytes_sent += connection.send(self.data[bytes_sent:])
