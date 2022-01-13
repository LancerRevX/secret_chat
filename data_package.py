from socket import *
from typing import Callable
from secret_chat_server.errors import *
import logging
from message import Message
from user import User


def receive_data(connection: socket, bytes_number: int):
    data = connection.recv(bytes_number)
    if len(data) == 0:
        raise ClientDisconnectedError
    return data


def receive_data_package(connection: socket):
    encrypted = bool.from_bytes(receive_data(connection, 1), 'big')
    data_size = int.from_bytes(receive_data(connection, 4), 'big')
    data = bytearray()
    while len(data) < data_size:
        data += receive_data(connection, 1)
    return DataPackage(data, encrypted)


class DataPackage:
    STRING_ENCODING = 'utf-8'
    INT_SIZE = 4
    BYTE_ORDER = 'big'

    def __init__(self, data: bytes = b'0', encrypted: bool = False):
        self.encrypted = encrypted
        self.data = data

    def encrypt(self, encryption_function: Callable[[bytearray], bytearray]):
        try:
            self.data = encryption_function(self.data)
        except AssertionError:
            raise InvalidPackageError
        self.encrypted = True

    def decrypt(self, decryption_function: Callable[[bytearray], bytearray]):
        try:
            self.data = decryption_function(self.data)
        except AssertionError:
            raise InvalidPackageError
        self.encrypted = False

    def message_code(self):
        if self.encrypted:
            raise PackageEncryptedError
        if len(self.data) < 1:
            raise InvalidPackageError
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
        return self.string_array()[0]

    def string_array(self, expected_strings_number=None) -> list[str]:
        if self.encrypted:
            raise PackageEncryptedError
        string_array = list()
        i = 1
        while i < len(self.data):
            if i + self.INT_SIZE > len(self.data):
                raise InvalidPackageError
            string_size = int.from_bytes(self.data[i:i+self.INT_SIZE], self.BYTE_ORDER)
            if i + self.INT_SIZE + string_size > len(self.data):
                raise InvalidPackageError
            string_array.append(self.data[i+self.INT_SIZE:i+self.INT_SIZE+string_size].decode(self.STRING_ENCODING))
            i += self.INT_SIZE + string_size
        if expected_strings_number is not None and len(string_array) != expected_strings_number:
            logging.debug('Unexpected number of strings')
            raise InvalidPackageError
        return string_array

    def messages_array(self, expected_messages_number=None) -> list[Message]:
        messages = list()
        string_array = self.string_array()
        if len(string_array) % 2 != 0:
            raise InvalidPackageError
        for username, text in zip(string_array[::2], string_array[1::2]):
            messages.append(Message(text, User(username), None))
        if expected_messages_number is not None and len(messages) != expected_messages_number:
            logging.debug('Unexpected number of messages')
            raise InvalidPackageError
        return messages

    def add_message(self, message: Message):
        self.add_string(message.client.name)
        self.add_string(message.text)

    def set_message_code(self, message_code: int):
        self.data = message_code.to_bytes(1, 'big')

    def set_int_array(self, int_array: list[int]):
        for item in int_array:
            int_length = (item.bit_length() + 7) // 8
            self.data += int_length.to_bytes(1, 'big')
            self.data += item.to_bytes(int_length, 'big')

    def add_string(self, string: str):
        string_bytes = string.encode(self.STRING_ENCODING)
        self.data += len(string_bytes).to_bytes(self.INT_SIZE, self.BYTE_ORDER)
        self.data += string_bytes

    def clear(self):
        self.data = self.data[0:1]

    def send(self, connection: socket):
        connection.send(self.encrypted.to_bytes(1, 'big'))
        connection.send(len(self.data).to_bytes(4, 'big'))
        bytes_sent = 0
        while bytes_sent != len(self.data):
            bytes_sent += connection.send(self.data[bytes_sent:])

    def __repr__(self):
        if self.encrypted:
            result = f'(Encrypted package)'
        else:
            result = f'(Message Code {self.message_code()}, {len(self.data[1:])} bytes of data)'
        return result
