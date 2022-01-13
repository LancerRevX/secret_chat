from .message_codes import MessageCode
from socket import *
import logging
from random import randint
from des import DesKey
from typing import Callable
import diffie_hellman
from .errors import *
from data_package import DataPackage, receive_data_package
from message import Message
from datetime import datetime
from user import User


class Client:
    def __init__(self, server, connection: socket, address: str):
        self.server = server
        self.id = server.get_new_id()
        self.connection, self.address = connection, address
        self.secret_key: DesKey = None
        self.name = None
        logging.info(f'{self} connected, ip = {address[0]}, port = {address[1]}')

    def send_message_code(self, message_code: int):
        package = DataPackage(message_code.to_bytes(1, 'big'))
        if self.secret_key:
            package.encrypt(self.encryption_function)
        package.send(self.connection)

    def send_int_array(self, message_code: int, int_array: list[int]):
        data = message_code.to_bytes(1, 'big')
        for item in int_array:
            int_length = (item.bit_length() + 7) // 8
            data += int_length.to_bytes(1, 'big')
            data += item.to_bytes(int_length, 'big')
        package = DataPackage(data)
        if self.secret_key is not None:
            package.encrypt(self.encryption_function)
        package.send(self.connection)

    def encryption_function(self, data: bytearray) -> bytearray:
        return bytearray(self.secret_key.encrypt(bytes(data), padding=True))

    def decryption_function(self, data: bytearray) -> bytearray:
        return bytearray(self.secret_key.decrypt(bytes(data), padding=True))

    def process_package(self, package: DataPackage):
        try:
            if package.encrypted:
                if self.secret_key is None:
                    raise InvalidPackageError
                package.decrypt(self.decryption_function)
            message_code = package.message_code()
            logging.debug(f'{self} - received package: {package}')
            if message_code == MessageCode.CREATE_SECRET_KEY:
                self.process_message_create_secret_key(package)
            elif message_code == MessageCode.LOGIN:
                self.process_message_login(package)
            elif message_code == MessageCode.SEND_MESSAGE:
                self.process_message_send_message(package)
            elif message_code == MessageCode.GET_MESSAGES:
                self.process_message_get_messages(package)
            else:
                raise InvalidRequestError
        except InvalidPackageError:
            logging.warning(f'{self} - invalid package')
            self.send_message_code(MessageCode.INVALID_DATA)
        except InvalidRequestError:
            logging.warning(f'{self} - invalid request')
            self.send_message_code(MessageCode.REFUSE)

    def process_message_create_secret_key(self, package: DataPackage):
        logging.debug(f'{self} - attempt to create a secret key')
        if self.secret_key is not None:
            logging.warning(f'{self} - attempt to create secret key when it is already created')
            raise InvalidRequestError
        p, g, B = package.int_array(3)
        if not diffie_hellman.validate_values(p, g, B):
            logging.warning(f'{self} - invalid diffie Hellman values')
            raise InvalidPackageError
        a = diffie_hellman.generate_a(10)
        key = diffie_hellman.calculate_secret_key(p, a, B)
        A = diffie_hellman.calculate_A(p, g, a)
        logging.debug(f'{self} - p = {p}, g = {g}, B = {B}, a = {a}, A = {A}, key = {key}')
        self.send_int_array(MessageCode.CREATE_SECRET_KEY, [A])
        self.secret_key = DesKey((key % 2**64).to_bytes(8, 'big'))
        logging.info(f'{self} - created secret key')

    def process_message_login(self, package: DataPackage):
        logging.debug(f'{self} - attempt to login')
        if self.name is not None:
            raise InvalidRequestError
        name = package.string()
        if self.server.is_name_taken(name):
            self.send_message_code(MessageCode.NAME_ALREADY_TAKEN)
            return
        self.name = name
        logging.info(f'{self} - set name "{name}"')

    def process_message_send_message(self, package: DataPackage):
        logging.debug(f'{self} - attempt to send message')
        if self.name is None or self.secret_key is None:
            raise InvalidRequestError
        message = Message(text=package.string(),
                          client=User(self.name),
                          time=datetime.now())
        logging.info(f'{self} - sending message {message}')
        self.server.send_message_to_all(message)

    def process_message_get_messages(self, package: DataPackage):
        logging.debug(f'{self} - attempt to get messages')
        if self.secret_key is None:
            raise InvalidRequestError
        package = DataPackage()
        package.set_message_code(MessageCode.GET_MESSAGES)
        for message in self.server.messages:
            package.add_message(message)
        package.encrypt(self.encryption_function)
        package.send(self.connection)
        logging.debug(f'{self} - sent messages')

    def send_message(self, message: Message):
        if self.secret_key is not None:
            package = DataPackage()
            package.set_message_code(MessageCode.SEND_MESSAGE)
            package.add_message(message)
            package.encrypt(self.encryption_function)
            package.send(self.connection)

    def start(self):
        try:
            while True:
                package = receive_data_package(self.connection)
                self.process_package(package)
        except (ClientDisconnectedError, OSError):
            logging.info(f'{self} - disconnected')
            self.connection.close()
            self.server.clients.remove(self)

    def __str__(self):
        return f'Client (id = {self.id}, name = {self.name})'

