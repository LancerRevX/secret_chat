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


class Client:
    def __init__(self, server, connection: socket, address: str):
        self.server = server
        self.id = server.get_new_id()
        self.connection, self.address = connection, address
        logging.info(f'Client connected: {address}')

        self.secret_key: DesKey = None
        self.name = None

    def send_message_code(self, message_code: MessageCode):
        package = DataPackage(message_code.to_bytes(1, 'big'))
        if self.secret_key:
            package.encrypt(self.encryption_function)
        package.send(self.connection)
        logging.info(f'Sent message code {message_code} to client {self.id}')

    def send_int_array(self, message_code: MessageCode, int_array: list[int]):
        data = message_code.to_bytes(1, 'big')
        for item in int_array:
            int_length = (item.bit_length() + 7) // 8
            data += int_length.to_bytes(1, 'big')
            data += item.to_bytes(int_length, 'big')
        package = DataPackage(data)
        if self.secret_key is not None:
            package.encrypt(self.encryption_function)
        package.send(self.connection)
        logging.info('Sent int array')

    def encryption_function(self, data: bytes):
        return self.secret_key.encrypt(data, padding=True)

    def decryption_function(self, data: bytes):
        return self.secret_key.decrypt(data, padding=True)

    def process_package(self, package: DataPackage):
        try:
            if package.encrypted:
                if self.secret_key is None:
                    raise InvalidPackageError
                package.decrypt(self.decryption_function)
            message_code = package.message_code()
            logging.debug(f'Received message code {message_code}')
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
            self.send_message_code(MessageCode.INVALID_DATA)
        except InvalidRequestError:
            self.send_message_code(MessageCode.REFUSE)

    def process_message_create_secret_key(self, package: DataPackage):
        if self.secret_key is not None:
            logging.info(f'Attempt to create secret key when it is already created')
            raise InvalidRequestError
        p, g, A = package.int_array(3)
        if not diffie_hellman.validate_values(p, g, A):
            logging.info('Invalid diffie Hellman values')
            raise InvalidPackageError
        B, key = diffie_hellman.calculate_secret_key(p, g, A)
        self.send_int_array(MessageCode.CREATE_SECRET_KEY, [B])
        self.secret_key = DesKey((key % 2**64).to_bytes(8, 'big'))

    def process_message_login(self, package: DataPackage):
        logging.debug('Attempt to set a name')
        if self.name is not None:
            raise InvalidRequestError
        name = package.string()
        if self.server.is_name_taken(name):
            self.send_message_code(MessageCode.NAME_ALREADY_TAKEN)
            return
        self.name = name
        logging.info(f'Name {name} set for user with id {self.id}')

    def process_message_send_message(self, package: DataPackage):
        if self.name is None or self.secret_key is None:
            raise InvalidRequestError
        message = Message(text=package.string(),
                          client=self,
                          time=datetime.now())
        self.server.send_message_to_all(message)

    def process_message_get_messages(self, package: DataPackage):
        pass

    def send_message(self, message: Message):
        if self.secret_key is not None:
            package = DataPackage(MessageCode.SEND_MESSAGE.to_bytes(1, 'big') + message.text.encode('utf-8'))
            package.encrypt(self.encryption_function)
            package.send(self.connection)

    def start(self):
        while True:
            package = receive_data_package(self.connection)
            self.process_package(package)

