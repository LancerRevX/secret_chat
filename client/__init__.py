from secret_chat_server.message_codes import MessageCode
from secret_chat_server.server import Server
from data_package import DataPackage, receive_data_package
from socket import *
from random import randint
from threading import Thread
import diffie_hellman

# sock = socket(AF_INET, SOCK_STREAM)
# sock.connect(('localhost', Server.PORT))
#
#
# def receive_messages():
#     while True:
#         package = receive_data_package(sock)
#         message_code = package.message_code()
#         print(f'Received message code {message_code}')
#         if message_code == MessageCode.SEND_MESSAGE:
#             print(f'Received message: {package.string()}')
#
#
# Thread(target=receive_messages).start()
# while key := input():
#     if key == '1':
#         package = DataPackage(MessageCode.LOGIN.to_bytes(1, 'big') + b'Lancer.Rev.X')
#         package.send(sock)
#     elif key == '2':
#         package = DataPackage(MessageCode.SEND_MESSAGE.to_bytes(1, 'big') + b'Test Message')
#         package.send(sock)
#     elif key == '3':
#         p, g, A, a = diffie_hellman.generate_values()
#         package = DataPackage(b'')
#         package.set_message_code(MessageCode.CREATE_SECRET_KEY)
#         package.set_int_array([p, g, A])
#         package.send(sock)
#
