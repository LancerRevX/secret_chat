from server import Server
from socket import *
from random import randint

sock = socket(AF_INET, SOCK_STREAM)
sock.connect(('localhost', Server.PORT))
import time
while True:
    sock.send(bytes([randint(1, 255)]))
    time.sleep(5)
