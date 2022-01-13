import tkinter as tk
from tkinter.messagebox import showerror, showwarning
from socket import *
from threading import Thread
from data_package import receive_data_package, DataPackage
from secret_chat_server.message_codes import MessageCode
from secret_chat_server.errors import *
from des import DesKey
import diffie_hellman
from message import Message
import logging
from user import User


class SecretChatInterface(tk.Tk):
    BACKGROUND_COLOR = 'white'

    def __init__(self):
        super().__init__()

        logging.basicConfig(format='%(message)s', level=logging.DEBUG)

        self.title('Секретный чат')
        self.geometry('800x500')
        self.minsize(800, 500)

        self.server_address = tk.StringVar(value='localhost')
        self.port = tk.IntVar(value=1999)
        self.message = tk.StringVar()
        self.name = tk.StringVar(value='User')

        self.connection = None
        self.secret_key = None
        self.connected = False

        self.p = tk.IntVar()
        self.g = tk.IntVar()
        self.a = tk.IntVar()

        diffie_hellman_frame = tk.LabelFrame(self, text='Создание секретного ключа по протоколу Диффи-Хеллмана')
        tk.Label(diffie_hellman_frame, text='p =').pack(side='left')
        self.p_entry = tk.Entry(diffie_hellman_frame, textvariable=self.p)
        self.p_entry.pack(side='left')
        tk.Label(diffie_hellman_frame, text='g =').pack(side='left')
        self.g_entry = tk.Entry(diffie_hellman_frame, textvariable=self.g)
        self.g_entry.pack(side='left')
        tk.Label(diffie_hellman_frame, text='a =').pack(side='left')
        self.a_entry = tk.Entry(diffie_hellman_frame, textvariable=self.a)
        self.a_entry.pack(side='left')
        self.generate_button = tk.Button(diffie_hellman_frame,
                                         text='Генерировать',
                                         command=self.generate_diffie_hellman)
        self.generate_button.pack(side='left')
        diffie_hellman_frame.pack()

        connect_frame = tk.Frame(self, borderwidth=5)
        tk.Label(connect_frame, text='Адрес сервера =').pack(side='left')
        self.address_entry = tk.Entry(connect_frame, textvariable=self.server_address)
        self.address_entry.pack(side='left')
        tk.Label(connect_frame, text='Порт =').pack(side='left')
        self.port_entry = tk.Entry(connect_frame, textvariable=self.port)
        self.port_entry.pack(side='left')
        tk.Label(connect_frame, text='Имя =').pack(side='left')
        self.name_entry = tk.Entry(connect_frame, textvariable=self.name)
        self.name_entry.pack(side='left')
        self.connect_button = tk.Button(connect_frame, text='Подключиться', command=self.connect_to_server)
        self.connect_button.pack(side='left')
        self.disconnect_button = tk.Button(connect_frame, text='Отключиться', state='disabled', command=self.disconnect)
        self.disconnect_button.pack(side='left')
        connect_frame.pack()

        self.messages_canvas = tk.Canvas(self, background=self.BACKGROUND_COLOR)
        self.messages_frame = tk.Frame(self.messages_canvas, background=self.BACKGROUND_COLOR)
        self.messages_frame.grid_columnconfigure(0, weight=1)

        self.messages_frame.bind(
            "<Configure>",
            lambda e: self.messages_canvas.configure(
                scrollregion=self.messages_canvas.bbox("all")
            )
        )
        messages_scrollbar = tk.Scrollbar(self.messages_canvas, orient='vertical', command=self.messages_canvas.yview)
        self.messages_canvas.configure(yscrollcommand=messages_scrollbar.set)

        canvas_frame = self.messages_canvas.create_window((0, 0), window=self.messages_frame, anchor='nw')
        self.messages_canvas.bind(
            '<Configure>',
            lambda event: self.messages_canvas.itemconfig(canvas_frame, width=event.width - 16)
        )
        self.messages_canvas.pack(expand=1, fill='both')
        messages_scrollbar.pack(side='right', fill='y')

        send_message_frame = tk.Frame(self)
        tk.Label(send_message_frame, text='Сообщение =').pack(side='left')
        self.message_entry = tk.Entry(send_message_frame, textvariable=self.message, state='disabled')
        self.message_entry.pack(side='left', expand=1, fill='x')
        self.send_message_button = tk.Button(send_message_frame, text='Отправить', state='disabled', command=self.send_message)
        self.send_message_button.pack(side='left')
        send_message_frame.pack(fill='x', padx=16, pady=8)

        self.generate_diffie_hellman()

        # self.add_message(Message('Hello!', User('Adahn'), None))
        # self.add_message(Message('Another message!', User('User'), None))
        # self.add_message(Message('And another one!', User('Adahn'), None))
        # for i in range(16):
        #     self.add_message(Message(str(i), User('Test'), None))

        self.protocol('WM_DELETE_WINDOW', self.on_close)

        self.bind('<Return>', lambda event: self.send_message())

    def process_messages(self):
        try:
            while True:
                package = receive_data_package(self.connection)
                logging.debug(f'Received data package: {package}')
                if package.encrypted:
                    if self.secret_key is None:
                        self.server_error()
                        return
                    package.decrypt(self.decryption_function)
                logging.info(package)
                message_code = package.message_code()
                if message_code == MessageCode.GET_MESSAGES:
                    messages = package.messages_array()
                    for message in messages:
                        self.add_message(message)
                elif message_code == MessageCode.SEND_MESSAGE:
                    self.add_message(package.messages_array(1)[0])
                elif message_code == MessageCode.NAME_ALREADY_TAKEN:
                    showwarning('Ошибка', 'Имя уже занято')
                    self.disconnect()
                elif message_code == MessageCode.CREATE_SECRET_KEY:
                    B = package.int_array(1)[0]
                    key = diffie_hellman.calculate_secret_key(self.p.get(), self.a.get(), B)
                    self.secret_key = DesKey((key % 2 ** 64).to_bytes(8, 'big'))

                    login_package = DataPackage()
                    login_package.set_message_code(MessageCode.LOGIN)
                    login_package.add_string(self.name.get())
                    login_package.encrypt(self.encryption_function)
                    login_package.send(self.connection)

                    get_messages_package = DataPackage()
                    get_messages_package.set_message_code(MessageCode.GET_MESSAGES)
                    get_messages_package.encrypt(self.encryption_function)
                    get_messages_package.send(self.connection)
                elif message_code in (MessageCode.REFUSE, MessageCode.INVALID_MESSAGE_CODE, MessageCode.INVALID_DATA):
                    self.server_error()
        except (OSError, ClientDisconnectedError):
            if self.connected:
                showwarning('Ошибка', 'Соединение с сервером потеряно')
                self.disconnect()
        except (AssertionError, InvalidPackageError, diffie_hellman.DiffieHellmanError):
            self.server_error()

    def connect_to_server(self):
        try:
            if len(self.name.get()) == 0:
                showwarning('Ошибка', 'Введите имя')
                return

            self.address_entry['state'] = 'disabled'
            self.port_entry['state'] = 'disabled'
            self.name_entry['state'] = 'disabled'
            self.connect_button['state'] = 'disabled'
            self.p_entry['state'] = 'disabled'
            self.g_entry['state'] = 'disabled'
            self.a_entry['state'] = 'disabled'
            self.generate_button['state'] = 'disabled'

            self.connection = socket(AF_INET, SOCK_STREAM)
            self.connection.connect((self.server_address.get(), self.port.get()))

            self.disconnect_button['state'] = 'active'
            self.message_entry['state'] = 'normal'
            self.send_message_button['state'] = 'active'

            A = diffie_hellman.calculate_A(self.p.get(), self.g.get(), self.a.get())

            secret_key_package = DataPackage()
            secret_key_package.set_message_code(MessageCode.CREATE_SECRET_KEY)
            secret_key_package.set_int_array([self.p.get(), self.g.get(), A])
            secret_key_package.send(self.connection)

            self.connected = True
            self.clear_messages()
            Thread(target=self.process_messages).start()
        except OSError:
            showerror('Ошибка', 'Не удалось подключиться к серверу')
            self.disconnect()
        except diffie_hellman.DiffieHellmanError:
            showerror('Ошибка', 'Некорректные значение для Диффи-Хеллмана')
            self.disconnect()

    def disconnect(self):
        if self.connected:
            self.connected = False
            self.connection.close()

        self.address_entry['state'] = 'normal'
        self.port_entry['state'] = 'normal'
        self.name_entry['state'] = 'normal'
        self.connect_button['state'] = 'active'
        self.p_entry['state'] = 'normal'
        self.g_entry['state'] = 'normal'
        self.a_entry['state'] = 'normal'
        self.generate_button['state'] = 'active'

        self.disconnect_button['state'] = 'disabled'
        self.message_entry['state'] = 'disabled'
        self.send_message_button['state'] = 'disabled'

    def server_error(self):
        showwarning('Внимание', 'Ошибка сервера')
        self.disconnect()

    def generate_diffie_hellman(self):
        q, p = diffie_hellman.generate_q_and_p()
        self.p.set(p)
        self.g.set(diffie_hellman.generate_g(q, p))
        self.a.set(diffie_hellman.generate_a(10))

    def clear_messages(self):
        for message in self.messages_frame.winfo_children():
            message.destroy()

    def add_message(self, message: Message):
        row = self.messages_frame.grid_size()[1] + 1
        if message.client.name == self.name.get():
            side = 'e'
            text = f'"{message.text}" <= {message.client.name}'
        else:
            side = 'w'
            text = f'{message.client.name} => "{message.text}"'
        tk.Label(self.messages_frame, text=text, background=self.BACKGROUND_COLOR).grid(row=row, column=0, sticky=side)
        self.messages_canvas.yview_moveto('1.0')
        logging.info(message)

    def encryption_function(self, message: bytearray) -> bytearray:
        return bytearray(self.secret_key.encrypt(bytes(message), padding=True))

    def decryption_function(self, message: bytearray) -> bytearray:
        return bytearray(self.secret_key.decrypt(bytes(message), padding=True))

    def send_message(self):
        message = self.message.get()
        if len(message) == 0:
            showwarning('Ошибка', 'Введите сообщение')
            return
        package = DataPackage()
        package.set_message_code(MessageCode.SEND_MESSAGE)
        package.add_string(message)
        package.encrypt(self.encryption_function)
        package.send(self.connection)
        self.message.set('')

    def on_close(self):
        self.disconnect()
        self.destroy()


