import threading
import socket
import queue
import logging


class Connection(threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self)

    def run(self):
        pass


class Server(threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self)

    def run(self):
        pass


class Client(threading.Thread):
    def __init__(self, host, port, cs_info):
        threading.Thread.__init__(self)
        self.host = host
        self.port = port
        self.cs_info = cs_info
        self.sock = socket.socket()

    def run(self):
        self.connect()
        self.demand_public_key()

    def connect(self):
        self.sock.connect((self.host, self.port))

    def disconnect(self):
        self.sock.close()

    def check_identity(self):
        pass

    def check_connection(self):
        pass

    def demand_public_key(self):
        try:
            self.sock.send('PUB'.encode())
            resp = self.sock.recv(1024).decode()
            public_key = self.parser(resp)
            check = self.demand_signed_hash(public_key)
            if check:
                pass
            else:
                pass
        except:
            self.disconnect()

    def demand_signed_hash(self, public_key):
        try:
            self.sock.send('SMS'.encode())
            resp = self.sock.recv(1024).decode()
            check = self.parser(resp)
            return check
        except:
            self.disconnect()

    def send_message(self, message):
        try:
            self.sock.send(message.encode())
            resp = self.sock.recv(1024).decode()
            parsed = self.parser(resp)
        except:
            self.disconnect()

    def blocked(self):
        try:
            self.sock.send('SBM'.encode())
            resp = self.sock.recv(1024).decode()
            parsed = self.parser(resp)
        except:
            self.disconnect()

    def unblocked(self):
        try:
            self.sock.send('SUM'.encode())
            resp = self.sock.recv(1024).decode()
            parsed = self.parser(resp)
        except:
            self.disconnect()

    def parser(self, rec):
        return rec
