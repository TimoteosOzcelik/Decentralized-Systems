import threading
import socket
import sys
import os
import uuid
from Crypto.PublicKey import RSA
from Crypto import Random
import queue
import logging

index_dict={}


class Connection(threading.Thread):
    def __init__(self, host, port):
        threading.Thread.__init__(self)

    def run(self):
        pass


class Server(threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self)

    def run(self):
        pass


class Client(threading.Thread):
    def __init__(self, server_uuid, server_host, server_port, server_private ,host, port, cs_info, type):
        threading.Thread.__init__(self)
        # Blogger
        self.is_blogger = 'Y'
        # Its server information to share
        self.server_uuid = server_uuid
        self.server_host = server_host
        self.server_port = server_port
        self.server_private = server_private
        # TODO: Get nickname from interface
        self.nickname = ''
        # Other side server information to connect & check
        self.host = host
        self.port = port
        self.public_key = ''
        # Client - Server Information Queue
        self.cs_info = cs_info
        # Socket
        self.sock = socket.socket()
        # False response count
        self.error = 0
        # Request or Connect
        self.type = type

    def run(self):
        self.connect()
        if self.type == 'Request':
            pass
        else:
            pass
        # self.demand_public_key()

    # Request & Response
    def connect(self):
        self.sock.connect((self.host, self.port))

    # Request & Response
    def disconnect(self):
        self.sock.close()
        sys.exit()

    # Request
    def login(self):
        req = 'INF'
        self.sock.send(
            (req + self.server_uuid + ';' + self.server_host + ';' + self.server_port + ';' + self.is_blogger
             + ';' + self.nickname).encode())
        resp = self.sock.recv(1024).decode()
        self.parser(req, resp)
        '''
        if resp == 'HEL':
            # TODO: Add to peer table as connected --> TO
            pass
        '''

    # Request
    def demand_peer_list(self):
        req = 'LSQ'
        self.sock.send(req.encode())
        resp = self.sock.recv(1024).decode()
        self.parser(req, resp)

    # Request & Response
    def demand_public_key(self):
        req = 'PUB'
        self.sock.send(req.encode())
        resp = self.sock.recv(1024).decode()
        self.parser(req, resp)

    # Request & Response
    def demand_signed_hash(self, public_key):
        req = 'SMS'
        self.sock.send(req.encode())
        resp = self.sock.recv(1024).decode()
        self.parser(req, resp)

    # Request
    def subscribe(self):
        req = 'SUB'
        self.sock.send(self.public_key.encrypt(req.encode(), 32).encode())
        resp = self.sock.recv(1024).decode()
        self.parser(req, resp)

    # Request
    def unsubscribe(self):
        req = 'USB'
        self.sock.send(self.public_key.encrypt(req.encode(), 32).encode())
        resp = self.sock.recv(1024).decode()
        self.parser(req, resp)

    # Request
    def demand_microblog(self):
        pass

    # Response
    def check_identity(self):
        pass

    # Request & Response
    def check_connection(self):
        req = 'TIC'
        self.sock.send(req.encode())
        resp = self.sock.recv(1024).decode()
        self.parser(req, resp)
        # TODO: Update timestamp

    # Request
    def send_message(self, message):
        pass

    # Response
    def blocked(self):
        pass

    # Response
    def unblocked(self):
        pass

    # Request & Response
    def parser(self, request, received):
        pass


def main():

    #Reads any existing information of network from file
    
    if(os.path.isfile('index_file.txt')):
        index_file = open('index_file.txt', 'r')
        data = index_file.readlines()

    #Copies available information to a dcitionary
        for line in data:
            words = line.rstrip("\n").split(",")
            index_dict[words[0]]=words
        index_file.close()

    else:
        print("No existing index file found")

    exists_pem = os.path.isfile('id_rsa.pem')
    exists_pub = os.path.isfile('id_rsa.pub')
    exists_uuid = os.path.isfile('uuid.pem')
    if exists_pem and exists_pub and exists_uuid:
        blogger_public_key = RSA.importKey(open('id_rsa.pem', 'rb').read())
        blogger_private_key = RSA.importKey(open('id_rsa.pub', 'rb').read())
        blogger_uuid = uuid.UUID(open('uuid.pem', 'r').read())
    else:
        random_generator = Random.new().read
        new_key = RSA.generate(2048, randfunc=random_generator)
        blogger_public_key = new_key.publickey()
        blogger_private_key = new_key
        blogger_uuid = uuid.uuid4()

        f = open('id_rsa.pem', 'w')
        f.write(blogger_private_key.exportKey().decode())
        f.close()

        f = open('id_rsa.pub', 'w')
        f.write(blogger_public_key.exportKey().decode())
        f.close()

        f = open('uuid.pem', 'w')
        f.write(blogger_uuid.__str__())
        f.close()

    #(Over)Writes the information on dictionary to a file just before closing
    index_file = open('index_file.txt', 'w')
    for value in index_dict.values():
        i=0
        for word in value:
            index_file.write(word)

            #No commas if last column
            if(i!=4):
                index_file.write(",")
            i=i+1
        index_file.write("\n")
    index_file.close()

    print(index_dict.values())

if __name__ == "__main__":
    main()