import threading
import socket
import os
import uuid
from Crypto.PublicKey import RSA
from Crypto import Random
from Crypto.Hash import SHA256
import time
import queue
import logging

# Dictionary to store every information
# TODO - a public key column can be added
index_dict = {}


class Connection(threading.Thread):
    def __init__(self, server_uuid, server_host, server_port, server_public, server_private):
        threading.Thread.__init__(self)
        self.server_uuid = server_uuid
        self.server_socket = socket.socket()
        self.server_host = server_host
        self.server_port = server_port
        self.server_public = server_public
        self.server_private = server_private

    def run(self):
        self.server_socket.bind((self.server_host, self.server_port))
        self.server_socket.listen(5)
        while True:
            rw_socket, addr = self.server_socket.accept()
            server = Server(rw_socket=rw_socket, server_public=self.server_public, server_private=self.server_private)
            server.start()


class Server(threading.Thread):
    def __init__(self, server_uuid, rw_socket, server_public, server_private):
        threading.Thread.__init__(self)
        self.server_uuid = server_uuid
        self.rw_socket = rw_socket
        self.server_public = server_public # without exportKey
        self.server_private = server_private # without exportKey

        self.is_logged = False
        self.is_subscribed = False
        self.is_blocked = False
        # To encryption need to have client public key
        self.client_uuid = ''
        self.client_public = ''

    def run(self):
        while True:
            if not self.is_subscribed:
                msg = self.rw_socket.recv(1024).decode()
                ret = self.parser(msg)
            else:
                msg = self.server_private.decrypt(self.rw_socket.recv(1024).decode())
                ret = self.parser(msg)

    def parser(self, received):
        if self.is_blocked:
            self.rw_socket.send('BLK'.encode())

        if received[0:3] == 'INF':
            rest = received[3:].strip()
            spl = rest.split(';')
            if len(spl) == 5 and '' not in spl:
                ctrl_uuid = spl[0]
                ctrl_host = spl[2]
                ctrl_port = spl[3]

                client = Client(client_uuid=ctrl_uuid, client_host=ctrl_host, client_port=ctrl_port)
                client.connect()
                check = client.check_identity()
                client.disconnect()

                if check is not 'ERR' and check == ctrl_uuid:
                    if ctrl_uuid not in index_dict.keys():
                        ext = ['', 'L', 'N', time.time(), 'Y']
                        spl = spl.extend(ext)
                        index_dict[ctrl_uuid] = spl
                        # TODO: ADD TO TABLE
                        self.client_uuid = ctrl_uuid
                        self.rw_socket.send('HEL'.encode())
                        self.is_logged = True
                self.rw_socket.send('REJ'.encode())
            return

        if received == 'WHO':
            self.rw_socket.send(('MID' + ' ' + str(self.server_uuid)).encode())
            return

        if not self.is_logged:
            self.rw_socket.send('ERL'.encode())
            return

        if received == 'LSQ':
            for k in index_dict.keys():
                spl = index_dict[k]
                snd = ''
                for i in spl[1:5]:
                    snd += str(i) + ';'
                snd = snd[:-1]
                self.rw_socket.send(snd.encode())
            self.rw_socket.send('END'.encode())
            return

        # PUBLIC & PRIVATE KEY
        elif received == 'PUB':
            ''' Client public key 
            client = Client(client_uuid=ctrl_uuid, client_host=ctrl_host, client_port=ctrl_port)
            client.connect()
            check = client.demand_public_key()
            client.disconnect()
            '''
            self.rw_socket.send('MPK '.encode() + self.server_public.exportKey())
            return

        elif received == 'SMS':
            hash = SHA256.new('abcdefgh'.encode()).digest()
            self.rw_socket.send('SYS '.encode() + str(self.server_private.sign(hash, '')[0]).encode())
            return
            # return 'SYS' + ' ' + hash + ';' + self.server_private.sign(hash, '')[0]

        # TODO
        elif received == 'DMB':
            for k in index_dict.keys():
                spl = index_dict[k]
                snd = ''
                for i in spl[1:5]:
                    snd += str(i) + ';'
                snd = snd[:-1]
                self.rw_socket.send(self.client_public.encrypt(snd.encode(), 32)[0].encode())
            self.rw_socket.send(self.client_public.encrypt('END'.encode(), 32)[0].encode())

        elif received[0:3] == 'MSG':
            rest = received[3:].strip()
            # TODO: Store message
            self.rw_socket.send(self.client_public.encrypt('MOK'.encode(), 32)[0].encode())
        else:
            if self.is_subscribed:
                self.rw_socket.send(self.client_public.encrypt('ERR'.encode(), 32))
            else:
                self.rw_socket.send('ERR'.encode())

class Client(threading.Thread):
    def __init__(self,  client_uuid, client_host, client_port, server_uuid=None, server_host=None, server_port=None, server_private=None):
        threading.Thread.__init__(self)
        # Blogger
        self.is_blogger = 'Y'
        # Its server information to share
        self.server_uuid = server_uuid  # Request - For login protocol
        self.server_host = server_host  # Request - For login protocol
        self.server_port = server_port  # Request - For login protocol
        self.server_private = server_private  # Request & Response - For decryption
        # TODO: Get nickname from interface
        self.nickname = ''
        # Other side server information to connect & check
        self.client_host = client_host  # Response - To connect
        self.client_port = client_port  # Response - To connect
        self.client_uuid = client_uuid  # Response - To connect & check UUID
        self.public_key = ''  # Response - To check public_key
        # Client - Server Information Queue - Probably not necessary
        # self.cs_info = cs_info
        # Socket
        self.sock = socket.socket()
        # False response count
        self.error = 0
        # Request or Connect - Probably not necessary
        # self.type = type

    def __del__(self):
        pass

    def run(self):
        pass

    # Request & Response
    def connect(self):
        self.sock.connect((self.client_host, self.client_port))

    # Request & Response
    def disconnect(self):
        self.sock.close()
        self.__del__()

    # Request
    def login(self):
        req = 'INF'
        self.sock.send(
            (req + self.server_uuid + ';' + self.server_host + ';' + self.server_port + ';' + self.is_blogger
             + ';' + self.nickname).encode())
        resp = self.sock.recv(1024).decode()
        self.parser(req, resp)

    # Request
    def demand_peer_list(self):
        req = 'LSQ'
        self.sock.send(req.encode())
        while True:
            resp = self.sock.recv(1024).decode()
            if resp == 'END':
                break
            self.parser(req, resp)

    # Request & Response
    def demand_public_key(self):
        req = 'PUB'
        self.sock.send(req.encode())
        resp = self.sock.recv(1024).decode()
        return self.parser(req, resp)

    # Request & Response
    def demand_signed_hash(self, public_key):
        req = 'SMS'
        self.sock.send(req.encode())
        resp = self.sock.recv(1024).decode()
        return self.parser(req, resp)

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
    def demand_microblog(self, microblog_quantity):
        # TODO Microblog integer or string??
        req = 'DMB' + ' ' + str(microblog_quantity)
        self.sock.send(self.public_key.encrypt(req.encode(), 32).encode())
        resp = self.sock.recv(1024).decode()
        self.parser(req, resp)

    # Response
    def check_identity(self):
        req = 'WHO'
        self.sock.send(req.encode())
        resp = self.sock.recv(1024).decode()
        return self.parser(req, resp)

    # Request & Response
    def check_connection(self):
        req = 'TIC'
        self.sock.send(req.encode())
        resp = self.sock.recv(1024).decode()
        self.parser(req, resp)
        # TODO: Update timestamp
        # TODO Maybe Add Timeout for no response
        # If no response may break entire communication?

    # Request
    def send_message(self, message):
        req = 'MSG'+" "+message
        self.sock.send(self.public_key.encrypt(req.encode(), 32).encode())
        resp = self.sock.recv(1024).decode()
        self.parser(req, resp)

    # Response
    def blocked(self):
        req = 'SBM'
        self.sock.send(req.encode())
        resp = self.sock.recv(1024).decode()
        self.parser(req, resp)
        # TODO block from list

    # Response
    def unblocked(self):
        req = 'SUM'
        self.sock.send(req.encode())
        resp = self.sock.recv(1024).decode()
        self.parser(req, resp)
        # TODO unblock from list

    # Request & Response
    def parser(self, request, received):
        if received == 'BLK':
            # TODO: Show rejected
            return False
        elif received == 'ERL':
            # TODO: Show not login
            return False
        elif received == 'ERS' or 'ERK':
            # TODO: Show not subscribed
            return False

        if request[0:3] == 'INF':
            if received == 'HEL':
                # TODO: Add to peer table as connected --> TO
                return
            elif received == 'REJ':
                # TODO: Show rejected
                return

        elif request == "WHO":
            if received[0:3] == "MID":
                rest = received[3:].strip()
                if not rest:
                    return rest
            return 'ERR'

        elif request == "LSQ":
            if received[0:3] == "LSA":
                rest = received[3:].strip()

                # TODO: Show in interface - Update the list

        elif request == 'PUB':
            if received[0:3] == "MPK":
                rest = received[3:].strip()
                if not rest:
                    self.public_key = rest

        elif request == 'SMS':
            if received[0:3] == "SYS":
                rest = received[3:].strip()
                spl = rest.split(';')
                if spl.__len__() == 2:
                    hash = spl[0]
                    signature = spl[1]
                    if self.public_key.verify(hash, signature):
                        # TODO: Add to dictionary & Update TYPE
                        pass
                    else:
                        pass
                else:
                    return 'ERK'

        elif request == 'SUB':
            if received == 'SOK':
                # TODO: Update in dictionary & Changes in interface
                pass
        elif request == 'USB':
            if received == 'UOK':
                # TODO: Update in dictionary & Changes in interface
                pass

        elif request[0:3] == "DMB":
            if received[0:3]=="MBM":
                rest = received[3:].strip()
                # TODO: Save as txt files with Nickname & UUID & Show in interface

        elif request == "MSG":
            if received == "MOK":
                # TODO: Show "Message Sent" in Interface
                pass
            else:
                # TODO: Show "Message did not reach to its destination" in Interface
                pass

        elif request == 'TIC':
            if received == 'TOK':
                # TODO: Update timestamp
                self.error = 0
            else:
                self.error += 1
                if self.error == 3:
                    # TODO: Set is_active 'N'
                    pass



def get_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('10.255.255.255', 1))
        ip = s.getsockname()[0]
    except:
        ip = '127.0.0.1'
    finally:
        s.close()
    return ip


def main():
    port = 12345
    exists_pem = os.path.isfile('id_rsa.pem')
    exists_pub = os.path.isfile('id_rsa.pub')
    exists_uuid = os.path.isfile('uuid.pem')
    if exists_pem and exists_pub and exists_uuid:
        blogger_public_key = RSA.importKey(open('id_rsa.pem', 'rb').read())
        blogger_private_key = RSA.importKey(open('id_rsa.pub', 'rb').read())
        blogger_uuid = uuid.UUID(open('uuid', 'r').read())
    else:
        random_generator = Random.new().read
        new_key = RSA.generate(2048, randfunc=random_generator)
        blogger_public_key = new_key.publickey()
        blogger_private_key = new_key
        blogger_uuid = str(uuid.uuid4())

        f = open('id_rsa', 'w')
        f.write(blogger_private_key.exportKey('PEM').decode())
        f.close()

        f = open('id_rsa.pub', 'w')
        f.write(blogger_public_key.exportKey('PEM').decode())
        f.close()

        f = open('uuid', 'w')
        f.write(blogger_uuid)
        f.close()

    # Reads any existing information of network from file
    if os.path.isfile('index_file.txt'):
        index_file = open('index_file.txt', 'r')
        file_header = index_file.readline()
        data = index_file.readlines()

    # Copies available information to a dictionary
        for line in data:
            words = line.rstrip().split(",")
            index_dict[words[0]] = words[1:]
        index_file.close()
    else:
        file_header = 'UUID,NICK,IP,PORT,IS_BLOGGER,PUBLIC_KEY,CONNECTION_FROM,CONNECTION_TO,TIMESTAMP,IS_ACTIVE'

    # TODO: Interface Implementation

    connection = Connection(blogger_uuid, get_ip(), port, blogger_private_key, blogger_public_key)
    connection.start()

    # (Over)Writes the information on dictionary to a file just before closing
    index_file = open('index_file.txt', 'w')
    index_file.write(file_header)

    for value in index_dict.values():
        i = 0
        for word in value:
            index_file.write(word)
            if i != 9:
                index_file.write(",")
            i+=1
        index_file.write("\n")
    index_file.close()


if __name__ == "__main__":
    main()
