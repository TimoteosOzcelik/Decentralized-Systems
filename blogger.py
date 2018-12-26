import threading
import socket
import sys
import os
import uuid
from Crypto.PublicKey import RSA
from Crypto import Random
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
    def __init__(self, rw_socket, server_public, server_private):
        threading.Thread.__init__(self)
        self.rw_socket = rw_socket
        self.server_public = server_public
        self.server_private = server_private

        self.is_login = False
        self.is_subscribed = False
        self.is_block = False

    def run(self):
        while True:
            if not self.is_subscribed:
                msg = self.rw_socket.recv(1024).decode()
                ret = self.parser(msg)
                self.rw_socket.send(ret.encode())
            else:
                pass

    def parser(self, received):
        if received[0:3] == 'INF':
            rest = received[3:].strip()
            spl = rest.split(';')
            if len(spl) == 5 and '' not in spl:
                ctrl_uuid = spl[0]
                ctrl_host = spl[1]
                ctrl_port = spl[2]
                ctrl_is_blogger = spl[3]
                nick = spl[4]
                client = Client(client_host=ctrl_host, client_port=ctrl_port, client_uuid=ctrl_uuid, server_private=self.server_private)
                client.connect()
                check = client.check_identity()
                client.disconnect()
                if check is not 'ERR' and str(check) == str(ctrl_uuid):
                    # TODO: IF check is OK add to table or do nothing
                    return 'HEL'
                elif self.is_block:
                    return 'BLK'
                else:
                    return 'REJ'
            else:
                return 'REJ'
        elif received == 'LSQ':
            if not self.is_login:
                return 'ERL'
            elif self.is_block:
                return 'BLK'
            else:
                # TODO: Return the list
                pass


class Client(threading.Thread):
    def __init__(self, client_host, client_port, client_uuid, server_private, server_uuid=None, server_host=None, server_port=None):
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
        self.client_host = client_host
        self.client_port = client_port
        self.client_uuid = client_uuid
        self.public_key = ''
        # Client - Server Information Queue - Probably not necessary
        # self.cs_info = cs_info
        # Socket
        self.sock = socket.socket()
        # False response count
        self.error = 0
        # Request or Connect - Probably not necessary
        # self.type = type

    def run(self):
        self.connect()
        # self.demand_public_key()

    # Request & Response
    def connect(self):
        self.sock.connect((self.client_host, self.client_port))

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
    def demand_microblog(self, microblog_quantity):
        # TODO Microblog integer or string??
        req = 'DMB'+" "+microblog_quantity
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
        if request == "WHO":
            if received[0:3] == "MID":
                rest = received[3:].strip()
                if not rest:
                    return rest
                else:
                    return 'ERR'
            else:
                return 'ERR'
        elif request == 'PUB':
            if received[0:3]=="MPK":
                rest = received[3:].strip()
                if not rest:
                    self.public_key = rest
                else:
                    return 'ERK'
            else:
                return 'ERR'
        elif request == 'SMS':
            if received[0:3]=="SYS":
                rest = received[3:].strip()
                spl = rest.split(';')
                if spl.__len__() == 2:
                    signature = spl[0]
                    hash = spl[1]
                    self.public_key.verify(hash, signature)
                    # TODO: Add to dictionary & Update TYPE
                else:
                    return 'ERK'
        '''
        if(req=="SUB"):
        else:
            return 'ERR'

        if(request=="LSQ"):
            if(rep[0:3]=="LSA"):
                s=rep[5:]
                print (s)
            else:
                s=rep["Not logged in"]
                print (s)
        if(req=="PUB"):
            if(rep[0:3]=="MPK"):
                # TODO Add Host Public Key To Dictionary
                print ("Key got.")
            else:
                print ("Problem Acquiring Key")
        if(req=="SMS"):
            if(rep[0:3]=="SYS"):
                # TODO Check Hash
                print ("Sign Checked.")
            else:
                print ("Problem with signed Key")
        if(req=="SUB"):
            if(rep=="SOK"):
                print ("Subscribed")
            else:
                print ("Could not subscribe.")
        if(req=="USB"):
            if(rep[3]=="SOK"):
                print ("Unsubscribed")
            else:
                print ("Could not unsubscribe.")
        if(req[0:3]=="DMB"):
            if(rep[0:3]=="MBM"):
                s=rep[5:]
                print (s)
            else:
                print ("Could not show microblogs.")
        if(req=="SBM"):
            if(rep[0:3]=="BOK"):
                print ("Succesfully blocked")
            else:
                print ("Could not tell blocked.")
        if(req=="SUM"):
            if(rep=="UOK"):
                print ("Succesfully unblocked")
            else:
                print ("Could not tell unblocked.")    
        if(req=="TIC"):
            if(rep=="TOC"):
                print ("Still Connected")
            else:
                print ("Not Connected")
        if(req=="MSG"):
            if(rep=="MOK"):
                print ("Message Sent")
            else:
                print ("Message did not reach to its destination")
        '''


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

    # Reads any existing information of network from file
    if os.path.isfile('index_file.txt'):
        index_file = open('index_file.txt', 'r')
        file_header = index_file.readline()
        data = index_file.readlines()

    # Copies available information to a dcitionary
        for line in data:
            words = line.rstrip().split(",")
            index_dict[words[0]] = words
        index_file.close()
    else:
        file_header = 'UUID,NICK,IP,PORT,IS_BLOGGER,PUBLIC_KEY,TYPE,TIMESTAMP,IS_ACTIVE'

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
            # No commas if last column
            if i != 8:
                index_file.write(",")
            i+=1
        index_file.write("\n")
    index_file.close()


if __name__ == "__main__":
    main()
