import threading
import socket
import sys
import os
import uuid
from Crypto.PublicKey import RSA
from Crypto import Random
import queue
import logging

#Dictionary to store every information
# TODO - a public key column can be added
index_dict={}

class Connection(threading.Thread):
    def __init__(self, host, port):
        threading.Thread.__init__(self)

    def run(self):
        pass


class Server(threading.Thread):
    def __init__(self, rw_socket, server_public, server_private):
        threading.Thread.__init__(self)
        self.rw_socket = rw_socket
        self.server_public_key = server_public
        self.server_private = server_private

        self.is_login = False
        self.is_subscribed = False
        self.is_block = False

    def run(self):
        while True:
            msg = self.rw_socket.recv(1024).decode()
            ret = self.parser(msg)
            self.rw_socket.send(ret.encode())

    def check_in_list(self):
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
                check = client.check_identity()
                # TODO: IF check is OK add to table or do nothing
                return check

            else:
                return 'REJ'


    def response(self):
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
        self.parser(req, resp)

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

# Prints can be deleted
    # Request & Response
    def parser(self, request, received):
        req=self.request
        resp=self.received
        if(req=="LSQ"):
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
        if(req=="WHO"):
            if(rep[0:3]=="MID"):
                print (s)
                # TODO if s in index_dict:
                #       print ("Verified Connection")
            else:
                print ("Could not verify connection") 
        if(req=="MSG"):
            if(rep=="MOK"):
                print ("Message Sent")
            else:
                print ("Message did not reach to its destination")

def main():

    #Reads any existing information of network from file 
    if(os.path.isfile('index_file.txt')):
        index_file = open('index_file.txt', 'r')
        file_header=index_file.readline()
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
    index_file.write(file_header)
    for value in index_dict.values():
        i=0
        for word in value:
            index_file.write(word)

            #No commas if last column
            if(i!=6):
                index_file.write(",")
            i=i+1
        index_file.write("\n")
    index_file.close()

    print(file_header)


if __name__ == "__main__":
    main()
