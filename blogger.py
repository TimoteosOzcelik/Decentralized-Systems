#!/usr/bin/env python3

import threading
import socket
import os
import uuid
from Crypto.PublicKey import RSA
from Crypto import Random
from PyQt5 import QtWidgets, QtCore
from UI.opening_screen_ui import Ui_OpeningScreen
from UI.homepage_ui import Ui_HomePage
from UI.new_microblog_ui import Ui_NewMicroblog
from Crypto.Hash import SHA256
import datetime, time
import queue

class Listen(threading.Thread):
    def __init__(self, my_uuid, host, port, public_key, private_key, key_dict, info_dict, new_blogs):
        threading.Thread.__init__(self)
        self.uuid = my_uuid
        self.socket = socket.socket()
        self.host = host
        self.port = int(port)
        self.public_key = public_key
        self.private_key = private_key
        self.new_blogs = new_blogs
        
        # KEYS AND INFO
        self.key_dict = key_dict
        self.info_dict = info_dict
    
    def run(self):
        # Socket Initialisation
        self.socket.bind((self.host, self.port))
        self.socket.listen(25)
        
        # Accept Connections
        while True:
            c, a = self.socket.accept()
            server = Server(self.uuid, self.host, self.port, c, self.public_key, self.private_key, self.key_dict,
                            self.info_dict, self.new_blogs)
            server.start()


class Server(threading.Thread):
    def __init__(self, server_uuid, rw_socket, server_public, server_private):
        threading.Thread.__init__(self)
        self.socket = connection
        self.uuid = str(my_uuid)
        self.host = host
        self.port = int(port)
        self.public_key = public_key
        self.private_key = private_key
        self.new_blogs = new_blogs
        
        # KEYS AND INFO
        self.key_dict = key_dict
        self.info_dict = info_dict
        
        # Peer Information to Authentication
        self.other_peer_uuid = None
        self.other_peer_public_key = None
        
        # Peer Old Connection Information
        self.is_logged = False
        self.is_blocked = False
        self.is_subscribed = False
        self.is_unsubscribed = False
        
        self.subscribed = False
        
        # To check, PUB passed
        self.is_public_key_shared = False
        self.blog_dict = {}
    
        # To fill blog_dict
        for file in os.listdir('./BLOGS'):
            
            # filename = './BLOGS/' + self.uuid + str(c) + '.txt'
            f = open('./BLOGS/' + file)
            blog = f.read()
            f.close()
            
            blogger_uuid = file[0:36]
                if blogger_uuid == self.uuid:
                    blogger_nickname = self.name
            else:
                blogger_nickname = self.info_dict[blogger_uuid][1]
                
                # TODO:
                # Take blog with its time, It's not correct always
                t = os.path.getmtime('./BLOGS/' + file)
                t = str(datetime.datetime.fromtimestamp(t))
                self.blog_dict[file[36:].split('.')[0]] = [blogger_uuid, blogger_nickname, blog, t]

    # Dict - Key: ID, Value: UUID, Who, Text, When

    def run(self):
        while True:
            if not self.is_subscribed:
                msg = self.rw_socket.recv(1024).decode()
                if msg == 'QUI':
                    break
                self.parser(msg)
            else:
                rec = self.rw_socket.recv(1024)
                msg = rec.decode()

                # SUBSCRIBE BUT NON-ENCRYPTED PROTOCOL MESSAGES
                if msg[0:3] == 'LSQ' or msg[0:3] == 'INF':
                    if msg == 'QUI':
                        break
                    self.parser(msg)
                # SUBSCRIBE AND ENCRYPTED PROTOCOL MESSAGES
                else:
                    msg = self.m_private.decrypt(rec).decode()
                    self.parser(msg)

    def parser(self, received):
        if self.is_blocked:
            self.rw_socket.send('BLK'.encode())

        if received[0:3] == 'INF':
            rest = received[3:].strip()
            spl = rest.split(';')
            if len(spl) == 5 and '' not in spl:
                c_uuid = spl[0]
                c_nickname = spl[1]
                c_host = spl[2]
                c_port = int(spl[3])

                client = Client(client_uuid=c_uuid, client_host=c_host, client_port=c_port)
                client.connect()
                check = client.check_identity()
                client.disconnect()

                if check is not 'ERR' and check == c_uuid:
                    if c_uuid not in index_dict.keys():
                        # NOT IN DICTIONARY -> ADD EXTENDED SPL
                        ext = ['', 'L', 'N', time.time(), 'Y']
                        spl = spl.extend(ext)
                        index_dict[c_uuid] = spl

                        # WRITING THE UPDATED DICTIONARY
                        index_file = open('Indexes/index_file.txt', 'w')
                        file_header = 'UUID,NICK,IP,PORT,IS_BLOGGER,CONNECTION_FROM,CONNECTION_TO,TIMESTAMP,IS_ACTIVE'
                        index_file.write(file_header)

                        for value in index_dict.values():
                            i = 0
                            for word in value:
                                index_file.write(word)
                                if i != 8:
                                    index_file.write(",")
                                i += 1
                            index_file.write("\n")
                        index_file.close()

                        # CHECK IS OK, RECORD UUID
                        self.client_uuid = c_uuid

                    else:
                        lst = index_dict[c_uuid]
                        # IF BLOCKED
                        if lst[5] == 'B':
                            self.is_blocked = True
                            self.rw_socket.send('BLK'.encode())
                            return

                        # IN DICTIONARY --> UPDATE
                        lst[1] = c_nickname
                        lst[2] = c_host
                        lst[3] = c_port
                        lst[7] = str(time.time())
                        lst[8] = 'A'

                        # IF ALREADY SUBSCRIBED
                        if lst[5] == 'S':
                            self.is_subscribed = True
                        # IF NOT LOGGED-IN
                        elif lst[5] == 'N':
                            lst[5] = 'L'
                        # UPDATE DICTIONARY
                        index_dict[c_uuid] = lst
                    # IF HERE, MEAN: NON-BLOCKED - LOGIN ACCEPTED
                    self.rw_socket.send('HEL'.encode())
                    self.is_logged = True
                    return
                self.rw_socket.send('REJ'.encode())
            return

        # RESPONSE - UUID CONTROL
        if received == 'WHO':
            self.rw_socket.send(('MID' + ' ' + str(self.m_uuid)).encode())
            return

        # IF NOT LOGIN - ERROR
        if not self.is_logged:
            self.rw_socket.send('ERL'.encode())
            return

        # LIST QUERY
        if received == 'LSQ':
            for k in index_dict.keys():
                spl = index_dict[k]
                snd = ''
                for i in spl[1:5]:
                    snd += str(i) + ';'
                snd = snd[:-1]
                self.rw_socket.send(snd.encode())
                time.sleep(0.25)
            self.rw_socket.send('END'.encode())
            return

        # DEMAND PUBLIC KEY
        elif received == 'PUB':
            lst = index_dict[self.client_uuid]
            host = lst[1]
            port = int(lst[2])

            client = Client(client_uuid=self.client_uuid, client_host=host, client_port=port)
            client.connect()
            pk = client.demand_public_key_reverse()
            if client.demand_signed_hash_reverse():
                self.client_public = pk
                # TODO: Add keys file
            client.disconnect()

            self.rw_socket.send('MPK '.encode() + self.m_public.exportKey())
            return

                # DEMANDED PUBLIC KEY
        elif received == 'RPB':
            self.rw_socket.send('MPK '.encode() + self.m_public.exportKey())
            return

        # DEMANDED SIGNED HASH
        elif received == 'RSM':
            hash = SHA256.new('abcdefgh'.encode()).digest()
            self.rw_socket.send('SYS '.encode() + str(self.m_private.sign(hash, '')[0]).encode())
            return

        # DEMAND SIGNED HASH
        elif received == 'SMS':
            hash = SHA256.new('abcdefgh'.encode()).digest()
            self.rw_socket.send('SYS '.encode() + str(self.m_private.sign(hash, '')[0]).encode())
            return

        # DEMAND MICROBLOG
        elif received[0:3] == 'DMB':
            n = int(received[3:].strip())
            # TODO: Pull microblogs and send
            self.rw_socket.send(self.client_public.encrypt('END'.encode(), 32)[0].encode())

        # RECEIVED MESSAGE
        elif received[0:3] == 'MSG':
            rest = received[3:].strip()
            # TODO: Store message
            self.rw_socket.send(self.client_public.encrypt('MOK'.encode(), 32)[0].encode())
        else:
            if self.is_subscribed:
                self.rw_socket.send(self.client_public.encrypt('ERR'.encode(), 32))
            else:
                self.rw_socket.send('ERR'.encode())


class Client(object):
    def __init__(self,  client_uuid, client_host, client_port, server_uuid=None, server_host=None, server_port=None, server_private=None):
        # Blogger
        self.is_blogger = 'Y'

        # Its server information to share
        self.m_uuid = server_uuid  # Request - For login protocol
        self.m_host = server_host  # Request - For login protocol
        self.m_port = server_port  # Request - For login protocol
        self.m_private = server_private  # Request & Response - For decryption

        # TODO: Get nickname from interface
        self.nickname = ''

        # Other side server information to connect & check
        self.y_host = client_host  # Response - To connect
        self.y_port = client_port  # Response - To connect
        self.y_uuid = client_uuid  # Response - To connect & check UUID
        self.y_public_key = ''  # Response - To check public_key

        # Socket
        self.sock = socket.socket()

        # False response count
        self.error = 0

    def __del__(self):
        pass

    def run(self):
        pass

    # Request & Response
    def connect(self):
        self.sock.connect((self.y_host, self.y_port))

    # Request & Response
    def disconnect(self):
        self.sock.close()
        self.__del__()

    # Request
    def login(self):
        req = 'INF'
        self.sock.send(
            (req + self.m_uuid + ';' + self.m_host + ';' + self.m_port + ';' + self.is_blogger
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
    def demand_signed_hash(self):
        req = 'SMS'
        self.sock.send(req.encode())
        resp = self.sock.recv(1024).decode()
        return self.parser(req, resp)

    # Request & Response
    def demand_public_key_reverse(self):
        req = 'RPB'
        self.sock.send(req.encode())
        resp = self.sock.recv(1024).decode()
        return self.parser(req, resp)

    # Request & Response
    def demand_signed_hash_reverse(self):
        req = 'RSM'
        self.sock.send(req.encode())
        resp = self.sock.recv(1024).decode()
        return self.parser(req, resp)
    # Request
    def subscribe(self):
        req = 'SUB'
        self.sock.send(self.y_public_key.encrypt(req.encode(), 32).encode())
        resp = self.sock.recv(1024).decode()
        self.parser(req, resp)

    # Request
    def unsubscribe(self):
        req = 'USB'
        self.sock.send(self.y_public_key.encrypt(req.encode(), 32).encode())
        resp = self.sock.recv(1024).decode()
        self.parser(req, resp)

    # Request
    def demand_microblog(self, microblog_quantity):
        # TODO: Microblog from interface
        req = 'DMB ' + str(microblog_quantity)
        self.sock.send(self.y_public_key.encrypt(req.encode(), 32).encode())
        resp = self.sock.recv(1024).decode()
        self.parser(req, resp)

    # Response
    def check_identity(self):
        req = 'WHO'
        self.sock.send(req.encode())
        resp = self.sock.recv(1024).decode()
        return self.parser(req, resp)

    # Request & Response
    # TODO: Timestamp necessary? IS_ACTIVE column can be used!
    def check_connection(self):
        req = 'TIC'
        self.sock.send(req.encode())
        resp = self.sock.recv(1024).decode()
        self.parser(req, resp)

    # Request
    def send_message(self, message):
        req = 'MSG ' + message
        self.sock.send(self.y_public_key.encrypt(req.encode(), 32).encode())
        resp = self.sock.recv(1024).decode()
        self.parser(req, resp)

    # Response
    def blocked(self):
        req = 'SBM'
        self.sock.send(req.encode())
        resp = self.sock.recv(1024).decode()
        self.parser(req, resp)
        # TODO: Block from list

    # Response
    def unblocked(self):
        req = 'SUM'
        self.sock.send(req.encode())
        resp = self.sock.recv(1024).decode()
        self.parser(req, resp)
        # TODO unblock from list

    def publish_microblog(self):
        # TODO: Add microblog file
        pass

    def remove_microblog(self):
        # TODO: Delete microblog file
        pass

    def quit(self):
        req = 'QUI'
        self.sock.send(req.encode())

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
                    self.y_public_key = rest
                    # TODO: Add keys file - IFNOT
                return self.y_public_key

        elif request == 'RPB':
            if received[0:3] == "MPK":
                rest = received[3:].strip()
                if not rest:
                    self.y_public_key = rest
                    # TODO: Add keys file - IFNOT
                return self.y_public_key

        elif request == 'RSM':
            if received[0:3] == "SYS":
                rest = received[3:].strip()
                spl = rest.split(';')
                if spl.__len__() == 2:
                    hash = spl[0]
                    signature = spl[1]
                    if self.y_public_key.verify(hash, signature):
                        # TODO: Add to dictionary & Update TYPE
                        return True
                    else:
                        return False
                else:
                    return 'ERK'

        elif request == 'SMS':
            if received[0:3] == "SYS":
                rest = received[3:].strip()
                spl = rest.split(';')
                if spl.__len__() == 2:
                    hash = spl[0]
                    signature = spl[1]
                    if self.y_public_key.verify(hash, signature):
                        # TODO: Add to keyss
                        return True
                    else:
                        return False
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
    port = 12346

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
    if os.path.isfile('Indexes/index_file'):
        index_file = open('Indexes/index_file', 'r')
        file_header = index_file.readline().strip('\n')
        data = index_file.readlines()

    # Copies available information to a dictionary
        for line in data:
            print(line)
            if line:
                words = line.rstrip('\n').split(",")
                index_dict[words[0]] = words
        index_file.close()
    else:
        file_header = 'UUID,NICK,IP,PORT,IS_BLOGGER,CONNECTION_FROM,CONNECTION_TO,TIMESTAMP,IS_ACTIVE'

    # TODO: Interface Implementation

    connection = Connection(blogger_uuid, get_ip(), port, blogger_private_key, blogger_public_key)
    connection.start()

    # (Over)Writes the information on dictionary to a file just before closing
    # open('Indexes/index_file', 'w').close()
    index_file = open('Indexes/index_file', 'w')
    index_file.write(file_header + '\n')

    for value in index_dict.values():
        i = 0
        for word in value:
            index_file.write(word)
            if i != 8:
                index_file.write(",")
            i+=1
        index_file.write("\n")
    index_file.close()


if __name__ == "__main__":
    main()
