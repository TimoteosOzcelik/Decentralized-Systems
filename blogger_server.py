import threading
from blogger import Client
import socket
import sys
import os
import uuid
from Crypto.PublicKey import RSA
from Crypto import Random


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
        self.check_in_list()
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

    def response(self):
        pass

    '''
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
