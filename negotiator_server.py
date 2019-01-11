import threading
import socket
import uuid
import queue
import time
import os
import sys
fihrist={}


class threadConnexion(threading.Thread):
    def __init__(self, uuid_, host, port, info_dict):
        threading.Thread.__init__(self)
        self.uuid = uuid_
        self.socket = socket.socket()
        self.host = host
        self.port = int(port)

        # INFO
        self.info_dict = info_dict

    def run(self):
        # Socket Initialisation
        self.socket.bind((self.host, self.port))
        self.socket.listen(25)

        # Accept Connections
        while True:
            c_soket, a = self.socket.accept()
            server = N_Server(self.uuid, self.host, self.port, c_soket, self.info_dict)
            server.start()


class N_Server(threading.Thread):
        def __init__(self, server_uuid, host, port, c_soket, info_dict):
            threading.Thread.__init__(self)
            self.server_uuid = server_uuid
            self.host = host
            self.port = port
            self.c_soket = c_soket
            self.info_dict = info_dict

            self.client_uuid = None

            self.is_logged = False

        def run(self):
            while True:
                msg = self.c_soket.recv(1024).decode()
                if self.parser(msg) == 'BYE':
                    break

        def parser(self, recu):
            info_file = './INFO.txt'
            file_header = 'UUID,NICK,IP,PORT,IS_BLOGGER,CONNECTION_FROM,CONNECTION_TO,TOKEN'

            #  FILE FOR KEY UPDATE
            if recu == 'QUI':
                self.c_soket.send('BYE'.encode())
                self.c_soket.close()
                return 'BYE'

            if recu[0:3] == 'INF':
                rest = recu[3:].split()
                spl = rest.split(';')

                if len(spl)==5 and '' not in spl:
                    ctrl_uuid = spl[0]
                    ctrl_nickname = spl[1]
                    ctrl_ip = spl[2]
                    ctrl_port = int(spl[3])
                    ctrl_type = spl[4]


                    client = Client(ctrl_uuid, ctrl_ip, ctrl_port, self.info_dict)
                    client.connect()
                    check = client.check_identity()
                    client.disconnect()


                    if check is not 'ERR' and check == ctrl_uuid:
                        #  TOKEN AND SEND MESSAGE
                        token = str(uuid.uuid4())
                        snd = 'HEL ' + token
                        self.c_soket.send(snd.encode())

                        add_to_dict = ['L', 'N', token]
                        spl.extend(add_to_dict)
                        self.info_dict[ctrl_uuid] = spl
                        write_on_info_file(info_file, file_header, self.info_dict)
                        return
                    self.c_soket.send('REJ'.encode())
                return

            elif recu[0:3] == 'LOG':
                rest = recu[3:].strip()
                spl = rest.split(';')

                if len(spl) == 5 and '' not in spl:
                    if spl[0] in self.info_dict.keys():

                        # BLOCKED BEFORE OR NOT
                        self.client_uuid = str(spl[0])

                        self.info_dict[self.client_uuid][1] = spl[1]
                        self.info_dict[self.client_uuid][2] = spl[2]
                        self.info_dict[self.client_uuid][3] = spl[3]

                        if self.info_dict[self.client_uuid][7] == spl[4]:
                            self.is_logged = True
                            write_on_info_file(info_file, file_header, self.info_dict)
                            snd = 'HEL ' + spl[4]
                            self.c_soket.send(snd.encode())
                            return
                self.c_soket.send('REJ'.encode())
                return

            if not self.is_logged:
                self.c_soket.send('ERL'.encode())
                return

            # LIST QUERY RECEIVED
            elif recu == 'LSQ':
                for key in self.info_dict.keys():
                    snd = ''
                    for s in self.info_dict[key][0:5]:
                        snd += str(s) + ';'
                    snd = snd[:-1]
                    snd = 'LSA ' + snd
                    self.c_soket.send(snd.encode())
                self.c_soket.send('END'.encode())
                return


def write_on_info_file(info_file, file_header, info_dict):
    index_file = open(info_file, 'w')
    index_file.write(file_header + '\n')

    for value in info_dict.values():
        i = 0
        for word in value:
            index_file.write(str(word))
            if i != 7:
                index_file.write(",")
            i += 1
        index_file.write("\n")
    index_file.close()


class Client(object):
    def __init__(self,uuid, ip, port, info_dict):
        self.uuid=uuid
        self.ip=ip
        self.port=port
        self.info_dict=info_dict
        self.s = socket.socket()
    def connect(self):
        self.s.connect((self.ip,self.port))
    def disconnect(self):
        self.s.send('QUI'.encode())
        if self.s.recv(1024).decode()=='BYE':
            self.s.close()
    def check_identity(self):
        self.s.send('WHO'.encode())
        cevap = self.s.recv(1024).decode()
        if cevap[:3] == 'MID':
            uuid_=cevap[3:].strip()
            if uuid_ :
                return uuid_
        return 'ERR'

def main():
    negotiator_port=12654
    negotiator_host='0.0.0.0' #burda 0.0.0.0 olması gerekiyor
    info_file='./INFO.txt'
    info_dict={}

    if os.path.isfile('uuid'):
        negotiator_uuid=str(uuid.UUID(open('uuid','r').read()))
    else:
        negotiator_uuid=str(uuid.uuid4())
        f=open('uuid','w')
        f.write(negotiator_uuid)
        f.close()
        # INFO FILE OPERATIONS
        try:
            index_file = open(info_file)
            file_header = index_file.readline().strip('\n')
            data = index_file.readlines()

            # Copies available information to a dictionary
            for line in data:
                print(line)
                if line:
                    words = line.rstrip('\n').split(",")
                    info_dict[words[0]] = words
            index_file.close()
        except:
            pass

        connection = threadConnexion(negotiator_uuid, negotiator_host, negotiator_port, info_dict)
        connection.start()

if __name__ == "__main__":
        main()
