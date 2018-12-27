import threading
import socket
import uuid
import queue
import time
import os
import sys
fihrist={}



class threadConnexion(threading.Thread):

    def __init__(self,server_name,Lqueue):
        threading.Thread.__init__(self)
        self.server_name = server_name
        self.Lqueue = Lqueue
        self.server_socket=socket.socket()

    def run(self):
        self.server_socket.bind((self.server_host, self.server_port))
        self.server_socket.listen(5)

        while True:
            c_soket,adrr = self.server_socket.accept()
            server = N_Server(server_name=self.server_name,c_soket=c_soket,Lqueue=self.Lqueue)
            server.start()

class N_Server(threading.Thread):
        def __init__(self,server_name,Lqueue,c_soket):
            threading.Thread.__init__(self)
            self.server_name = server_name
            self.Lqueue= Lqueue
            self.c_soket=c_soket

            self.is_logged = False
            self.is_subscribed = False
            self.is_blocked = False

        def run(self):
            msg = self.c_soket.recv(1024).decode()
            ret = self.parser(msg)

        def parser(self,recu):
            if self.is_blocked:
                self.c_soket.send('BLK'.encode())

            if recu[0:3] == 'INF':
                rest = recu[3:].split()
                spl=rest.split(';')

                if len(spl)==5 and '' not in spl:
                    ctrl_uuid = spl[0]
                    ctrl_ip = spl[1]
                    ctrl_port = int(spl[2])
                    ctrl_type = spl[3]
                    ctrl_nickname = spl[4]

                    client = Client(client_uuid=ctrl_uuid,client_ip=ctrl_ip,client_port=ctrl_port,client_type=ctrl_port,client_nickname=ctrl_nickname)
                    client.connect()
                    check = client.check_identity()
                    client.disconnect()

                    if check is not 'ERR' and check == ctrl_uuid:

                        if ctrl_uuid not in fihrist.keys():
                            ext = ['', 'L', 'N', time.time(), 'Y']
                            spl = spl.extend(ext)
                            fihrist[ctrl_uuid] = spl
                            # Writing on the file
                            index_file = open('index_file.txt', 'w')
                            file_header = 'UUID,IP,PORT,TYPE,NICKNAME'
                            index_file.write(file_header)

                            for value in fihrist.values():
                                i = 0

                                for word in value:
                                    index_file.write(word)

                                    if i != 9:
                                        index_file.write(",")
                                    i += 1
                                index_file.write("\n")
                            index_file.close()
                            #
                            self.client_uuid = ctrl_uuid
                            self.c_soket.send('HEL'.encode())
                            self.is_logged = True


                    self.c_soket.send('REJ'.encode())

                return
            if not self.is_logged:
                self.c_soket.send('ERL'.encode())
                return

            if recu == 'LSQ':
                for k in fihrist.keys():
                    spl = fihrist[k]
                    snd = ''
                    for i in spl[1:5]:
                        snd += str(i) + ';'
                    snd = snd[:-1]
                    self.c_soket.send(snd.encode())
                self.c_soket.send('END'.encode())
                return
            else:
                self.soket.send("ERR\n").encode()
                return







class Client(threading.Thread):

    def check_identity(self):
        req = 'WHO'
        self.sock.send(req.encode())
        resp = self.sock.recv(1024).decode()
        return self.parser(req, resp)







def main():
    print('hello')

if __name__ == "__main__":
        main()
