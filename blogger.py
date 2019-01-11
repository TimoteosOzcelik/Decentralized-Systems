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
    def __init__(self, my_uuid, host, port, connection, public_key, private_key, key_dict, info_dict, new_blogs):
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
            if self.is_public_key_shared:
                received = self.socket.recv(2048)

                # If public_key shared before but not sent encrypted message
                try:
                    non_encrypted = received
                    protocol = non_encrypted[0:3].decode()
                    message = non_encrypted[3:]

                    # Public key shared but not encrypted message
                    if protocol in ['LSQ', 'SBM', 'SUM', 'QUI']:
                        if self.parser(protocol, message) == 'BYE':
                            break
                except:
                    print('Received', received)
                    r = (received, )
                    decrypted = self.private_key.decrypt(r).decode()
                    print(decrypted)
                    protocol = decrypted[0:3]
                    message = decrypted[3:]
                    self.parser(protocol, message)
            else:
                # Receive before public key shared
                received = self.socket.recv(2048)
                protocol = received[0:3].decode()
                message = received[3:]

                # SEND IN PARSER
                if self.parser(protocol, message) == 'BYE':
                    break

    def parser(self, protocol, message):
        print('Protocol:', protocol)

        if protocol == 'QUI' and not message.decode():
            print('Protokol, QUI', protocol)
            self.socket.send('BYE'.encode())
            self.socket.close()
            return 'BYE'

        info_file = './INFO.txt'
        file_header = 'UUID,NICK,IP,PORT,IS_BLOGGER,CONNECTION_FROM,CONNECTION_TO,TOKEN'

        # INF UUID;NICK;IP;PORT;IS_BLOGGER
        if protocol == 'WHO' and not message.decode():
            print('Protokol, WHO', protocol)
            snd = 'MID ' + self.uuid
            self.socket.send(snd.encode())
            return True

        elif protocol == 'INF':
            messages = message.decode().strip().split(';')

            if len(messages) == 5 and '' not in messages:
                is_in_dict = messages[0] in self.info_dict.keys()

                # Blocked before or not
                if is_in_dict:
                    if self.info_dict[messages[0]][5] == 'B':
                        self.is_blocked = True
                        self.socket.send('BLK'.encode())
                        return

                other_peer_uuid = messages[0]
                nickname = messages[1]
                host2connect = messages[2]
                port2connect = int(messages[3])

                # TODO: Control client first parameter
                # Client2Check Identity

                client = Client(self.uuid, host2connect, port2connect, self.key_dict, self.info_dict)
                client.connect()
                uuid_taken = client.check_identity()
                client.disconnect()

                # UUID CONTROL
                if other_peer_uuid != 'ERR' and other_peer_uuid == uuid_taken:
                    self.other_peer_uuid = uuid_taken

                    if is_in_dict:
                        # Update nickname, ip and port
                        self.info_dict[other_peer_uuid][1] = nickname
                        self.info_dict[other_peer_uuid][2] = host2connect
                        self.info_dict[other_peer_uuid][3] = port2connect

                        # Not logged-in before
                        if self.info_dict[other_peer_uuid][5] == 'N':
                            self.info_dict[other_peer_uuid][5] = 'L'

                        # Inf Protocol means not interaction before
                        token = str(uuid.uuid4())
                        self.info_dict[other_peer_uuid][7] = token

                    # Peer see me in its list, but it's not recorded before in my list
                    else:
                        # Token Creation
                        token = str(uuid.uuid4())

                        # Add to dictionary and write on the file
                        add_to_dict = ['L', 'N', token]
                        messages.extend(add_to_dict)

                        self.info_dict[uuid_taken] = messages

                    msg2send = 'HEL ' + token
                    self.socket.send(msg2send.encode())
                    write_on_info_file(info_file, file_header, self.info_dict)

                    return 'HEL'

                self.socket.send('REJ'.encode())
                return 'REJ'

        # INTERACTION BEFORE, LOGIN P2P
        elif protocol == 'LOG':
            messages = message.decode().strip().split(';')

            if len(messages) == 5 and '' not in messages:
                if messages[0] in self.info_dict.keys():

                    # BLOCKED BEFORE OR NOT
                    self.other_peer_uuid = str(messages[0])
                    self.info_dict[self.other_peer_uuid][1] = messages[1]
                    self.info_dict[self.other_peer_uuid][2] = messages[2]
                    self.info_dict[self.other_peer_uuid][3] = messages[3]

                    if self.info_dict[self.other_peer_uuid][5] == 'B':
                        self.is_blocked = True

                    if self.info_dict[self.other_peer_uuid][7] == messages[4]:
                        # Not logged before or blocked & unblocked
                        if self.info_dict[self.other_peer_uuid][5] == 'N':
                            self.info_dict[self.other_peer_uuid][5] = 'L'
                            self.is_logged = True

                        # Already logged before
                        elif self.info_dict[self.other_peer_uuid][5] == 'L':
                            self.is_logged = True

                        # Already subscribed before
                        elif self.info_dict[self.other_peer_uuid][5] == 'S':
                            self.is_logged = True
                            self.is_subscribed = True

                        # Already subscribed & unsubscribed me
                        elif self.info_dict[self.other_peer_uuid][5] == 'U':
                            self.is_logged = True
                            self.is_unsubscribed = True

                        if self.info_dict[self.other_peer_uuid][6] == 'S':
                            self.subscribed = True

                        if os.path.exists('./KEYS/' + self.other_peer_uuid + '.pub'):
                            self.other_peer_public_key = self.key_dict[self.other_peer_uuid]
                            self.is_public_key_shared = True

                        write_on_info_file(info_file, file_header, self.info_dict)
                        snd = 'HEL ' + messages[4]
                        self.socket.send(snd.encode())
                        return 'HEL'
            self.socket.send('REJ'.encode())
            return 'REJ'

        if self.subscribed and protocol == 'BLG':
            messages = message.strip().split(';')
            blog = messages[0]
            timestamp = messages[1]
            c = 0
            for k in self.blog_dict.keys():
                if self.blog_dict[k][0] == self.other_peer_uuid:
                    c += 1

            filename = './BLOGS/' + self.uuid + str(c) + '.txt'
            f = open(filename, 'w')

            f.write(blog)
            f.close()

            self.new_blogs.put(self.other_peer_uuid + ';' + blog)
            self.socket.send(self.other_peer_public_key.encrypt('TKN'.encode(), 1024)[0])
            return 'BLG'

        elif protocol == 'SBM':
            self.info_dict[self.other_peer_uuid][6] = 'B'
            write_on_info_file(info_file, file_header, self.info_dict)
            self.socket.send('BOK'.encode())
            return 'SBM'

        elif protocol == 'SUM':
            self.info_dict[self.other_peer_uuid][6] = 'N'
            write_on_info_file(info_file, file_header, self.info_dict)
            self.socket.send('ROK'.encode())
            return 'SUM'

        elif self.is_blocked:
            self.socket.send('BLK'.encode())
            return 'BLK'

        elif not self.is_logged:
            self.socket.send('ERL'.encode())
            return 'ERL'

        # List query received
        elif protocol == 'LSQ' and not message.decode():
            for key in self.info_dict.keys():
                snd2message = ''

                for s in self.info_dict[key][0:5]:
                    snd2message += str(s) + ';'

                snd2message = snd2message[:-1]

                snd2message = 'LSA ' + snd2message

                self.socket.send(snd2message.encode())
                time.sleep(0.5)
            # To say list is ended
            self.socket.send('END'.encode())
            return 'END'

        elif protocol == 'PUB':
            self.other_peer_public_key = RSA.importKey(message[1:])
            self.socket.send('PUB '.encode() + self.public_key.exportKey())
            return 'PUB'

        elif protocol == 'SMS':
            text = 'Hello'
            hash_text = SHA256.new(text.encode()).digest()
            self.socket.send('SMS '.encode() + str(self.private_key.sign(hash_text, '')[0]).encode() + ';'.encode() + text.encode())

            msg_split = message.decode().strip().split(';')
            print(msg_split)

            # TUPLE SIGNATURE
            signature = int(msg_split[0])
            signature = (signature, '')

            text = msg_split[1]
            hash_text = SHA256.new(text.encode()).digest()

            try:
                if not self.other_peer_public_key.verify(hash_text, signature):
                    self.other_peer_public_key = None
            except:
                pass

            return 'SMS'

        elif protocol == 'POK' and not message.decode():
            if self.other_peer_public_key is not None:
                self.socket.send('POK'.encode())

                # Public key add to dictionary
                self.key_dict[self.other_peer_uuid] = self.other_peer_public_key

                # Record public key to file
                filename = './KEYS/' + self.other_peer_uuid + '.pub'
                f = open(filename, 'w')
                f.write(self.other_peer_public_key.exportKey('PEM').decode())
                f.close()

                self.is_public_key_shared = True

                # self.info_dict[self.other_peer_uuid][5] = 'S'
                # write_on_info_file(info_file, file_header, self.info_dict)

                return 'POK'
            else:
                self.socket.send('PER'.encode())
                print('POK - PER')
                return 'PER'

        elif protocol == 'PER':
            print('PER')
            self.other_peer_public_key = None
            self.socket.send('PER'.encode())
            return 'PER'

        elif protocol == 'SUB' and not message:
            self.info_dict[self.other_peer_uuid][5] = 'S'
            write_on_info_file(info_file, file_header, self.info_dict)
            print(self.other_peer_public_key)
            self.socket.send(self.other_peer_public_key.encrypt('SOK'.encode(), 1024)[0])
            return 'SUB'

        elif protocol == 'USB' and not message:
            self.info_dict[self.other_peer_uuid][5] = 'U'
            write_on_info_file(info_file, file_header, self.info_dict)
            self.socket.send(self.other_peer_public_key.encrypt('UOK'.encode(), 1024)[0])
            return 'USB'

        self.socket.send('ERR'.encode())
        return 'ERR'


class Client(object):
    def __init__(self, my_uuid, host2connect, port2connect,  key_dict=None, info_dict=None, public_key=None, private_key=None,
                 nickname=None, host=None, port=None, other_peer_uuid=None):
        # Blogger
        self.is_blogger = 'Y'
        self.socket = socket.socket()

        # My Peer Information
        self.uuid = my_uuid
        self.host = host

        try:
            self.port = int(port)
        except:
            self.port = None

        # KEYS AND INFO
        self.key_dict = key_dict
        self.info_dict = info_dict

        self.nickname = nickname
        self.public_key = public_key
        self.private_key = private_key

        # TO CONNECT
        self.host2connect = str(host2connect)
        self.port2connect = int(port2connect)

        # Other Peer Information to Authentication
        self.other_peer_uuid = other_peer_uuid
        self.other_peer_public_key = None

    # Request & Response
    def connect(self):
        self.socket.connect((self.host2connect, self.port2connect))

    # Request & Response
    def disconnect(self):
        request = 'QUI'
        self.socket.send(request.encode())
        received = self.socket.recv(2048).decode()
        if received == 'BYE':
            self.socket.close()

    # Request
    def login(self):
        token = self.info_dict[self.other_peer_uuid][7]
        if token:
            request = 'LOG'
            self.socket.send((request + ' ' + self.uuid + ';' + self.nickname + ';' + self.host + ';' + str(self.port) + ';' + token).encode())
        else:
            request = 'INF'
            self.socket.send((request + ' ' + self.uuid + ';' + self.nickname + ';' + self.host + ';' + str(self.port) + ';' + self.is_blogger).encode())

        received = self.socket.recv(2048).decode()
        return self.parser(request, received)

    # Response
    def check_identity(self):
        request = 'WHO'
        self.socket.send(request.encode())
        received = self.socket.recv(2048).decode()
        return self.parser(request, received)

    # Request
    def demand_peer_list(self):
        request = 'LSA'
        self.socket.send(request.encode())
        received = self.socket.recv(2048).decode()
        return self.parser(request, received)

    # Request
    def share_public_key(self):
        request = 'PUB'
        self.socket.send('PUB '.encode() + self.public_key.exportKey())
        print(self.public_key.exportKey())
        print('PUB '.encode() + self.public_key.exportKey())
        received = self.socket.recv(2048)
        self.parser(request, received)

    # Request
    def signed_hash_check(self):
        request = 'SMS'
        text = 'Hello'
        hash_text = SHA256.new(text.encode()).digest()
        self.socket.send('SMS '.encode() + str(self.private_key.sign(hash_text, '')[0]).encode() + ';'.encode() + text.encode())
        received = self.socket.recv(2048).decode()
        self.parser(request, received)

    # Request
    def send_key_sharing_information(self):
        if self.other_peer_public_key is not None:
            print('Client - POK')
            request = 'POK'

        else:
            print('Client - PER')
            request = 'PER'
            return 'PER'

        self.socket.send(request.encode())
        received = self.socket.recv(2048).decode()
        return self.parser(request, received)

    # Request
    def subscribe(self):
        request = 'SUB'
        self.socket.send(self.other_peer_public_key.encrypt(request.encode(), 1024)[0])
        r = self.socket.recv(2048)
        received = self.private_key.decrypt((r,)).decode()
        return self.parser(request, received)

    # Request
    def unsubscribe(self):
        request = 'USB'
        self.socket.send(self.other_peer_public_key.encrypt(request.encode(), 1024)[0])
        r = self.socket.recv(2048)
        received = self.private_key.decrypt((r,)).decode()
        return self.parser(request, received)

    # Request
    def blocked_message(self):
        request = 'SBM'
        self.socket.send(request.encode())
        received = self.socket.recv(2048).decode()
        return self.parser(request, received)

    # Request
    def blocking_removed_message(self):
        request = 'SUM'
        self.socket.send(request.encode())
        received = self.socket.recv(2048).decode()
        return self.parser(request, received)

    # Request
    def publish_new_microblog(self, blog, published_time):
        print('BLG Gonderiyorum.')
        request = 'BLG'
        msg = request + ' ' + str(blog) + ';' + str(published_time)
        self.socket.send(self.other_peer_public_key.encrypt(msg.encode(), 1024)[0])
        r = self.socket.recv(2048)
        received = self.private_key.decrypt((r,)).decode()
        return self.parser(request, received)

    def parser(self, request, received):
        info_file = './INFO.txt'
        file_header = 'UUID,NICK,IP,PORT,IS_BLOGGER,CONNECTION_FROM,CONNECTION_TO,TIMESTAMP,IS_ACTIVE'

        if received == 'BLK' or received == 'ERL':
            return received

        # LOGIN PROTOCOL
        if request == 'INF':
            if received[0:3] == 'HEL':
                token = received[3:].strip()

                self.info_dict[self.other_peer_uuid][6] = 'L'
                self.info_dict[self.other_peer_uuid][7] = token

                write_on_info_file(info_file, file_header, self.info_dict)
                return True
            return False

        elif request == 'LOG':
            if received[0:3] == 'HEL':
                if self.other_peer_uuid in self.key_dict.keys():
                    self.other_peer_public_key = self.key_dict[self.other_peer_uuid]

                if self.info_dict[self.other_peer_uuid][6] == 'N':
                    self.info_dict[self.other_peer_uuid][6] = 'L'
                    write_on_info_file(info_file, file_header, self.info_dict)
                return True
            return False

        # Check identity
        elif request == 'WHO':
            if received[0:3] == 'MID':
                other_peer_uuid = received[3:].strip()
                if other_peer_uuid:
                    return other_peer_uuid
            return 'ERR'

        # Demand Peer List
        elif request == 'LSQ':
            while received[0:3] != 'END':
                rest = received[3:].strip()
                rest_list = rest.split(';')
                if len(rest_list) == 5 :
                    if rest_list[0] != self.uuid:
                        if rest_list[0] not in self.info_dict.keys():
                            rest_list.extend(['N', 'N', ''])
                            self.info_dict[rest_list[0]] = rest_list
                        else:
                                self.info_dict[rest_list[0]][0:5] = rest_list

                time.sleep(0.25)
                received = self.socket.recv(2048).decode()
            return 'LSQ'

        elif request == 'PUB':
            if received[0:3].decode() == 'PUB':
                self.other_peer_public_key = RSA.importKey(received[3:].strip())
                return 'PUB'

        elif request == 'SMS':
            msg_split = received[3:].strip().split(';')

            # TUPLE SIGNATURE
            signature = int(msg_split[0])
            signature = (signature, '')

            text = msg_split[1]
            hash_text = SHA256.new(text.encode()).digest()

            try:
                if not self.other_peer_public_key.verify(hash_text, signature):
                    self.other_peer_public_key = None
            except:
                pass

        elif request == 'POK' or request == 'PER':
            if received == 'POK':
                # Public key add to dictionary
                self.key_dict[self.other_peer_uuid] = self.other_peer_public_key

                # Record public key to file
                filename = './KEYS/' + self.other_peer_uuid + '.pub'
                f = open(filename, 'w')
                f.write(self.other_peer_public_key.exportKey('PEM').decode())
                f.close()

                # self.info_dict[self.other_peer_uuid][6] = 'S'
                # write_on_info_file(info_file, file_header, self.info_dict)
                return 'POK'
            elif received == 'PER':
                return 'PER'

        elif request == 'SUB':
            if received == 'SOK':
                self.info_dict[self.other_peer_uuid][6] = 'S'
                write_on_info_file(info_file, file_header, self.info_dict)
                return 'SUB'

        elif request == 'USB':
            if received == 'UOK':
                self.info_dict[self.other_peer_uuid][6] = 'U'
                write_on_info_file(info_file, file_header, self.info_dict)
                return 'USB'

        elif request == 'SBM':
            # TODO: Karşı taraf kabul etmese de block
            print('SBM received', received)
            if received == 'BOK':
                self.info_dict[self.other_peer_uuid][5] = 'B'
                write_on_info_file(info_file, file_header, self.info_dict)
                return 'SBM'

        elif request == 'SUM':
            if received == 'ROK':
                self.info_dict[self.other_peer_uuid][5] = 'N'
                write_on_info_file(info_file, file_header, self.info_dict)
                return 'SUM'

        elif request == 'BLG':
            if received == 'TKN':
                return 'BLG'

        return 'ERR'


# Opening Screen OK
class OpeningScreen_UI(QtWidgets.QMainWindow):
    def __init__(self, my_uuid, host, port, public_key, private_key, key_dict, info_dict, new_blogs, parent=None):
        self.qt_app = QtWidgets.QApplication([])
        super(OpeningScreen_UI, self).__init__(parent)

        self.uuid = my_uuid

        # May be record my info somewhere
        self.nickname = None

        self.public_key = public_key
        self.private_key = private_key

        self.key_dict = key_dict
        self.info_dict = info_dict
        self.host = host
        self.port = int(port)
        self.new_blogs = new_blogs

        # Configure Position
        qtRectangle = self.frameGeometry()
        centerPoint = QtWidgets.QDesktopWidget().availableGeometry().center()
        qtRectangle.moveCenter(centerPoint)
        self.move(qtRectangle.topLeft())

        # create the main ui
        self.ui = Ui_OpeningScreen()
        self.ui.setupUi(self)
        self.ui.enter.pressed.connect(self.get_nickname)

    def get_nickname(self):
        self.nickname = self.ui.nickname.text()

        if self.nickname:
            f = open('nickname', 'w')
            f.write(self.nickname)
            f.close()
            self.close()

            homepage_screen = Homepage_UI(self.uuid, self.nickname, self.host, self.port, self.public_key,
                                          self.private_key, self.key_dict, self.info_dict, self.new_blogs, parent=self)
            homepage_screen.show()

    def run(self):
        self.show()
        self.qt_app.exec_()


class Homepage_UI(QtWidgets.QMainWindow):
    def __init__(self, my_uuid, nick, host, port, public_key, private_key, key_dict, info_dict, new_blogs, parent=None):
        if parent is None:
            self.qt_app = QtWidgets.QApplication([])

        QtWidgets.QMainWindow.__init__(self, parent)

        # Shape Configuration
        qtRectangle = self.frameGeometry()
        centerPoint = QtWidgets.QDesktopWidget().availableGeometry().center()
        centerPoint.setX(centerPoint.x() - self.width())
        centerPoint.setY(centerPoint.y() - self.height())
        qtRectangle.moveCenter(centerPoint)
        self.move(qtRectangle.topLeft())

        # create the main ui
        self.ui = Ui_HomePage()
        self.ui.setupUi(self)

        # Peer Information
        self.uuid = my_uuid
        self.nickname = nick
        self.public_key = public_key
        self.private_key = private_key
        self.key_dict = key_dict
        self.info_dict = info_dict
        self.host = str(host)
        self.port = int(port)
        self.new_blogs = new_blogs

        self.ui.id_label.setText('ID: ' + str(my_uuid))
        self.ui.nickname_label.setText('Kullanıcı Adı: ' + str(nick))

        # Refresh list
        self.timer2refresh_list = QtCore.QTimer()
        self.timer2refresh_list.timeout.connect(self.refresh_list)
        self.timer2refresh_list.start(5000)

        self.timer2pull_new_blogs = QtCore.QTimer()
        self.timer2pull_new_blogs.timeout.connect(self.pull_new_blogs)
        self.timer2pull_new_blogs.start(30000)

        self.timer2demand_list = QtCore.QTimer()
        self.timer2demand_list.timeout.connect(self.demand_list_from_negotiator)
        self.timer2demand_list.start(60000)

        # self.ui.tabWidget.currentChanged.connect(self.send_message)
        self.ui.login.clicked.connect(self.login)
        self.ui.blogger_list.currentTextChanged.connect(self.button_settings)
        self.ui.new_blog.clicked.connect(self.create_new_blog)
        self.ui.block.clicked.connect(self.block)
        self.ui.subscribe.clicked.connect(self.subscribe)
        self.ui.exit.clicked.connect(self.exit)

        self.ui.listWidget.setSizeAdjustPolicy(QtWidgets.QAbstractScrollArea.AdjustToContents)
        self.ui.listWidget.setSizePolicy(QtWidgets.QSizePolicy.Maximum, QtWidgets.QSizePolicy.Maximum)

        # START TO ACCEPT CONNECTIONS
        listen = Listen(self.uuid, self.host, self.port, self.public_key, self.private_key, self.key_dict, self.info_dict,
                        self.new_blogs)
        listen.start()

        self.refresh_list()
        self.button_settings()

        self.blog_dict = {}
        for file in os.listdir('./BLOGS'):
            f = open('./BLOGS/' + file)
            blog = f.read()
            f.close()

            blogger_uuid = file[0:36]
            if blogger_uuid == self.uuid:
                blogger_nickname = self.nickname
            else:
                blogger_nickname = self.info_dict[blogger_uuid][1]

            self.add_blog(blogger_nickname + ' : ' + blogger_uuid + ' : ' + blog)

            t = os.path.getmtime('./BLOGS/' + file)
            t = str(datetime.datetime.fromtimestamp(t))
            self.blog_dict[file[36:].split('.')[0]] = [blogger_uuid, blogger_nickname, blog, t]

    def pull_new_blogs(self):
        while not self.new_blogs.empty():
            gets = self.new_blogs.get().split(';')
            blog = gets[1]
            other_peer_uuid = gets[0]
            nickname = self.info_dict[other_peer_uuid][1]
            text = nickname + ':' + other_peer_uuid + blog
            self.add_blog(text)

    def button_settings(self):
        if self.ui.blogger_list.currentIndex() != -1:
            uuid_ = self.ui.blogger_list.currentText().split(';')[1].strip()
            if self.info_dict[uuid_][6] == 'N':
                self.ui.login.setDisabled(False)
                self.ui.request_list.setDisabled(True)
                self.ui.subscribe.setText('Takip Et')
                self.ui.subscribe.setDisabled(True)
            else:
                self.ui.login.setDisabled(True)
                self.ui.request_list.setDisabled(False)
                self.ui.subscribe.setDisabled(False)

            self.ui.block.setDisabled(False)

            if self.info_dict[uuid_][6] == 'S':
                self.ui.subscribe.setText('Takibi Kes')

            elif self.info_dict[uuid_][6] == 'U':
                self.ui.subscribe.setText('Takip Et')

            elif self.info_dict[uuid_][6] == 'B':
                self.ui.subscribe.setDisabled(True)
                self.ui.request_list.setDisabled(True)

            if self.info_dict[uuid_][5] == 'B':
                self.ui.block.setText('Blok Kaldır')
            else:
                self.ui.block.setText('Blokla')
        else:
            self.ui.login.setDisabled(True)
            self.ui.subscribe.setDisabled(True)
            self.ui.request_list.setDisabled(True)
            self.ui.block.setDisabled(True)

    def refresh_list(self):
        print('Tried to refresh list')
        print(self.info_dict)

        active_bloggers = []

        for u in self.info_dict.keys():

            # If it's blogger
            if self.info_dict[u][4] == 'Y':
                host2connect = self.info_dict[u][2]
                port2connect = int(self.info_dict[u][3])

                try:
                    # Check connection
                    client = Client(self.uuid, host2connect, port2connect)
                    # Print connect
                    client.connect()
                    active_bloggers.append(str(self.info_dict[u][1]) + ' ; ' + str(u))
                    client.disconnect()
                except:
                    pass
                    # TODO: Logger...

        self.ui.blogger_list.clear()
        self.ui.blogger_list.addItems(active_bloggers)

    # TODO: Hata durumları
    def demand_list_from_negotiator(self):

        for u in self.info_dict.keys():
            # If it's not blogger
            if self.info_dict[u][4] == 'N':
                host2connect = self.info_dict[u][2]
                port2connect = int(self.info_dict[u][3])
                try:
                    client = Client(self.uuid, host2connect, port2connect, host=self.host, port=self.port,
                                    info_dict=self.info_dict)
                    client.connect()
                    client.login()

                    self.button_settings()

                    client.demand_peer_list()
                    client.disconnect()
                finally:
                    self.refresh_list()

    # TODO: Hata durumları
    def login(self):
        # Need for client
        other_peer_uuid = self.ui.blogger_list.currentText().split(';')[1].strip()
        host2connect = self.info_dict[other_peer_uuid][2]
        port2connect = int(self.info_dict[other_peer_uuid][3])

        try:
            client = Client(self.uuid, host2connect, port2connect, nickname=self.nickname, host=self.host, port=self.port,
                            other_peer_uuid=other_peer_uuid, info_dict=self.info_dict, key_dict=self.key_dict)
            client.connect()
            client.login()
            client.disconnect()
        except:
            QtWidgets.QMessageBox.about(self, "Hata", "Listede Kimse Yok")

    # TODO: Hata durumları
    def demand_list_from_blogger(self):
        # Other peer uuid to request
        other_peer_uuid = self.ui.blogger_list.currentText().split(';')[1].strip()
        host2connect = self.info_dict[other_peer_uuid][2]
        port2connect = int(self.info_dict[other_peer_uuid][3])

        try:
            client = Client(self.uuid, host2connect, port2connect, nickname=self.nickname, host=self.host, port=self.port,
                            other_peer_uuid=other_peer_uuid, info_dict=self.info_dict, key_dict=self.key_dict)
            client.connect()
            client.login()
            client.demand_peer_list()
            self.refresh_list()
            client.disconnect()
        except:
            # QtWidgets.QMessageBox.about(self, "Hata", "Listede Kimse Yok")
            pass

    def create_new_blog(self):
        new_micro = NewMicroBlog_UI(self.uuid, self.nickname, self.public_key, self.private_key, self.key_dict, self.info_dict,
                                    self.host, self.port, self.blog_dict, self.ui.blogger_list, parent=self)
        new_micro.setModal(True)
        new_micro.show()

    def subscribe(self):
        if self.ui.subscribe.text() == 'Takibi Kes':
            self.unsubscribe()
        else:
            # Other peer uuid to request
            other_peer_uuid = self.ui.blogger_list.currentText().split(';')[1].strip()
            host2connect = self.info_dict[other_peer_uuid][2]
            port2connect = int(self.info_dict[other_peer_uuid][3])
            if other_peer_uuid in self.key_dict.keys():
                other_peer_public_key = self.key_dict[other_peer_uuid]
            else:
                other_peer_public_key = None

            try:
                client = Client(self.uuid, host2connect, port2connect, nickname=self.nickname, host=self.host, port=self.port,
                                other_peer_uuid=other_peer_uuid, info_dict=self.info_dict, key_dict=self.key_dict,
                                public_key=self.public_key, private_key=self.private_key)
                client.connect()
                # If subscribe selection is able to choose, means: Token shared
                client.login()
                print(other_peer_public_key)
                if other_peer_public_key is not None:
                    time.sleep(0.25)
                    client.subscribe()
                else:
                    client.share_public_key()
                    time.sleep(0.25)
                    client.signed_hash_check()
                    time.sleep(0.25)
                    if client.send_key_sharing_information() == 'POK':
                        time.sleep(0.25)
                        client.subscribe()

                self.button_settings()
                client.disconnect()
            except:
                pass

    def block(self):
        if self.ui.block.text() == 'Blok Kaldır':
            self.unblock()
        else:
            # Other peer uuid to request
            other_peer_uuid = self.ui.blogger_list.currentText().split(';')[1].strip()
            host2connect = self.info_dict[other_peer_uuid][2]
            port2connect = int(self.info_dict[other_peer_uuid][3])

            try:
                client = Client(self.uuid, host2connect, port2connect, nickname=self.nickname, host=self.host, port=self.port,
                                other_peer_uuid=other_peer_uuid, info_dict=self.info_dict, key_dict=self.key_dict,
                                public_key=self.public_key, private_key=self.private_key)
                client.connect()

                # If subscribe selection is able to choose, means: Token shared
                client.login()
                time.sleep(0.25)
                client.blocked_message()
                self.button_settings()
                client.disconnect()
            except:
                pass

    def unblock(self):
            # Other peer uuid to request
            other_peer_uuid = self.ui.blogger_list.currentText().split(';')[1].strip()
            host2connect = self.info_dict[other_peer_uuid][2]
            port2connect = int(self.info_dict[other_peer_uuid][3])

            try:
                client = Client(self.uuid, host2connect, port2connect, nickname=self.nickname, host=self.host, port=self.port,
                                other_peer_uuid=other_peer_uuid, info_dict=self.info_dict, key_dict=self.key_dict,
                                public_key=self.public_key, private_key=self.private_key)
                client.connect()

                # If subscribe selection is able to choose, means: Token shared
                client.login()
                time.sleep(0.25)
                client.blocking_removed_message()
                self.button_settings()
                client.disconnect()
            except:
                pass

    def add_blog(self, text):
        item = QtWidgets.QListWidgetItem(text)
        items = item.text().split(':')
        item_header = items[0] + ':' + items[1] + '\n'
        items = items[2:]
        item_text = ''
        for i in items:
            item_text += i + ':'
        item_text = item_text[:-1]
        line = ''
        text = ''
        for word in item_text.split():
            line += word + ' '
            text += word + ' '
            if len(line) > 48:
                text += '\n'
                line = ''

        item_text = item_header + text
        self.ui.listWidget.insertItem(0, item_text)

    def exit(self):
        self.close()

    def run(self):
        self.show()
        self.qt_app.exec_()


class NewMicroBlog_UI(QtWidgets.QDialog):
    def __init__(self, uuid_, nick, public_key, private_key, key_dict, info_dict, host, port, blog_dict, parent_combo_box, parent):
        super(NewMicroBlog_UI, self).__init__(parent)
        self.parent = parent
        self.parent_combo_box = parent_combo_box

        # create the main ui
        self.ui = Ui_NewMicroblog()
        self.ui.setupUi(self)

        self.uuid = uuid_
        self.nickname = nick
        self.public_key = public_key
        self.private_key = private_key
        self.key_dict = key_dict
        self.info_dict = info_dict
        self.blog_dict = blog_dict
        self.host = host
        self.port = port

        self.ui.yayinla.clicked.connect(self.publish_microblog)

    def publish_microblog(self):
        # Save my blogs - Write on the file
        blog = self.ui.blog.toPlainText()

        c = 0
        for k in self.blog_dict.keys():
            if self.blog_dict[k][0] == self.uuid:
                c += 1

        filename = './BLOGS/' + self.uuid + str(c) + '.txt'
        f = open(filename, 'w')

        f.write(blog)
        f.close()

        t = os.path.getmtime(filename)
        t = str(datetime.datetime.fromtimestamp(t))

        self.parent.add_blog(self.nickname + ' : ' + self.uuid + ' : ' + blog)

        AllItems = [self.parent_combo_box.itemText(i) for i in range(self.parent_combo_box.count())]
        for items in AllItems:
            other_peer_uuid = items.split(';')[1].strip()
            if self.info_dict[other_peer_uuid][5] == 'S':
                try:
                    host2connect = self.info_dict[other_peer_uuid][2]
                    port2connect = self.info_dict[other_peer_uuid][3]
                    client = Client(self.uuid, host2connect, port2connect, nickname=self.nickname, host=self.host, port=self.port,
                                other_peer_uuid=other_peer_uuid, info_dict=self.info_dict, key_dict=self.key_dict,
                                public_key=self.public_key, private_key=self.private_key)
                    client.connect()
                    client.login()
                    time.sleep(0.25)

                    client.publish_new_microblog(blog, t)
                    time.sleep(0.25)
                    client.disconnect()
                except:
                    pass
        self.close()

    def run(self):
        self.show()


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


def main():
    # PORT
    blogger_port = 12372

    # HOST
    blogger_host = '127.0.0.1'

    # KEYS INFO
    keys_path = './KEYS'
    key_dict = {}

    # INFORMATION PATH
    info_file = './INFO.txt'
    info_dict = {}

    # BLOGS INFO
    blog_path = './BLOGS'

    # Automatically Private & Public Key and UUID
    exists_pem = os.path.isfile('id_rsa.pem')
    exists_pub = os.path.isfile('id_rsa.pub')
    exists_uuid = os.path.isfile('uuid')
    if exists_pem and exists_pub and exists_uuid:
        blogger_private_key = RSA.importKey(open('id_rsa.pem', 'rb').read())
        blogger_public_key = RSA.importKey(open('id_rsa.pub', 'rb').read())
        blogger_uuid = str(uuid.UUID(open('uuid', 'r').read()))
    else:
        random_generator = Random.new().read
        blogger_private_key = RSA.generate(1024, randfunc=random_generator)
        blogger_public_key = blogger_private_key.publickey()
        blogger_uuid = str(uuid.uuid4())

        f = open('id_rsa.pem', 'w')
        f.write(blogger_private_key.exportKey('PEM').decode())
        f.close()

        f = open('id_rsa.pub', 'w')
        f.write(blogger_public_key.exportKey('PEM').decode())
        f.close()

        f = open('uuid', 'w')
        f.write(blogger_uuid)
        f.close()

    # KEYS DIRECTORY & FILE OPERATIONS
    if os.path.isdir(keys_path):
        for filename in os.listdir(keys_path):
            key_dict[filename.split('.')[0]] = RSA.importKey(open(keys_path + '/' + filename, 'rb').read())
    else:
        # define the access rights
        access_rights = 0o755
        try:
            os.mkdir(keys_path, access_rights)
        except OSError:
            print("Creation of the directory %s failed" % keys_path)

    if not os.path.isdir(blog_path):
        # define the access rights
        access_rights = 0o755
        try:
            os.mkdir(blog_path, access_rights)
        except OSError:
            print("Creation of the directory %s failed" % blog_path)

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
        file_header = 'UUID,NICK,IP,PORT,IS_BLOGGER,CONNECTION_FROM,CONNECTION_TO,TOKEN'

    # write_on_info_file(info_file, file_header, info_dict)

    new_blogs_queue = queue.Queue()

    if os.path.isfile('nickname'):
        f = open('nickname', 'r')
        nickname = f.read()
        f.close()

        app = Homepage_UI(blogger_uuid, nickname, blogger_host, blogger_port, blogger_public_key,
                          blogger_private_key, key_dict, info_dict, new_blogs_queue)
        app.run()


    else:
        app = OpeningScreen_UI(blogger_uuid, blogger_host, blogger_port, blogger_public_key, blogger_private_key, key_dict,
                               info_dict, new_blogs_queue)
        app.run()

    write_on_info_file(info_file, file_header, info_dict)

    # uuid_, host2connect, port2connect,  key_dict, info_dict, public_key=None, private_key=None, nickname=None, host=None, port=None


if __name__ == "__main__":
    main()
