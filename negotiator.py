
#!/usr/bin/env python3.7

import socket
import time
import threading
import queue

logger = open('C:\\Desktop\logger.txt','w')
#kayit = open('C:\\Desktop\kisi_listesi.txt','r+')
liste=[]
fihrist={}
class Logger(threading.Thread):
    def __init__(self,name,Lqueue):
        threading.Thread.__init__(self)
        self.name=name
        self.Lqueue=Lqueue

    def run(self):
        logger.write(self.name + " basliyor"+str(time.ctime())+"\n")
        while True:
            msg=self.Lqueue.get()
            if msg=="QUIT":
                logger.write(self.name + " cikis mesaji gelmistir"+str(time.ctime())+"\n")
                break
            logger.write(str(time.ctime())+" tarih ve saatinde "+msg+" "+self.name+" tarafından gonderilmistir.\n")
        logger.write(self.name +"  "+ str(time.ctime())+ " cikis yapti\n")

class IlgiliKisi(threading.Thread):
    def __init__(self,name,soket,addr,fihrist,Lqueue):
        threading.Thread.__init__(self)
        self.name=name
        self.soket=soket
        self.addr=addr
        self.fihrist=fihrist
        self.Lqueue=Lqueue
    def run(self):
        self.Lqueue.put(self.name +" basliyor "+str(time.ctime())+"\n")
        while True:
            msg= self.soket.rcv(1024).decode()
            dnd=self.parser(msg)
            if dnd == "ERR":
                self.soket.close()
                break

    def parser(self,msg):
        if len(msg)<3:
            self.soket.send('ERR\n').encode()
            return "ERR"
        else:
            if msg[0:3] == "INF":
                ayristi=msg.split(" ") #tek bosluga gore ayrıstırma yapılyor
                for s in ayristi:
                    if(s != "INF" and s != " "): #uuid,nickame,ip,port,is_blogger bilgilerini almak icin kullanılıyor
                        parametre = s.split(",") #virgule gore ayrıstırma islemi
                        for deger in parametre:  #degerlerin liste'ye atanmasi icin dongu
                            eleman = deger.strip() #elemanların etrafındaki bosluklar kaldiriliyor
                            liste.append(eleman) #elemanlar listeye ataniyor
                        if (fihrist.has_key(str(liste[0])) == 1):
                            self.soket.send("HEL\n").encode()
                            return "HEL"
                        else:
                            s_yeni = socket.socket() #Yeni soket aciliyor
                            s_yeni.connect((str(liste[2]),liste[3])) #daha once listede kullanıcının ip ve port numaraları mevcuttu
                            s_yeni.send('WHO\n').encode()
                            gelen=s_yeni.recv(1024).decode() #Kullanicidan uuid bekliyoruz
                            if gelen == str(liste[0]): #server tarafından gelen ile daha önce gelen uuid eşitse
                                self.soket.send('HEL\n').encode() #Merhaba
                                fihrist[str(liste[0])]=[str(liste[1]),str(liste[2]),liste[3],str(liste[4])]#fihriste ekleme
                                #kayit.write() #dosyaya ekleme
                                return "HEL"
                            else:    #değilse
                                self.soket.send('REJ\n').encode() #reddiyoruz
                                return "REJ"
            elif msg=="LSQ":
                for key in fihrist.keys():
                    self.soket.send('LSA'+'   '+key+' '+key.value()+'\n').encode()
                self.soket.send('END\n')
                return "END"

            else:
                self.soket.send("ERR\n").encode()
                return "ERR"

lQueue = queue.Queue()
lThread = Logger("Logger", lQueue)
lThread.start()

s = socket.socket()
host = "0.0.0.0"
port = 12345
s.bind((host,port))
s.listen(5)

# give unique name to all of the threads
counter = 0

while True:
    # close the port gracefully
    try:
        c, addr = s.accept()
    except KeyboardInterrupt:
        s.close()
        lQueue.put('QUIT')
        break
lQueue.put('Got new connection from' + str(addr))
newThread = IlgiliKisi('Thread-' + str(counter),
                                 c,
                                 addr[0],
                                addr[1],
                                 fihrist,
                                 lQueue)
newThread.start()
counter += 1
