import socket
import json
from header import *
import time
import threading

class UDPSocket:
    buffersize = 1024

    def __init__(self, id):
        self.address = clientIPs[id]
        self.UDPsocket = socket.socket(socket.AF_INET, type=socket.SOCK_DGRAM)
        self.UDPsocket.bind(self.address)

    def sendMessage(self, message, ip):
        time.sleep(3)
        msgByte = str.encode(json.dumps(message))
        self.UDPsocket.sendto(msgByte, ip)

    def recvMessage(self):
        data, clientIP = self.UDPsocket.recvfrom(self.buffersize)
        data = json.loads(data.decode())
        return data, clientIP

class PersistFile:
    def __init__(self,id):
        self.log = "log" +str(id)
        self.keyPair = ("public"+str(id),"private"+str(id))

class Client:
    def __init__(self,id,mode):
        self.id = id
        self.socket = UDPSocket(id)
        self.mode = mode
        self.persistFile = PersistFile(id)

    def broadcast(self,receiverGroupId,data):
        threads = []
        for receiverId in receiverGroupId:
            threads.append(threading.Thread(target=self.socket.sendMessage, args=(data, clientIPs[receiverId])))
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()