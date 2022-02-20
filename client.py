from pickle import TRUE
import socket
import json
from header import *
import time
import threading
import random


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
    def __init__(self, id):
        self.log = "log" + str(id)
        self.keyPair = ("public"+str(id), "private"+str(id))


class Client:
    def __init__(self, id, mode):
        self.id = id
        self.socket = UDPSocket(id)
        self.mode = mode
        self.persistFile = PersistFile(id)
        self.lock = threading.Lock()
        self.term = 0
        self.lastLogIndex = 0
        self.lastLogTerm = 0
        self.state = 1  # Follower
        self.electionTimeout = random.randrange(100, 500)/1000
        self.curLeader = -1
        self.votedFor = -1
        self.receiverGroup = [0, 1, 2, 3, 4]
        self.receiverGroup.remove(self.id)
        self.votesReceived = []
        self.commitIndex = 0

    def broadcast(self, receiverGroupId, data):
        threads = []
        for receiverId in receiverGroupId:
            threads.append(threading.Thread(
                target=self.socket.sendMessage, args=(data, clientIPs[receiverId])))
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

    def requestVote(self):
        payload = {'id': self.id, 'op': ELECTION, 'data': {'term': self.term,
                                                           'lastLogIndex': self.lastLogIndex, 'lastLogTerm': self.lastLogTerm}}
        self.broadcast(self.receiverGroup, payload)

    def timeout(self):
        while(1):
            self.curLeader == -1
            time.sleep(self.electionTimeout)
            if self.state == 1 and self.curLeader == -1:
                self.term += 1
                self.state = 2  # candidate
                self.votedFor = self.id
                self.votesReceived = [self.id]
                self.resetTimeout()
                self.requestVote()

    def resetTimeout(self):
        self.electionTimeout = random.randrange(100, 500)/1000
    
    
    def appendEntries(self, entry):
        payload = {'id': self.id, 'op': APPEND, 'data': {'term': self.term,
                                                           'lastLogIndex': self.lastLogIndex, 'lastLogTerm': self.lastLogTerm,
                                                           'entry': entry, 'commitIndex': self.commitIndex}}

    def leader(self):
        while(1):
            self.appendEntries("")

    def listen(self):
        while(1):
            data, sender = self.socket.recvMessage()
            if data['op'] == ELECTION:
                print("{} received ELECTION from {} with tag {}".format(
                    self.id, data['id'], data['data']))
                #TODO: check last log term and index
                if self.term < data['data']['term']:
                    self.votedFor = data['id']
                    self.term = data['data']['term']
                    self.state = 1  #step down to FOLLOWER
                    payload = {'id': self.id, 'op': RESPONDELECTION,
                               'data': {'term': self.term, 'voteGranted': True}}
                    self.socket.sendMessage(payload, clientIPs[data['id']])
                else:
                    payload = {'id': self.id, 'op': RESPONDELECTION, 'data': {
                        'term': self.term, 'voteGranted': False}}
                    self.socket.sendMessage(payload, clientIPs[data['id']])

            if data['op'] == RESPONDELECTION:
                print("{} received RESPONDELECTION from {} with tag {}".format(
                    self.id, data['id'], data['data']))
                if self.term < data['data']['term']:
                        self.term = data['data']['term']
                        self.state = 1 # follower
                        self.votedFor = -1
                if self.state == 2:
                    if data['data']['voteGranted']:
                        self.votesReceived.append(data['id'])
                        if len(self.votesReceived) > (len(self.receiverGroup)+1)/2:
                            self.state = 3 # leader
            
            if data['op'] == APPEND:
                print("{} received APPEND from {} with tag {}".format(
                    self.id, data['id'], data['data']))
                if self.term > data['data']['term']:
                    payload = {'id': self.id, 'op': RESPONDAPPEND, 'data': {
                        'term': self.term, 'success': False}}
                    self.socket.sendMessage(payload, clientIPs[data['id']])
                else:
                    self.term = data['data']['term']
                    self.state = 1 # follower
                    self.curLeader = data['id']
                    self.resetTimeout()
                    



