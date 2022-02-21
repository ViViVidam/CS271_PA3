from pickle import TRUE
import socket
import json
import sys
from zmq import REQ
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
        # time.sleep(1)
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
        self.curTerm = 0
        self.lastLogIndex = 0
        self.lastLogTerm = 0
        self.prevLogIndex = 0
        self.prevLogTerm = 0
        self.state = 1  # Follower
        self.electionTimeout = random.randint(10,20)
        self.curLeader = -1
        self.votedFor = -1
        self.receiverGroup = [0, 1, 2, 3, 4]
        self.receiverGroup.remove(self.id)
        self.votesReceived = []
        self.log = []
        self.commitIndex = 0
        self.messageSent = False
        self.HeardFromLeader = False
        print("***TERM {}***".format(self.curTerm))

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
        payload = {'id': self.id, 'op': ELECTION,
                   'data': {'term': self.curTerm,
                            'lastLogIndex': self.lastLogIndex,
                            'lastLogTerm': self.lastLogTerm}}
        self.broadcast(self.receiverGroup, payload)

    def startElection(self):
        self.state = 2  # candidate
        self.curTerm += 1
        self.votedFor = self.id
        self.votesReceived = [self.id]
        self.resetTimeout()
        self.requestVote()

    def timeout(self):
        while(1):
            if self.state == 1:
                self.HeardFromLeader = False
                time.sleep(self.electionTimeout)
                if self.state == 1 and not self.HeardFromLeader:
                    self.startElection()

            if self.state == 2:
                time.sleep(self.electionTimeout)
                # Election timeout elapses without election resolution:
                # increment term, start new election
                if self.state == 2 and not self.HeardFromLeader:
                    self.startElection()

            # Send initial empty AppendEntries RPCs (heartbeat) to each
            # follower; repeat during idle periods to prevent election timeouts
            if self.state == 3:
                if not self.messageSent:
                    self.appendEntries("")
                self.messageSent = False
                time.sleep(self.heartbeatTimeout)
            
            print(self.log)


    def resetTimeout(self):
        self.electionTimeout = random.randint(10, 20)

    def appendEntries(self, entry):
        if entry != "":
            self.messageSent = True
            self.log.append({'term': self.curTerm, 'message': entry})
            self.lastLogIndex += 1
            self.lastLogTerm = self.curTerm
        payload = {'id': self.id, 'op': APPEND,
                   'data': {'term': self.curTerm,
                            'prevLogIndex': self.prevLogIndex,
                            'prevLogTerm': self.prevLogTerm,
                            'entry': entry,
                            'commitIndex': self.commitIndex}}
        if entry != "":
            self.prevLogIndex = self.lastLogIndex
            self.prevLogTerm = self.curTerm
        self.broadcast(self.receiverGroup, payload)

    def initializeLeader(self):
        # Initialize nextIndex for each to last log index + 1
        self.nextIndex = []
        self.heartbeatTimeout = random.randint(8, 10)
        self.messageSent = False
        for i in range(CLIENTNUM):
            self.nextIndex.append(self.lastLogIndex + 1)

    def listen(self):
        while(1):
            data, sender = self.socket.recvMessage()
            if data['op'] == ELECTION:
                print("{} received ELECTION from {} with tag {}".format(
                    self.id, data['id'], data['data']))
                # check last log term and index
                if self.curTerm < data['data']['term']:
                    self.votedFor = -1
                    self.curTerm = data['data']['term']
                    print("***TERM {}***".format(self.curTerm))
                    self.state = 1  # step down to FOLLOWER
                    self.curLeader = -1
                if self.curTerm == data['data']['term']:
                    if self.votedFor != -1 or self.lastLogTerm > data['data']['lastLogTerm'] or (self.lastLogTerm == data['data']['lastLogTerm'] and self.lastLogIndex > data['data']['lastLogIndex']):
                        payload = {'id': self.id, 'op': RESPONDELECTION,
                                   'data': {'term': self.curTerm, 'voteGranted': False}}
                    else:
                        self.votedFor = data['id']
                        payload = {'id': self.id, 'op': RESPONDELECTION,
                                   'data': {'term': self.curTerm, 'voteGranted': True}}
                    self.socket.sendMessage(payload, clientIPs[data['id']])
                else:
                    payload = {'id': self.id, 'op': RESPONDELECTION, 'data': {
                        'term': self.curTerm, 'voteGranted': False}}
                    self.socket.sendMessage(payload, clientIPs[data['id']])

            if data['op'] == RESPONDELECTION:
                print("{} received RESPONDELECTION from {} with tag {}".format(
                    self.id, data['id'], data['data']))
                if self.curTerm < data['data']['term']:
                    self.curTerm = data['data']['term']
                    print("***TERM {}***".format(self.curTerm))
                    self.state = 1  # follower
                    self.votedFor = -1
                    self.curLeader = -1
                if self.state == 2:
                    if data['data']['voteGranted']:
                        self.votesReceived.append(data['id'])
                        if len(self.votesReceived) > (len(self.receiverGroup)+1)/2:
                            self.curLeader = self.id
                            self.state = 3  # leader
                            self.initializeLeader()

            if data['op'] == APPEND:
                print("{} received APPEND from {} with tag {}".format(
                    self.id, data['id'], data['data']))
                if self.curTerm > data['data']['term']:
                    payload = {'id': self.id, 'op': RESPONDAPPEND,
                               'data': {'term': self.curTerm, 'success': False}}
                    self.socket.sendMessage(payload, clientIPs[data['id']])
                else:
                    if self.curTerm < data['data']['term']:        
                        self.curTerm = data['data']['term']
                        print("***TERM {}***".format(self.curTerm))
                    self.state = 1  # follower
                    self.curLeader = data['id']
                    self.HeardFromLeader = True
                    self.resetTimeout()
                    # TODO:
                    if data['data']['entry'] != "":
                        if len(self.log) < data['data']['prevLogIndex'] or (data['data']['prevLogIndex'] != 0 and self.log[data['data']['prevLogIndex'] - 1]['term'] != data['data']['prevLogTerm']):
                            while len(self.log) >= data['data']['prevLogIndex']:
                                self.log.pop()
                            self.lastLogIndex = len(self.log)
                            self.lastLogTerm = self.log[-1]['term']
                            payload = {'id': self.id, 'op': RESPONDAPPEND,
                                       'data': {'term': self.curTerm, 'success': False}}
                        else:
                            self.log.append({'term': self.curTerm, 'message': data['data']['entry']})
                            self.lastLogIndex += 1
                            self.lastLogTerm = self.curTerm
                            payload = {'id': self.id, 'op': RESPONDAPPEND,
                                       'data': {'term': self.curTerm, 'success': True}}
                        self.socket.sendMessage(payload, clientIPs[data['id']])

            # TODO:
            if data['op'] == RESPONDAPPEND:
                print("{} received RESPONDAPPEND from {} with tag {}".format(
                    self.id, data['id'], data['data']))
                # step down to follower
                if self.curTerm < data['data']['term']:
                    self.curTerm = data['data']['term']
                    print("***TERM {}***".format(self.curTerm))
                    self.state = 1  # follower
                    self.votedFor = -1
                    self.curLeader = -1
                if self.state == 3:
                    # When AppendEntries consistency check fails, decrement nextIndex and try again:
                    if not data['data']['success']:
                        self.nextIndex[data['id']] -= 1
                        payload = {'id': self.id, 'op': APPEND,
                                    'data': {'term': self.curTerm,
                                            'prevLogIndex': self.nextIndex[data['id']] - 1,
                                            'prevLogTerm': self.log[self.nextIndex[data['id']] - 2]['term'],
                                            'entry': self.log[self.nextIndex[data['id']] - 2]['message'],
                                            'commitIndex': self.commitIndex}}
                        self.socket.sendMessage(payload, clientIPs[data['id']])
                    else:
                        #TODO: majority success, then commit
                        return

            if data['op'] == MESSAGE:
                print("{} received MESSAGE from {} with tag {}".format(
                    self.id, data['id'], data['data']))
                if self.state == 3:
                    self.appendEntries(data['data']['entry'])
                # resend to leader
                elif self.curLeader != -1:
                    self.socket.sendMessage(data, clientIPs[self.curLeader])
                else:
                    # TODO: what if clients does not have leader info
                    self.socket.sendMessage(data, clientIPs[self.curLeader])

    def read(self):
        val = 0
        while(1):
            while (val != 'w' and val != 'c' and val != 's' and val != 'd'):
                val = input(
                    "May I help you? (w for writing, c for check balance , s for snapshot, to view the snapshots: d): \n")
            if val == 'w':
                val = input()
                # TODO: encrypt message
                payload = {'id': self.id, 'op': MESSAGE,
                           'data': {'term': self.curTerm, 'entry': val}}
                if self.curLeader == self.id:
                    self.appendEntries(val)
                elif self.curLeader != -1:
                    self.socket.sendMessage(payload, clientIPs[self.curLeader])
                else:
                    # TODO: what if clients does not have leader info
                    self.socket.sendMessage(payload, clientIPs[self.curLeader])
    
    def run(self):
        #threading.Thread(target=monitor).start()
        listenThread = threading.Thread(target=self.listen)
        timeoutThread = threading.Thread(target = self.timeout)
        if self.mode == NORMAL:
            sendThread = threading.Thread(target=self.read)
        else:
            sendThread = threading.Thread(target=self.read)
        listenThread.start()
        time.sleep(1)
        sendThread.start()
        time.sleep(1)
        timeoutThread.start()
        listenThread.join()
        sendThread.join()
        timeoutThread.join()


if __name__ == '__main__':
    client = Client(int(sys.argv[1]), NORMAL)
    print("{} client started\nlistening...".format(client.id))
    client.run()


