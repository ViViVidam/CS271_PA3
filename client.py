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
        # self.prevLogIndex = 0
        # self.prevLogTerm = 0
        self.state = 1  # Follower
        self.electionTimeout = random.randint(10, 20)
        self.curLeader = -1
        self.votedFor = -1
        self.log = []
        self.commitIndex = 0
        self.messageSent = False
        self.HeardFromLeader = False

        # peers look like:
        # {0: {'next index': 1, 'match index': 0, 'vote granted': False},
        #  1: {'next index': 1, 'match index': 0, 'vote granted': False},
        #  3: {'next index': 1, 'match index': 0, 'vote granted': False},
        #  4: {'next index': 1, 'match index': 0, 'vote granted': False}}
        self.peers = {}

        # self.receiverGroup = [0, 1, 2, 3, 4]
        # self.receiverGroup.remove(self.id)
        # self.votesReceived = []
        print("***TERM {}***".format(self.curTerm))

    def broadcast(self, data):
        threads = []
        for receiverId in range(CLIENTNUM):
            if clientGraph[self.id][receiverId]:
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
        self.broadcast(payload)

    def restPeers(self):
        for i in range(CLIENTNUM):
            if i != self.id:
                self.peers[i] = {'next index': 1,
                                 'match index': 0, 
                                 'vote granted': False}

    def startElection(self):
        self.state = 2  # candidate
        self.curTerm += 1
        self.votedFor = self.id
        self.votesReceived = [self.id]
        self.restPeers()
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
                self.HeardFromLeader = False
                time.sleep(self.electionTimeout)
                # Election timeout elapses without election resolution:
                # increment term, start new election
                if self.state == 2 and not self.HeardFromLeader:
                    self.startElection()

            # Send initial empty AppendEntries RPCs (heartbeat) to each
            # follower; repeat during idle periods to prevent election timeouts
            if self.state == 3:
                # if not self.messageSent:
                #     self.appendEntries("")
                # self.messageSent = False
                self.heartbeat()
                time.sleep(self.heartbeatTimeout)
                print("****peers status:\n")
                print(self.peers)

            print(self.log)

    # TODO: 感觉reset之后要打断time thread重新开始？找不到restart thread的办法
    def resetTimeout(self):
        self.electionTimeout = random.randint(10, 20)

    def heartbeat(self):
        threads = []
        for i in range(CLIENTNUM):
            if clientGraph[self.id][i]:

                if self.lastLogIndex >= self.peers[i]["next index"]:
                    # heartbeat with message to append
                    entry = self.log[self.peers[i]["next index"]-1]
                else:
                    # normal heartbeat
                    entry = ""

                if self.peers[i]["next index"]-2 >= 0:
                    term = self.log[self.peers[i]["next index"]-2]['term']
                else :
                    term = 0

                payload = {'id': self.id, 'op': APPEND,
                   'data': {'term': self.curTerm,
                            'prevLogIndex': self.peers[i]["next index"] - 1,
                            'prevLogTerm': term,
                            'entry': entry,
                            'commitIndex': self.commitIndex}}
                threads.append(threading.Thread(
                    target=self.socket.sendMessage, args=(payload, clientIPs[i])))

        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

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
        self.heartbeatTimeout = random.randint(8, 10)
        self.messageSent = False
        for key in self.peers:
            self.peers[key]['next index'] = self.lastLogIndex + 1

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
                # step down
                if self.curTerm < data['data']['term']:
                    self.curTerm = data['data']['term']
                    print("***TERM {}***".format(self.curTerm))
                    self.state = 1  # follower
                    self.votedFor = -1
                    self.curLeader = -1

                if self.state == 2:
                    if data['data']['voteGranted']:
                        self.peers[data['id']]['vote granted'] = True
                        # self.votesReceived.append(data['id'])
                        # num of vote granted
                        if sum(x['vote granted'] for x in self.peers.values()) + 1 > CLIENTNUM/2:
                            self.state = 3  # leader
                            self.curLeader = self.id
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
                    # check if i have log at prevLogIndex contains prevLogTerm
                    if len(self.log) < data['data']['prevLogIndex'] or (data['data']['prevLogIndex'] != 0 and self.log[data['data']['prevLogIndex'] - 1]['term'] != data['data']['prevLogTerm']):
                        # delete log after prevLogIndex and the unmatch log at prevLogIndex
                        while len(self.log) >= data['data']['prevLogIndex'] and len(self.log) > 0:
                            self.log.pop()
                    
                        # update lastLogIndex and lastLogIndex
                        self.lastLogIndex = len(self.log)
                        if len(self.log) > 0:
                            self.lastLogTerm = self.log[-1]['term']
                        else:
                            self.lastLogTerm = 0

                        payload = {'id': self.id, 'op': RESPONDAPPEND,
                                    'data': {'term': self.curTerm, 'match index': 0, 'success': False}}
                    # else: match at prevLogIndex
                    else:
                        # delete log after prevLogIndex, log at prevLogIndex match, so we do not delete it
                        while len(self.log) > data['data']['prevLogIndex'] and len(self.log) > 0:
                            self.log.pop()
                        if data['data']['entry'] != "":
                            self.log.append(data['data']['entry'])
                            self.lastLogIndex = len(self.log)
                            self.lastLogTerm = self.log[-1]['term']
                        payload = {'id': self.id, 'op': RESPONDAPPEND,
                                    'data': {'term': self.curTerm, 'match index': self.lastLogIndex, 'success': True}}
                    self.socket.sendMessage(payload, clientIPs[data['id']])
                    # if data['data']['entry'] != "":
                    #     if len(self.log) < data['data']['prevLogIndex'] or (data['data']['prevLogIndex'] != 0 and self.log[data['data']['prevLogIndex'] - 1]['term'] != data['data']['prevLogTerm']):
                    #         while len(self.log) >= data['data']['prevLogIndex'] and len(self.log) > 0:
                    #             self.log.pop()
                    #         self.lastLogIndex = len(self.log)
                    #         self.lastLogTerm = self.log[-1]['term']
                    #         payload = {'id': self.id, 'op': RESPONDAPPEND,
                    #                    'data': {'term': self.curTerm, 'match index': 0, 'success': False}}
                    #     else:
                    #         while len(self.log) >= data['data']['prevLogIndex'] and len(self.log) > 0:
                    #             self.log.pop()
                    #         self.log.append(data['data']['entry'])
                    #         self.lastLogIndex = len(self.log)
                    #         self.lastLogTerm = self.log[-1]['term']
                    #         payload = {'id': self.id, 'op': RESPONDAPPEND,
                    #                    'data': {'term': self.curTerm, 'match index': self.lastLogIndex, 'success': True}}
                    #     self.socket.sendMessage(payload, clientIPs[data['id']])

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
                    # When AppendEntries consistency check fails, decrement nextIndex and try again in next heartbeat:
                    if not data['data']['success']:
                        #self.nextIndex[data['id']] -= 1
                        self.peers[data['id']]['next index'] -= 1
                    else:
                        self.peers[data['id']]['match index'] = data['data']['match index']
                        self.peers[data['id']]['next index'] = data['data']['match index'] + 1
                        # TODO: majority success, then commit
                        

            if data['op'] == MESSAGE:
                print("{} received MESSAGE from {} with tag {}".format(
                    self.id, data['id'], data['data']))
                # step down to follower
                if self.curTerm < data['data']['term']:
                    self.curTerm = data['data']['term']
                    print("***TERM {}***".format(self.curTerm))
                    self.state = 1  # follower
                    self.votedFor = -1
                    self.curLeader = -1

                if self.state == 3:
                    self.log.append({'term': self.curTerm, 'message': data['data']['entry']})
                    self.lastLogIndex += 1
                    self.lastLogTerm = self.log[-1]['term']
                # resend to leader
                elif self.curLeader != -1:
                    self.socket.sendMessage(data, clientIPs[self.curLeader])
                else:
                    # TODO: what if clients does not have leader info (random send?)
                    self.socket.sendMessage(data, clientIPs[(self.id+1)%5])

    def read(self):
        val = 0
        while(1):
            while (val != 'w' and val != 'c' and val != 's' and val != 'd'):
                val = input(
                    "May I help you? (w for writing): \n")
            if val == 'w':
                val = input("message:")
                # TODO: encrypt message
                payload = {'id': self.id, 'op': MESSAGE,
                           'data': {'term': self.curTerm, 'entry': val}}
                if self.state == 3:
                    self.log.append({'term': self.curTerm, 'message': val})
                    self.lastLogIndex += 1
                    self.lastLogTerm = self.log[-1]['term']
                elif self.curLeader != -1:
                    self.socket.sendMessage(payload, clientIPs[self.curLeader])
                else:
                    # TODO: what if clients does not have leader info
                    self.socket.sendMessage(payload, clientIPs[(self.id+1)%5])

    def run(self):
        # threading.Thread(target=monitor).start()
        listenThread = threading.Thread(target=self.listen)
        timeoutThread = threading.Thread(target=self.timeout)
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
