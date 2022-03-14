import os
import socket
import json
import sys
from header import *
import time
import threading
import random
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import hashlib
import re
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

pads =  padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
def argParse(string:str):
    return re.split(' +',string)


class UDPSocket:
    buffersize = 16384

    def __init__(self, id):
        self.address = clientIPs[id]
        self.UDPsocket = socket.socket(socket.AF_INET, type=socket.SOCK_DGRAM)
        self.UDPsocket.bind(self.address)
        self.ips = clientIPs[:]
        self.buffer = ["","","","",""]
        self.total = [0,0,0,0,0]
    def sendMessage(self, message, ip):
        time.sleep(1)
        messagestring = json.dumps(message)
        #messageBytes = messagestring.encode('latin1')
        total = int(len(messagestring) / 7000)
        if len(messagestring) % 7000 != 0:
            total += 1
        for current in range(total):
            segment = messagestring[current*7000:(current+1)*7000]
            payload = {'total':total,'packetId':current,'segment':segment}
            msgByte = json.dumps(payload).encode('latin1')
            self.UDPsocket.sendto(msgByte, ip)

    def recvMessage(self):
        while 1:
            data, clientIP = self.UDPsocket.recvfrom(self.buffersize)
            data = data.decode('latin1')
            data = json.loads(data)
            index = self.ips.index(clientIP)
            if data['packetId'] == 0:
                self.buffer[index]=""
                self.total[index] = data['total']

            self.buffer[index]+=data['segment']
            if data['packetId'] == data['total'] - 1 :
                payload = json.loads(self.buffer[index])
                self.buffer[index] = ""
                self.total[index] = 0
                return payload, clientIP

class KeyManager:

    def __init__(self,id):
        self.id = id
        self.counter = 0
        self.groupKeyPair = []# [((id,counter),pub,priv)]
        self.clientKeys = [] #(ID,Publickey),also stores itself
        self.privateKeyName = "privateKey"+str(id)+".pem"
        self.publicKeyName = "publicKey"+str(id)+".pem"

        if os.path.exists(self.privateKeyName) == True:
            priv = open(self.privateKeyName,"rb")
            self.privateKey = serialization.load_pem_private_key(priv.read(), password=None)
            priv.close()
        else:
            print("Key not found {}".format(self.privateKeyName))
            exit(1)

        if os.path.exists(self.publicKeyName) == True:
            pub = open(self.publicKeyName,"rb")
            self.publicKey = serialization.load_pem_public_key(pub.read())
            pub.close()
        else:
            print("Key not found {}".format(self.publicKeyName))
            exit(1)

        for i in range(CLIENTNUM):
            publicKeyName = "publicKey"+str(i)+".pem"
            if os.path.exists(publicKeyName) == True:
                pub = open(publicKeyName, "rb")
                clientPublicKey = serialization.load_pem_public_key(pub.read())
                self.clientKeys.append((i,clientPublicKey))
            else:
                print("Key not found {}".format(self.privateKey))
                exit(1)

    def getPublicKey(self):
        return self.publicKey.public_bytes(encoding=serialization.Encoding.PEM,
                                               format=serialization.PublicFormat.SubjectPublicKeyInfo)
    def getPrivateKey(self):
        return self.privateKey.private_bytes(encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption())

    def makeGroupKey(self,groupId:(int,int)):
        private = rsa.generate_private_key(65537,2048)
        public = private.public_key()
        if groupId[1] == 0:
            return None,None
        # we don't append it until it is commited
        # self.groupKeyPair.append((id,public,private))
        # same counter maybe used multiple times, but only the first committed in the log will be used.
        return private.private_bytes(encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()),public.public_bytes(encoding=serialization.Encoding.PEM,format=serialization.PublicFormat.SubjectPublicKeyInfo)

    def findGroupKey(self, id):
        for i in range(len(self.groupKeyPair)):
            if self.groupKeyPair[i][0] == id:
                return i
        return -1

    def addGroupKey(self,id,publicByte,privateByte):
        flag = 0
        for i in range(len(self.groupKeyPair)):
            if self.groupKeyPair[i][0] == id:
                flag = 1
                break
        if flag == 0:
            public = serialization.load_pem_public_key(publicByte)
            private = serialization.load_pem_private_key(privateByte, password=None)
            self.groupKeyPair.append((id,public,private))
    def removeGroupKey(self,id):
        for i in range(len(self.groupKeyPair)):
            if self.groupKeyPair[i][0] == id:
                self.groupKeyPair.pop(i)
                break
    def makeValidation(self,publicKey):
        return publicKey.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo)
    def getPrivateGroupKey(self,index):
        return self.groupKeyPair[index][2].private_bytes(encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption())
    def getPublicGroupKey(self,index):
        return self.groupKeyPair[index][1].public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo)

    def encryptAndChunk(self,key, data: bytes):
        i = 0
        packet = []
        while i < len(data):
            tmp = key.encrypt(data[i:(i + 90)], pads)
            tmp = tmp.decode('latin1')
            packet.append(tmp)
            i += 90
        return packet

    def decryptAndConnect(self,key, packet: [bytes]):
        decryption = []
        for item in packet:
            tmp = item.encode('latin1')
            tmp = key.decrypt(tmp, pads)
            decryption.append(tmp)
        return b"".join(decryption)

class Group:
    def __init__(self):
        self.groupId = []
        self.groupmember = []
        self.groupMessage = [] #(),()
    def isInGroup(self,id:(int,int)):
        for i in range(len(self.groupId)):
            if id == self.groupId[i]:
                return True
        return False
    def putGroup(self,id:(int,int),members:[int],messages=None):
        print(members)
        if id not in self.groupId:
            self.groupId.append(id)
            self.groupmember.append([])
            self.groupmember[-1] = members[:]
            self.groupMessage.append([])
            if messages is not None:
                self.groupMessage[-1] = messages[:]
        else:
            print(self.groupId)
    def getGroupMembers(self,id:(int,int)):
        try:
            index = self.groupId.index(id)
            return self.groupmember[index]
        except ValueError:
            return None

    def getGroupMessages(self,id:(int,int)):
        try:
            index = self.groupId.index(id)
            return self.groupMessage[index]
        except ValueError:
            return None

    def insertGroupMember(self,id:(int,int),member:int):
        try:
            index = self.groupId.index(id)
            if member not in self.groupmember[index]:
                self.groupmember[index].append(member)
        except ValueError:
            print("{} not found {}".format(id,self.groupId))
    def removeGroup(self,id:(int,int)):
        try:
            index = self.groupId.index(id)
            self.groupId.pop(index)
            self.groupmember.pop(index)
        except ValueError:
            print("{} not found {}".format(id,self.groupId))
    def removeGroupMember(self,id:(int,int),member:int):
        try:
            index = self.groupId.index(id)
            self.groupmember[index].remove(member)
        except ValueError:
            print("{} not found {}".format(id,self.groupId))

    def putMessage(self,groupId,sender,message):
        try:
            index = self.groupId.index(groupId)
            self.groupMessage[index].append((sender,message))
        except ValueError:
            print("{} not found {}".format(id,self.groupId))
class Client:
    def __init__(self, id, mode):
        self.id = id
        self.socket = UDPSocket(id)
        self.mode = mode
        self.keyManager = KeyManager(id)
        self.lock = threading.Lock()
        self.group = Group()
        self.invalidGroup = Group()
        # log structure:
        # [{'term': 1, 'type': 'message', 'message': '0000', 'sender':1, 'committed': True}, 
        # {'term': 2, 'type': 'message', 'message': '111111111', 'sender':1, 'committed': True}, 
        # {'term': 2, 'type': 'message', 'message': '000000000', 'sender':1, 'committed': True}, 
        # {'term': 4, 'type': 'message', 'message': '222222222', 'sender':1, 'committed': False}, 
        # {'term': 4, 'type': 'message', 'message': '33333333333', 'sender':1, 'committed': False}]
        # {'term': 4, 'type': 'key', 'message': 'A77BA9BFABDF123', 'SHA':....,'committed': False}]
        self.log = []
        self.readJson()
        for index in range(len(self.log)):
            if self.log[index]['committed'] is True:
                self.doLog(index)
        if len(self.log):
            self.lastLogIndex = len(self.log)
            self.lastLogTerm = self.log[-1]['term']
        else:
            self.lastLogIndex = 0
            self.lastLogTerm = 0

        self.curTerm = self.lastLogTerm
        self.state = FOLLOWER  # Follower
        self.electionTimeout = random.randint(8, 15)
        self.curLeader = -1
        self.votedFor = -1
        self.commitIndex = 0
        for i in range(len(self.log) - 1, -1, -1):
            if self.log[i]['committed']:
                self.commitIndex = i + 1
                break
        # self.messageSent = False
        self.HeardFromLeader = False
        if os.path.exists("json") is False:
            os.mkdir("json")
        # peers structure:
        # {0: {'next index': 1, 'match index': 0, 'vote granted': False},
        #  1: {'next index': 1, 'match index': 0, 'vote granted': False},
        #  3: {'next index': 1, 'match index': 0, 'vote granted': False},
        #  4: {'next index': 1, 'match index': 0, 'vote granted': False}}
        self.peers = {}

        print("***TERM {}***".format(self.curTerm))
    def readJson(self):
        try:
            with open("json/"+str(self.id)+".json", "r") as f:
                self.log = json.load(f)
                # print(self.log)
        except:
            print("create json file later")

    def writeJson(self):
        with open("json/"+str(self.id)+".json", "w") as f:
           json.dump(self.log, f) 

    def broadcast(self, data):
        threads = []
        with open("networkConfig.txt", "r") as fo:
            network = fo.read()
        for receiverId in range(CLIENTNUM):
            if network[self.id*5+receiverId] == '1':
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
        self.state = CANDIDATE  # candidate
        self.curTerm += 1
        self.votedFor = self.id
        # self.votesReceived = [self.id]
        self.restPeers()
        self.resetTimeout()
        self.requestVote()

    def timeout(self):
        while(1):
            if self.state == FOLLOWER:
                self.HeardFromLeader = False
                self.timeoutReseted = False
                for _ in range(self.electionTimeout):
                    time.sleep(1)
                    if self.timeoutReseted:
                        break
                with self.lock:
                    if self.state == FOLLOWER and not self.HeardFromLeader and not self.timeoutReseted:
                        self.startElection()

            if self.state == CANDIDATE:
                self.HeardFromLeader = False
                self.timeoutReseted = False
                for _ in range(self.electionTimeout):
                    time.sleep(1)
                    if self.timeoutReseted:
                        break
                # Election timeout elapses without election resolution:
                # increment term, start new election
                with self.lock:
                    if self.state == CANDIDATE and not self.HeardFromLeader and not self.timeoutReseted:
                        self.startElection()

            # Send initial empty AppendEntries RPCs (heartbeat) to each
            # follower; repeat during idle periods to prevent election timeouts
            if self.state == LEADER:
                self.heartbeat()
                time.sleep(self.heartbeatTimeout)
                print("****peers status:")
                print(self.peers)

            print("***log:")
            for log in self.log:
                print("{} {} {}".format(log['term'],log['type'],log['committed']),flush=True)

    def resetTimeout(self):
        self.timeoutReseted = True
        self.electionTimeout = random.randint(8, 15)

    def heartbeat(self):
        threads = []
        with open("networkConfig.txt", "r") as fo:
            network = fo.read()
        for i in range(CLIENTNUM):

            if network[self.id*5+i] == '1':

                if self.lastLogIndex >= self.peers[i]["next index"]:
                    # heartbeat with message to append
                    entry = self.log[self.peers[i]["next index"]-1]
                else:
                    # normal heartbeat
                    entry = ""

                if self.peers[i]["next index"]-2 >= 0:
                    term = self.log[self.peers[i]["next index"]-2]['term']
                else:
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

    def initializeLeader(self):
        # Initialize nextIndex for each to last log index + 1
        self.heartbeatTimeout = 5
        # self.messageSent = False
        for key in self.peers:
            self.peers[key]['next index'] = self.lastLogIndex + 1

    ### added two functions
    def SHA256(self,object):
        if not isinstance(object, str):
            strings = json.dumps(object)
        res = hashlib.sha256(strings)
        return res.hexdigest()
    # client standard payload {id,op,entrypt,data{term,type,entry},SHA(data)}
    def makeMessagePayload(self,encrypt:bool,data):
        payload = {'id': self.id, 'op': MESSAGE, 'encrypt': encrypt, 'data': data}
        return payload

    def doLog(self,index:int):
        assert(self.log[index]['committed'])
        groupId = tuple(self.log[index]["groupId"])
        if self.log[index]['type'] == 'message':
            print(self.log[index])
            if groupId[1] != 0:
                if self.group.isInGroup(groupId)==True:
                    i = self.keyManager.findGroupKey(groupId)
                    message = self.keyManager.decryptAndConnect(self.keyManager.groupKeyPair[i][2],self.log[index]['message'])
                    self.group.putMessage(groupId,self.log[index]['sender'],message.decode('utf-8'))
        elif self.log[index]['type'] == 'create':
            members = self.log[index]['members']
            if self.group.isInGroup(groupId) is False and self.id in members:
                i = members.index(self.id)
                privateBytes = self.keyManager.decryptAndConnect(self.keyManager.privateKey,self.log[index]['private'][i])
                self.keyManager.addGroupKey(groupId,self.log[index]['public'].encode('latin1'),privateBytes)
                self.group.putGroup(groupId,self.log[index]['members'])
        elif self.log[index]['type'] == 'add':
            clientId = self.log[index]['member']
            if self.id == clientId:
                historymessages = None
                if self.invalidGroup.isInGroup(groupId):
                    historymessages = self.invalidGroup.getGroupMessages(groupId)
                privateBytes = self.keyManager.decryptAndConnect(self.keyManager.privateKey,self.log[index]['private'])
                self.keyManager.addGroupKey(groupId, self.log[index]['public'].encode('latin1'), privateBytes)
                flag = False #prevent create twice
                for j in range(0,index):
                    if tuple(self.log[j]['groupId'])==groupId and self.log[j]['committed'] == True:
                        if self.log[j]['type'] == "create" and flag is False:
                            newMembers = self.log[j]['members'][:]
                            flag = True
                        elif self.log[j]['type'] == "kick":
                            if self.log[j]['member'] in newMembers:
                                newMembers.remove(self.log[j]['member'])
                        elif self.log[j]['type'] == "add":
                            if self.log[j]['member'] not in newMembers:
                                newMembers.append(self.log[j]['member'])
                if self.id not in newMembers:
                    newMembers.append(self.id)
                self.group.putGroup(tuple(self.log[j]['groupId']), newMembers,historymessages)
            else:
                if self.group.isInGroup(groupId):
                    self.group.insertGroupMember(groupId,clientId)
        elif self.log[index]['type'] == "kick":
            clientId = self.log[index]['member']
            if self.id == clientId and self.group.isInGroup(groupId):
                if self.invalidGroup.isInGroup(groupId):
                    self.invalidGroup.removeGroup(groupId)
                self.invalidGroup.putGroup(groupId,self.group.getGroupMembers(groupId),self.group.getGroupMessages(groupId))
                self.group.removeGroup(groupId)
                self.keyManager.removeGroupKey(groupId)

            elif self.group.isInGroup(groupId):
                members = self.group.getGroupMembers(groupId)
                print(self.group.groupMessage)
                messages = self.group.getGroupMessages(groupId)
                if clientId in members:
                    members.remove(clientId)
                    print(self.keyManager.groupKeyPair)
                    self.keyManager.removeGroupKey(groupId)
                    self.group.removeGroup(groupId)
                    print("{} remove {} from {}".format(self.id,clientId,groupId),flush=True)
                    privateBytes = self.keyManager.decryptAndConnect(self.keyManager.privateKey,self.log[index]['private'][members.index(self.id)])
                    self.keyManager.addGroupKey(groupId, self.log[index]['public'].encode('latin1'),
                                                privateBytes)
                    print(self.keyManager.groupKeyPair)
                    self.group.putGroup(groupId,members,messages)

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
                    self.state = FOLLOWER  # step down to FOLLOWER
                    self.curLeader = -1
                    self.curLeader = -1
                if self.curTerm == data['data']['term']:
                    if self.votedFor != -1 or self.lastLogTerm > data['data']['lastLogTerm'] or (self.lastLogTerm == data['data']['lastLogTerm'] and self.lastLogIndex > data['data']['lastLogIndex']):
                        payload = {'id': self.id, 'op': RESPONDELECTION,
                                   'data': {'term': self.curTerm, 'voteGranted': False}}
                    else:
                        self.votedFor = data['id']
                        self.resetTimeout()
                        payload = {'id': self.id, 'op': RESPONDELECTION,
                                   'data': {'term': self.curTerm, 'voteGranted': True}}
                else:
                    payload = {'id': self.id, 'op': RESPONDELECTION, 'data': {
                        'term': self.curTerm, 'voteGranted': False}}

                with open("networkConfig.txt", "r") as fo:
                    network = fo.read()
                if network[self.id*5+data['id']] == '1':
                    self.socket.sendMessage(payload, clientIPs[data['id']])

            if data['op'] == RESPONDELECTION:
                print("{} received RESPONDELECTION from {} with tag {}".format(
                    self.id, data['id'], data['data']))
                # step down
                if self.curTerm < data['data']['term']:
                    self.curTerm = data['data']['term']
                    print("***TERM {}***".format(self.curTerm))
                    self.state = FOLLOWER  # follower
                    self.votedFor = -1
                    self.curLeader = -1

                if self.state == CANDIDATE:
                    if data['data']['voteGranted']:
                        self.peers[data['id']]['vote granted'] = True
                        # num of vote granted
                        if sum(x['vote granted'] for x in self.peers.values()) + 1 > CLIENTNUM/2:
                            self.state = LEADER  # leader
                            self.curLeader = self.id
                            self.initializeLeader()

            if data['op'] == APPEND:
                flag = 0 # indicate whether could be send a keypublish message
                print("{} received APPEND from {} with tag {}".format(
                    self.id, data['id'], data['data']['term']))
                if self.curTerm > data['data']['term']:
                    payload = {'id': self.id, 'op': RESPONDAPPEND,
                               'data': {'term': self.curTerm, 'match index': 0, 'success': False}}
                else:
                    if self.curTerm < data['data']['term']:
                        self.curTerm = data['data']['term']
                        print("***TERM {}***".format(self.curTerm))
                    self.state = FOLLOWER  # follower
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
                        flag = 1
                        # delete log after prevLogIndex, log at prevLogIndex match, so we do not delete it
                        while len(self.log) > data['data']['prevLogIndex'] and len(self.log) > 0:
                            self.log.pop()

                        if data['data']['entry'] != "":
                            self.log.append(data['data']['entry'])
                            self.log[-1]['committed'] = False
                            self.lastLogIndex = len(self.log)
                            self.lastLogTerm = self.log[-1]['term']

                        if data['data']['commitIndex'] >= self.lastLogIndex:
                            for j in range(self.commitIndex+1, self.lastLogIndex+1):
                                self.log[j-1]['committed'] = True
                                self.doLog(j - 1)
                            self.commitIndex = self.lastLogIndex
                        else:
                            for j in range(self.commitIndex+1, data['data']['commitIndex']+1):
                                self.log[j-1]['committed'] = True
                                self.doLog(j - 1)
                            self.commitIndex = data['data']['commitIndex']
                        payload = {'id': self.id, 'op': RESPONDAPPEND,
                                   'data': {'term': self.curTerm, 'match index': self.lastLogIndex, 'success': True}}
                    
                self.writeJson()

                with open("networkConfig.txt", "r") as fo:
                    network = fo.read()
                if network[self.id*5+data['id']]=='1':
                    self.socket.sendMessage(payload, clientIPs[data['id']])

            if data['op'] == RESPONDAPPEND:
                print("{} received RESPONDAPPEND from {} with tag {}".format(
                    self.id, data['id'], data['data']))
                # step down to follower
                if self.curTerm < data['data']['term']:
                    self.curTerm = data['data']['term']
                    print("***TERM {}***".format(self.curTerm))
                    self.state = FOLLOWER  # follower
                    self.votedFor = -1
                    self.curLeader = -1
                elif self.state == LEADER:
                    # When AppendEntries consistency check fails, decrement nextIndex and try again in next heartbeat:
                    if not data['data']['success']:
                        self.peers[data['id']]['next index'] -= 1
                    else:
                        self.peers[data['id']]['match index'] = data['data']['match index']
                        self.peers[data['id']]['next index'] = data['data']['match index'] + 1
                        # majority success, then commit 在这里好像没啥影响
                        for i in range(self.lastLogIndex, self.commitIndex, -1):
                            if sum(x['match index'] >= i for x in self.peers.values()) + 1 > CLIENTNUM/2:
                                if self.log[i-1]['term'] >= self.curTerm:
                                    for j in range(self.commitIndex+1, i+1):
                                        self.log[j-1]['committed'] = True
                                        print("{} set committed to ture".format(self.id))
                                        self.doLog(j-1)
                                    self.commitIndex = i
                                    self.writeJson()
                                break

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

                with open("networkConfig.txt", "r") as fo:
                    network = fo.read()

                if self.state == LEADER:
                    ### leader logs behaviour change to type set data's type
                    if data['data']['type']=="create":
                        self.log.append(
                            {'term': self.curTerm, 'type': data['data']['type'],'public':data['data']['public'],
                             'private':data['data']['private'],'members':data['data']['members'],
                             'groupId':data['data']['groupId'],'committed':False})
                    elif data['data']['type']=="add" or data['data']['type']=="kick":
                        self.log.append({'term': self.curTerm, 'type': data['data']['type'],'public':data['data']['public'],
                             'private':data['data']['private'],'member':data['data']['member'],
                             'groupId':data['data']['groupId'],'committed':False})
                    elif data['data']['type'] == 'message':
                        self.log.append(
                            {'term': self.curTerm, 'type': 'message', 'groupId': data['data']['groupId'],
                             'message': data['data']['message'], 'sender':data['id'], 'committed': False})
                    self.lastLogIndex += 1
                    self.lastLogTerm = self.log[-1]['term']
                    self.writeJson()

                # # resend to leader
                # elif self.curLeader != -1 and network[self.id*5+self.curLeader]=='1':
                #     self.socket.sendMessage(data, clientIPs[self.curLeader])
                # else:
                #     # TODO: what if clients does not have leader info (random send currently)
                #     for key in self.peers:
                #         if network[self.id*5+key] == '1':
                #             self.socket.sendMessage(data, clientIPs[key])
                #             break

    #leader log entry term,type,entryval,commit

    def read(self):
        val = 0
        while(1):
            val = input("May I help you? (help to see available instructions):\n")
            args = argParse(val)
            if args[0] == "help" or args[0] == 'h':
                print("--------------------------------------")
                print("writing message: w [message] [groupId]")
                print("create Group: createGroup （[processId],[counter]) [clientId] [clientId]...")
                print("add member: add [processId],[counter]) [clientId]")
                print("kick member: kick [groupId] [clientId]")
                print("print group: printGroup [groupId]")
                print("fail link: failLink [clientId] [clientId]")
                print("fix link: fixLink [clientId] [clientId]")
                print("fail process: ctrl C will be used")
                print("groupId (anyprocessId,0) will be used as a global group")
                print("--------------------------------------")
            if args[0] == 'w' and len(args) == 3:
                val = args[1]
                groupId = tuple(map(int,args[2][1:-1].split(',')))
                print("groupID {}".format(groupId),flush=True)

                index = self.keyManager.findGroupKey(groupId)
                if index == -1 and groupId[1] != 0:
                    print("I am not in that group", flush=True)
                    continue
                val = val.encode('utf-8')
                packet = self.keyManager.encryptAndChunk(self.keyManager.groupKeyPair[index][1], val)
                if self.state == LEADER:
                    self.log.append({'term': self.curTerm, 'type': 'message','groupId':groupId,
                                     'message': packet, 'sender': self.id, 'committed': False})
                    self.lastLogIndex += 1
                    self.lastLogTerm = self.log[-1]['term']
                    self.writeJson()
                else:
                    if groupId[1] != 0:
                        data = {'term': self.curTerm, 'type': 'message', 'groupId': groupId,
                                'message': packet}
                        payload = self.makeMessagePayload(True,data)
                    elif groupId[1] == 0:
                        data = {'term': self.curTerm, 'type': 'message', 'groupId': groupId,
                                'message': val}
                        payload = self.makeMessagePayload(False,data)

                    with open("networkConfig.txt", "r") as fo:
                        network = fo.read()
                    if self.curLeader != -1 and network[self.id*5+self.curLeader] == '1':
                        self.socket.sendMessage(payload, clientIPs[self.curLeader])
                    else:
                        print("failed\nthe network currently is not available\n",flush=True)
                        break
                        # # what if clients does not have leader info, 感觉这样ok
                        # for key in self.peers:
                        #     if network[self.id*5+key] == '1':
                        #         self.socket.sendMessage(payload, clientIPs[key])
                        #         break

            elif args[0] == "createGroup" and len(args)>2:
                groupId = tuple(map(int, args[1][1:-1].split(',')))
                private, public = self.keyManager.makeGroupKey(groupId)
                if private == None or public == None:
                    print("you might use counter 0 which is used by global group or clientId must match groupId",flush=True)
                    continue
                if str(self.id) not in args[1:]:
                    print("the group member must have the initiator",flush=True)
                    continue
                if groupId[0] != self.id:
                    print("process id doesn't match",flush=True)
                    continue
                if self.group.isInGroup(groupId):
                    print("group already created {}".format(groupId),flush=True)
                encryptedPrivate = []
                members = []
                print(args)
                for i in range(2,len(args)):
                    clientId = int(args[i])
                    packet = self.keyManager.encryptAndChunk(self.keyManager.clientKeys[clientId][1],private)
                    encryptedPrivate.append(packet)
                    members.append(clientId)

                if self.state == LEADER:
                    self.log.append({'term': self.curTerm, 'type': 'create','groupId':groupId,
                                     'public':public.decode('latin1'),'private':encryptedPrivate,
                                     'members':members, 'committed': False})
                    self.lastLogIndex += 1
                    self.lastLogTerm = self.log[-1]['term']
                    self.writeJson()
                else:
                    with open("networkConfig.txt", "r") as fo:
                        network = fo.read()
                    data = {'term':self.curTerm,'type':'create','groupId':groupId,
                            'public':public.decode('latin1'),'private':encryptedPrivate,'members':members}
                    payload = self.makeMessagePayload(True,data)
                    if self.curLeader != -1 and network[self.id * 5 + self.curLeader] == '1':
                        self.socket.sendMessage(payload, clientIPs[self.curLeader])
                    else:
                        print("failed\nthe network currently is not available\n",flush=True)
                        break
                                        # what if clients does not have leader info, 感觉这样ok
                                        #for key in self.peers:
                                        #    if network[self.id * 5 + key] == '1':
                                        #        self.socket.sendMessage(payload, clientIPs[key])
                                        #        break

            elif args[0] == "add" and len(args)==3:
                groupId = tuple(map(int,args[1][1:-1].split(',')))
                index = self.keyManager.findGroupKey(groupId)
                if index == -1:
                    print("group key does not exist or hasn't been committed",flush=True)
                    continue
                clientId = int(args[2])
                packet = self.keyManager.encryptAndChunk(self.keyManager.clientKeys[clientId][1],self.keyManager.getPrivateGroupKey(index))
                if self.state == LEADER:
                    self.log.append({'term': self.curTerm, 'type': 'add','groupId':groupId,
                                     'public':self.keyManager.getPublicGroupKey(index).decode('latin1'),'private':packet,
                                     'member':clientId, 'committed': False})
                    self.lastLogIndex += 1
                    self.lastLogTerm = self.log[-1]['term']
                    self.writeJson()
                else:
                    with open("networkConfig.txt", "r") as fo:
                        network = fo.read()
                    data = {'term': self.curTerm, 'type': 'add','groupId':groupId,
                                     'public':self.keyManager.getPublicGroupKey(index).decode('latin1'),'private':packet,
                                     'member':clientId}
                    payload = self.makeMessagePayload(True,data)
                    if self.curLeader != -1 and network[self.id * 5 + self.curLeader] == '1':
                        self.socket.sendMessage(payload, clientIPs[self.curLeader])
                    else:
                        print("failed\nthe network currently is not available",flush=True)
                        break

            elif args[0] == "kick":
                groupId = tuple(map(int, args[1][1:-1].split(',')))
                index = self.keyManager.findGroupKey(groupId)
                if index == -1:
                    print("group key does not exist or hasn't been committed", flush=True)
                    continue
                clientId = int(args[2])

                members = self.group.getGroupMembers(groupId)
                if clientId not in members:
                    print("client Id: {} not in group {}".format(clientId,members),flush=True)
                    continue
                private, public = self.keyManager.makeGroupKey(groupId)
                #if kick twice, only the first one will be executed
                encryptedKey = []
                for member in members:
                    packet = self.keyManager.encryptAndChunk(self.keyManager.clientKeys[member][1],private)
                    encryptedKey.append(packet)
                if self.state == LEADER:
                    self.log.append({'term': self.curTerm, 'type': 'kick', 'groupId': groupId,
                                     'public': public.decode('latin1'), 'private': encryptedKey,
                                     'member': clientId, 'committed': False})
                    self.lastLogIndex += 1
                    self.lastLogTerm = self.log[-1]['term']
                    self.writeJson()
                else:
                    with open("networkConfig.txt", "r") as fo:
                        network = fo.read()
                    data = {'term': self.curTerm, 'type': 'kick', 'groupId': groupId,
                            'public': public.decode('latin1'), 'private': encryptedKey,
                                     'member': clientId }
                    payload = self.makeMessagePayload(True, data)
                    if self.curLeader != -1 and network[self.id * 5 + self.curLeader] == '1':
                        self.socket.sendMessage(payload, clientIPs[self.curLeader])
                    else:
                        print("failed\nthe network currently is not available", flush=True)
                        break
            elif args[0] == "printGroup":
                groupId = tuple(map(int, args[1][1:-1].split(',')))
                print("group ids are: {}".format(self.group.groupId))
                if self.group.isInGroup(groupId) is True:
                    print("group {} members {}".format(groupId, self.group.getGroupMembers(groupId)), flush=True)
                    print("messages: {}".format(self.group.getGroupMessages(groupId)), flush=True)
                elif self.invalidGroup.isInGroup(groupId) is True:
                    print("group {} members {}".format(groupId, self.invalidGroup.getGroupMembers(groupId)), flush=True)
                    print("messages: {}".format(self.invalidGroup.getGroupMessages(groupId)), flush=True)
                else:
                    print("group {} doesn't exsist".format(groupId), flush=True)
                    continue

            elif args[0] == 'fail':
                val_1 = int(args[1])
                val_2 = int(args[2])
                if val_1 >= 0 and val_1 < CLIENTNUM and val_2 >= 0 and val_2 < CLIENTNUM and val_1 != val_2:
                    with open("networkConfig.txt", "r+") as fo:
                        network = fo.read()
                        if network[val_1*5+val_2] == '1':
                            network = network[0:val_1*5+val_2]+'0'+network[val_1*5+val_2+1:]
                            network = network[0:val_2*5+val_1]+'0'+network[val_2*5+val_1+1:]
                            fo.seek(0, 0)
                            fo.write(network)
                    # fo.close()

            elif args[0] == 'fix':
                val_1 = int(args[1])
                val_2 = int(args[2])
                if val_1 >= 0 and val_1 < CLIENTNUM and val_2 >= 0 and val_2 < CLIENTNUM and val_1 != val_2:
                    with open("networkConfig.txt", "r+") as fo:
                        network = fo.read()
                        if network[val_1*5+val_2] == '0':
                            # str = fo.read()
                            network = network[0:val_1*5+val_2]+'1'+network[val_1*5+val_2+1:]
                            network = network[0:val_2*5+val_1]+'1'+network[val_2*5+val_1+1:]
                            fo.seek(0, 0)
                            fo.write(network)
            else:
                print("invalid instruction",flush=True)

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
