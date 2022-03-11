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

def argParse(string):
    return string.split("[ ]*")


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

class KeyManager:

    def __init__(self,id):
        self.id = id
        self.counter = 0
        self.groupKeyPair = []# [(),()]
        self.clientKeys = []#(ID,Publickey)
        self.dirname = "keystorage"+str(id)
        self.privateKeyName = "private"+str(id)+".pem"
        self.publicKeyName = "public"+str(id)+".pem"

        if os.path.exists(self.dirname+"/"+self.privateKeyName) == True:
            priv = open(self.dirname+"/"+self.privateKeyName,"rb")
            self.privateKey = serialization.load_pem_private_key(priv.read(), password=None)
            priv.close()
        else:
            self.privateKey = rsa.generate_private_key(65547, 1024)
            pem = self.privateKey.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
            f = open(self.privateKeyName, "wb")
            f.write(pem)
            f.close()

        if os.path.exists(self.dirname+"/"+self.publicKeyName) == True:
            pub = open(self.dirname+"/"+self.publicKeyName,"rb")
            self.publicKey = serialization.load_pem_public_key(pub.read())
            pub.close()
        else:
            self.publicKey = self.privateKey.public_key()
            pem = self.publicKey.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo)
            f = open("public"+str(id)+".pem","rb")
            f.write(pem)
            f.close()
        self.readClientKey()

        if(os.path.isdir("keystorage"+str(id))==False):
            os.makedirs("keystorage"+str(id))

    def getPublicKey(self):
        return self.publicKey.public_bytes(encoding=serialization.Encoding.PEM,
                                               format=serialization.PublicFormat.SubjectPublicKeyInfo)
    def getPrivateKey(self):
        return self.privateKey.private_bytes(encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption())

    def writeClientKey(self,id):
        with open(self.dirname+"/"+str(id)+"public"+str(id)+".pem","wb") as f:
            pem = self.clientKeys[id].public_bytes(encoding=serialization.Encoding.PEM,format=serialization.PublicFormat.SubjectPublicKeyInfo)
            f.write(pem)
            #self.clientKeys[id] =

    def readClientKey(self):
        for i in CLIENTNUM:
            if os.path.exists(self.dirname + "/" + "public" + str(i) + ".pem") == True:
                f = open(self.dirname + "/" + "public" + str(i) + ".pem","rb")
                self.clientKeys.append(serialization.load_pem_public_key(f.read()))
            else:
                self.clientKeys.append(None)

    def makeGroupKey(self):
        private = rsa.generate_private_key(65547,1024)
        public = private.public_key()
        id = (self.id,self.counter)
        self.groupKeyPair.append((id,public,private))
        return id,private.private_bytes(encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()),public.public_bytes(encoding=serialization.Encoding.PEM,format=serialization.PublicFormat.SubjectPublicKeyInfo)

    def findGroupKey(self, id):
        for i in range(len(self.groupKeyPair)):
            if self.groupKeyPair[i][0] == id:
                return i
        return -1

    def addGroupKey(self,id,publicByte,privateByte):
        public = serialization.load_pem_public_key(publicByte)
        private = serialization.load_pem_private_key(privateByte, password=None)
        self.groupKeyPair.append((id,public,private))

    def makeValidation(self,publicKey):
        return publicKey.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo)

class Client:
    def __init__(self, id, mode):
        self.id = id
        self.socket = UDPSocket(id)
        self.mode = mode
        self.keyManager = KeyManager(id)
        self.initKey = False
        self.lock = threading.Lock()
        # log structure:
        # [{'term': 1, 'type': 'message', 'message': '0000', 'committed': True}, 
        # {'term': 2, 'type': 'message', 'message': '111111111', 'committed': True}, 
        # {'term': 2, 'type': 'message', 'message': '000000000', 'committed': True}, 
        # {'term': 4, 'type': 'message', 'message': '222222222', 'committed': False}, 
        # {'term': 4, 'type': 'message', 'message': '33333333333', 'committed': False}]
        self.groupCounter = 0
        self.log = []
        self.readJson()
        
        if len(self.log):
            self.lastLogIndex = len(self.log)
            self.lastLogTerm = self.log[-1]['term']
        else:
            self.lastLogIndex = 0
            self.lastLogTerm = 0

        self.curTerm = self.lastLogTerm
        self.state = FOLLOWER  # Follower
        self.electionTimeout = random.randint(10, 20)
        self.curLeader = -1
        self.votedFor = -1
        # self.log = []
        # self.readJson()
        self.commitIndex = 0
        for i in range(len(self.log) - 1, -1, -1):
            if self.log[i]['committed']:
                self.commitIndex = i + 1
                break
        # self.messageSent = False
        self.HeardFromLeader = False

        # peers structure:
        # {0: {'next index': 1, 'match index': 0, 'vote granted': False},
        #  1: {'next index': 1, 'match index': 0, 'vote granted': False},
        #  3: {'next index': 1, 'match index': 0, 'vote granted': False},
        #  4: {'next index': 1, 'match index': 0, 'vote granted': False}}
        self.peers = {}

        print("***TERM {}***".format(self.curTerm))
    def createGroup:

    def addMember2Group:
    def kickMember:
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
                time.sleep(self.electionTimeout)
                with self.lock:
                    if self.state == FOLLOWER and not self.HeardFromLeader:
                        self.startElection()

            if self.state == CANDIDATE:
                self.HeardFromLeader = False
                time.sleep(self.electionTimeout)
                # Election timeout elapses without election resolution:
                # increment term, start new election
                with self.lock:
                    if self.state == CANDIDATE and not self.HeardFromLeader:
                        self.startElection()

            # Send initial empty AppendEntries RPCs (heartbeat) to each
            # follower; repeat during idle periods to prevent election timeouts
            if self.state == LEADER:
                self.heartbeat()
                time.sleep(self.heartbeatTimeout)
                print("****peers status:")
                print(self.peers)

            print("***log:")
            print(self.log)

    # TODO: 感觉reset之后要打断timeout thread重新开始？找不到restart thread的办法
    def resetTimeout(self):
        self.electionTimeout = random.randint(10, 20)

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
        self.heartbeatTimeout = random.randint(8, 10)
        # self.messageSent = False
        for key in self.peers:
            self.peers[key]['next index'] = self.lastLogIndex + 1

    ### added two functions
    def SHA256(self,object):
        strings = json.dumps(object)
        res = hashlib.sha256(strings)
        return res.hexdigest()
    # client standard payload {id,op,entrypt,data{term,type,entry},SHA(data)}
    def makeMessagePayload(self,encrypt, type, entry, key):
        data = {'term': self.curTerm, 'type':type,'entry': entry}
        if key == None:
            payload = {'id': self.id, 'op': MESSAGE, 'encrypt': encrypt, 'data': data,
                       'SHA': self.SHA256(data)}
        else:
            payload = {'id': self.id,'op': MESSAGE,'encrypt':encrypt,'data': key.encrypt(data),
                       'SHA':self.SHA256(data)}
        return payload


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
                if self.curTerm == data['data']['term']:
                    if self.votedFor != -1 or self.lastLogTerm > data['data']['lastLogTerm'] or (self.lastLogTerm == data['data']['lastLogTerm'] and self.lastLogIndex > data['data']['lastLogIndex']):
                        payload = {'id': self.id, 'op': RESPONDELECTION,
                                   'data': {'term': self.curTerm, 'voteGranted': False}}
                    else:
                        self.votedFor = data['id']
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
                            # [{'term': 1, 'type': 'keypublish', 'message': (id,keybits), 'committed': False},
                            if self.initKey == False:
                                self.log.append(
                                    {'term': self.curTerm, 'type': 'keypublish', 'message': (self.id,self.keyManager.getPublicKey()), 'committed': False})
                                self.lastLogIndex += 1
                                self.lastLogTerm = self.log[-1]['term']
                                self.writeJson()
                                self.initKey = True

            if data['op'] == APPEND:
                flag = 0 # indicate whether could be send a keypublish message
                print("{} received APPEND from {} with tag {}".format(
                    self.id, data['id'], data['data']))
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
                            self.lastLogIndex = len(self.log)
                            self.lastLogTerm = self.log[-1]['term']

                        if data['data']['commitIndex'] >= self.lastLogIndex:
                            for j in range(self.commitIndex+1, self.lastLogIndex+1):
                                self.log[j-1]['committed'] = True
                            self.commitIndex = self.lastLogIndex
                        else:
                            for j in range(self.commitIndex+1, data['data']['commitIndex']+1):
                                self.log[j-1]['committed'] = True
                            self.commitIndex = data['data']['commitIndex']
                        payload = {'id': self.id, 'op': RESPONDAPPEND,
                                   'data': {'term': self.curTerm, 'match index': self.lastLogIndex, 'success': True}}
                    
                self.writeJson()

                with open("networkConfig.txt", "r") as fo:
                    network = fo.read()
                if network[self.id*5+data['id']]=='1':
                    self.socket.sendMessage(payload, clientIPs[data['id']])
                if flag == 1 and self.initKey == False:
                    self.initKey = True
                    payload = self.makeMessagePayload(0,'keypublish',(self.id,self.keyManager.getPublicKey()),None)
                    if network[self.id * 5 + data['id']] == '1':
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
                    self.log.append(
                        {'term': self.curTerm, 'type': data['data']['type'], 'message': data['data']['entry'], 'committed':False})
                    self.lastLogIndex += 1
                    self.lastLogTerm = self.log[-1]['term']
                    self.writeJson()

                # resend to leader
                elif self.curLeader != -1 and network[self.id*5+self.curLeader]=='1':
                    self.socket.sendMessage(data, clientIPs[self.curLeader])
                else:
                    # TODO: what if clients does not have leader info (random send currently)
                    for key in self.peers:
                        if network[self.id*5+key] == '1':
                            self.socket.sendMessage(data, clientIPs[key])
                            break
            if data['op'] == REQUESTKEY:

    #leader log entry term,type,entryval,commit

    def read(self):
        val = 0
        while(1):
            val = input("May I help you? (help to see available instructions): \n")
            args = argParse(val)
            if args[0] == "help" or args[0] == 'h':
                print("--------------------------------------")
                print("writing message: w [message] [groupId]")
                print("create Group: createGroup （[processId],[counter]) [clientId] [clientId]...")
                print("add member: add [groupId] [clientId]")
                print("kick member: kick [groupId] [clientId]")
                print("print group: printGroup [groupId]")
                print("fail link: failLink [clientId] [clientId]")
                print("fix link: fixLink [clientId] [clientId]")
                print("fail process: ctrl C will be used")
                print("--------------------------------------")
            if args[0] == 'w' and len(args) == 3:
                val = args[1]
                groupId = int(args[2])

                if self.state == LEADER:
                    self.log.append({'term': self.curTerm, 'type': 'message', 'message': val, 'committed': False})
                    self.lastLogIndex += 1
                    self.lastLogTerm = self.log[-1]['term']
                    self.writeJson()
                else:
                    with open("networkConfig.txt", "r") as fo:
                        network = fo.read()

                    index = self.keyManager.findGroupKey((self.id, groupId))
                    if index == -1:
                        print("I am not in that group",flush=True)
                        continue
                    if groupId != 0:
                        val = self.keyManager.groupKeyPair[index][1].encrypt(val)
                        validation = self.keyManager.makeValidation(self.keyManager.groupKeyPair[index][1])
                        validation = self.keyManager.groupKeyPair[index][1].encrypt(validation)
                        payload = {'id': self.id, 'op': MESSAGE, 'encrypt': 1,
                                   'data': {'term': self.curTerm, 'entry': val, 'valid': validation}}
                    else:
                        payload = {'id': self.id, 'op': MESSAGE, 'encrypt': 0,
                                   'data': {'term': self.curTerm, 'entry': val}}
                    if self.curLeader != -1 and network[self.id*5+self.curLeader] == '1':
                        self.socket.sendMessage(payload, clientIPs[self.curLeader])
                    else:
                        # what if clients does not have leader info, 感觉这样ok
                        for key in self.peers:
                            if network[self.id*5+key] == '1':
                                self.socket.sendMessage(payload, clientIPs[key])
                                break

            elif args[0] == "createGroup" and len(args)>2:
                groupId, private, public = self.keyManager.makeGroupKey()
                with open("networkConfig.txt", "r+") as fo:
                    network = fo.read()
                threads = []
                for index in range(1,len(args)):
                    clientId = int(args[index])
                    if clientId>(CLIENTNUM-1):
                        print("invalid client index {}".format(clientId),flush=True)
                        break
                    threads.append(threading.Thread(target=self.checkPublicKeyandSend,args=(network,clientId,groupId,private,public)))

            elif val == "add":

            elif val == "kick":

            elif val == "printGroup":

            elif val == 'fail':
                val = input("2 link ids:")
                val_1 = int(val.split()[0])
                val_2 = int(val.split()[1])
                if val_1 >= 0 and val_1 < CLIENTNUM and val_2 >= 0 and val_2 < CLIENTNUM and val_1 != val_2:
                    with open("networkConfig.txt", "r+") as fo:
                        network = fo.read()
                        if network[val_1*5+val_2] == '1':
                            network = network[0:val_1*5+val_2]+'0'+network[val_1*5+val_2+1:]
                            network = network[0:val_2*5+val_1]+'0'+network[val_2*5+val_1+1:]
                            fo.seek(0, 0)
                            fo.write(network)
                    # fo.close()

            elif val == 'fix':
                val = input("2 link ids:")
                val_1 = int(val.split()[0])
                val_2 = int(val.split()[1])
                if val_1 >= 0 and val_1 < CLIENTNUM and val_2 >= 0 and val_2 < CLIENTNUM and val_1 != val_2:
                    with open("networkConfig.txt", "r+") as fo:
                        network = fo.read()
                        if network[val_1*5+val_2] == '0':
                            # str = fo.read()
                            network = network[0:val_1*5+val_2]+'1'+network[val_1*5+val_2+1:]
                            network = network[0:val_2*5+val_1]+'1'+network[val_2*5+val_1+1:]
                            fo.seek(0, 0)
                            fo.write(network)
                   
    def checkPublicKeyandSend(self,network,id,groupId,private,public):
        if network[self.id * 5 + id] == '1':
            with self.lock:
                if self.keyManager.clientKeys[id] == None:
                    payload = {'id': self.id, 'op': REQUESTKEY, 'encrypt': 0, 'data': {self.keyManager.getPublicKey()}}
                    self.broadcast(payload)
                else:
                    validation = self.keyManager.makeValidation(self.keyManager.groupKeyPair[id][1])
                    validation = self.keyManager.groupKeyPair[id][1].encrypt(validation)
                    payload = {'id': self.id, 'op': CREATEGROUP, 'encrypt': 1,
                               'data': {'private': self.keyManager.clientKeys[id][1].encrypt(private), 'public': public,
                                        'groupId': groupId, 'valid': validation}}
                    self.socket.sendMessage(payload,clientIPs[id])

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
