#!/usr/local/bin/python3
import logging
import select
import socket
import struct

logging.basicConfig(level=logging.INFO,
                    format="[%(asctime)s][%(levelname)s]%(message)s",
                    datefmt="%m-%d-%Y %I:%M:%S %p")

# constants
MAXSERVENTS = 10
SOCKETTIMEOUT = 4.0
MTU = 416  # keyflood/topoflood are the larger packets we implement
MESSAGETYPES = dict(
    ID=4,
    KEYREQ=5,
    TOPOREQ=6,
    KEYFLOOD=7,
    TOPOFLOOD=8,
    RESP=9)
MESSAGEHEADERS = dict(
    ID="!HH",
    KEYREQ="!HLH%ds",
    TOPOREQ="!HL",
    KEYFLOOD="!HHLLHH%ds",
    TOPOFLOOD="!HHLLHH%ds",
    RESP="!HLH%ds")


def messageFactory(typeNumber, **kwargs):
    """ Take a typeNumber and a given list of named arguments to build a
    human-readable message in json format
    """
    message = None
    try:
        if typeNumber == MESSAGETYPES["ID"]:
            message = dict(typeNumber=typeNumber,
                           port=kwargs.get("port"))
        elif typeNumber == MESSAGETYPES["KEYREQ"]:
            message = dict(typeNumber=typeNumber,
                           nseq=int(kwargs.get("nseq")),
                           size=int(kwargs.get("size")),
                           key=kwargs.get("key"))
        elif typeNumber == MESSAGETYPES["TOPOREQ"]:
            message = dict(typeNumber=typeNumber,
                           nseq=int(kwargs.get("nseq")))
        elif typeNumber in [MESSAGETYPES["KEYFLOOD"],
                            MESSAGETYPES["TOPOFLOOD"]]:
            message = dict(typeNumber=typeNumber,
                           ttl=int(kwargs.get("ttl")),
                           nseq=int(kwargs.get("nseq")),
                           sourceIp=kwargs.get("sourceIp"),
                           sourcePort=int(kwargs.get("sourcePort")),
                           size=int(kwargs.get("size")),
                           info=kwargs.get("info"))
        elif typeNumber == MESSAGETYPES["RESP"]:
            message = dict(typeNumber=typeNumber,
                           nseq=int(kwargs.get("nseq")),
                           size=int(kwargs.get("size")),
                           value=kwargs.get("value"))
        else:
            logging.warning("Invalid message typeNumber %d" % typeNumber)
    except (KeyError, TypeError) as err:
        logging.warning(err)
    return message


def pack(typeNumber, kwargs):
    """ Take a typeNumber and a given list of named arguments to pack a
    message to network byte format
    """

    def ipToInt(ip):
        return struct.unpack("!L", socket.inet_aton(ip))[0]

    if typeNumber not in MESSAGETYPES.values():
        return None

    elif typeNumber == MESSAGETYPES["ID"]:
        return struct.pack(MESSAGEHEADERS["ID"],
                           typeNumber,
                           kwargs["port"])
    elif typeNumber == MESSAGETYPES["KEYREQ"]:
        return struct.pack(MESSAGEHEADERS["KEYREQ"] % kwargs["size"],
                           typeNumber,
                           kwargs["nseq"],
                           kwargs["size"],
                           kwargs["key"].encode())
    elif typeNumber == MESSAGETYPES["TOPOREQ"]:
        return struct.pack(MESSAGEHEADERS["TOPOREQ"],
                           typeNumber,
                           kwargs["nseq"])
    elif typeNumber in [MESSAGETYPES["KEYFLOOD"], MESSAGETYPES["TOPOFLOOD"]]:
        return struct.pack(MESSAGEHEADERS["KEYFLOOD"] % kwargs["size"],
                           typeNumber,
                           kwargs["ttl"],
                           kwargs["nseq"],
                           ipToInt(kwargs["sourceIp"]),
                           kwargs["sourcePort"],
                           kwargs["size"],
                           kwargs["info"].encode())
    elif typeNumber == MESSAGETYPES["RESP"]:
        return struct.pack(MESSAGEHEADERS["RESP"] % kwargs["size"],
                           typeNumber,
                           kwargs["nseq"],
                           kwargs["size"],
                           kwargs["value"].encode())
    return None


def unpack(typeNumber, payload):
    """ Take a typeNumber and payload to decode a network byte message that
    came from a socket and build a message from it using messageFactory
    """

    def intToIp(intip):
        return socket.inet_ntoa(struct.pack("!L", intip))

    message = None
    try:
        if typeNumber == MESSAGETYPES["ID"]:
            headerLimit = struct.calcsize(MESSAGEHEADERS["ID"])
            unpacked = struct.unpack(MESSAGEHEADERS["ID"],
                                     payload[:headerLimit])
            message = messageFactory(MESSAGETYPES["ID"],
                                     port=unpacked[1])
        elif typeNumber == MESSAGETYPES["KEYREQ"]:
            dataSize = len(payload) \
                        - struct.calcsize(MESSAGEHEADERS["KEYREQ"] % 0)
            unpacked = struct.unpack(MESSAGEHEADERS["KEYREQ"] % dataSize,
                                     payload)
            message = messageFactory(MESSAGETYPES["KEYREQ"],
                                     nseq=unpacked[1],
                                     size=unpacked[2],
                                     key=unpacked[3].decode())
        elif typeNumber == MESSAGETYPES["TOPOREQ"]:
            headerLimit = struct.calcsize(MESSAGEHEADERS["TOPOREQ"])
            unpacked = struct.unpack(MESSAGEHEADERS["TOPOREQ"],
                                     payload[:headerLimit])
            message = messageFactory(MESSAGETYPES["TOPOREQ"],
                                     nseq=unpacked[1])
        elif typeNumber == MESSAGETYPES["KEYFLOOD"]:
            dataSize = len(payload) \
                       - struct.calcsize(MESSAGEHEADERS["KEYFLOOD"] % 0)
            unpacked = struct.unpack(MESSAGEHEADERS["KEYFLOOD"] % dataSize,
                                     payload)
            message = messageFactory(MESSAGETYPES["KEYFLOOD"],
                                     ttl=unpacked[1],
                                     nseq=unpacked[2],
                                     sourceIp=intToIp(unpacked[3]),
                                     sourcePort=unpacked[4],
                                     size=unpacked[5],
                                     info=unpacked[6].decode())
        elif typeNumber == MESSAGEHEADERS["TOPOFLOOD"]:
            dataSize = len(payload) \
                       - struct.calcsize(MESSAGEHEADERS["TOPOFLOOD"] % 0)
            unpacked = struct.unpack(MESSAGEHEADERS["TOPOFLOOD"] % dataSize,
                                     payload)
            message = messageFactory(MESSAGETYPES["TOPOFLOOD"],
                                     ttl=unpacked[1],
                                     nseq=unpacked[2],
                                     sourceIp=intToIp(unpacked[3]),
                                     sourcePort=unpacked[4],
                                     size=unpacked[5],
                                     info=unpacked[6].decode())
        elif typeNumber == MESSAGETYPES["RESP"]:
            dataSize = len(payload) \
                        - struct.calcsize(MESSAGEHEADERS["RESP"] % 0)
            unpacked = struct.unpack(MESSAGEHEADERS["RESP"] % dataSize,
                                     payload)
            message = messageFactory(MESSAGETYPES["RESP"],
                                     nseq=unpacked[1],
                                     size=unpacked[2],
                                     value=unpacked[3].decode())
    except struct.error:
        pass
    return message


def interact(sock, message):
    """ Encode and send a message to a given socket """
    try:
        encoded = pack(message["typeNumber"], message)
        sock.send(encoded)
        return True
    except (KeyError, TypeError, socket.error) as err:
        logging.warning(err)
    return False


class Servent:
    def __init__(self, ipaddr, port):
        self.ipaddr = ipaddr
        self.port = port
        self.sockList = list()
        self.peerList = dict()
        self.clientList = dict()
        self.services = dict()
        self.messageHistory = list()

    def loadKeys(self, path):
        """ Take a file and read its contents to memory into a dict """
        services = dict()
        success = False
        try:
            with open(path) as inputFile:
                for line in inputFile.readlines():
                    line = ''.join(line).strip(' ')
                    if line != "#" and not line.isspace():
                        splitted = line.replace('\t', ' ')\
                                       .replace('  ', ' ').split()
                        # Extracts service name
                        key = splitted[0]
                        # Service port, protocol and any more info
                        services[key] = " ".join(splitted[1:])
            self.services = services
            success = True
            logging.info("Keys loaded succesfully")
        except IOError as err:
            logging.warning(err)
        return success

    def getKey(self, key):
        """ Search for a key in local db """
        if key in self.services:
            return self.services[key]
        return None

    def propagate(self, message, ignorePeers=None):
        """ Send a given message to every peer connected with

        'ignorePeers' is used so a given message is not forwarded to the peer
        who sent it to us
        """
        for peer in self.peerList:
            if ignorePeers and self.peerList[peer] in ignorePeers:
                continue
            interact(self.peerList[peer], message)

    def findMessageType(self, payload):
        """ Test which message type has just arrived """
        messageType = struct.unpack("!H", payload[:2])[0]
        if messageType not in MESSAGETYPES.values():
            return None
        message = unpack(messageType, payload)
        if message:
            return message

    def getClient(self, sock):
        if not len(self.clientList):
            return None
        for client in self.clientList.keys():
            if self.clientList[client] == sock:
                return client

    def respondToKeyReq(self, sock, message):
        """ Look into local db for the requested key and generate a KEYFLOOD
        message to ask for the same key to the other peers
        """
        source = self.getClient(sock)
        if not source:
            logging.warning("Client not found in clientList")
            return
        logging.info("Received KEYREQ from client %s:%d" % (source[0],
                                                            source[1]))
        key = self.getKey(message["key"])
        if key:
            response = messageFactory(MESSAGETYPES["RESP"],
                                      nseq=message["nseq"],
                                      size=len(key),
                                      value=key)
            interact(self.clientList[source], response)
            logging.info("Response sent to client %s:%d with nseq %d"
                         % (source[0], source[1], message["nseq"]))

        keyflood = messageFactory(MESSAGETYPES["KEYFLOOD"],
                                  ttl=3,
                                  nseq=message["nseq"],
                                  sourceIp=source[0],
                                  sourcePort=source[1],
                                  size=message["size"],
                                  info=message["key"])
        self.propagate(keyflood)
        logging.info("KEYFLOOD message created and sent to peers")

    def respondToTopoReq(self, sock, message):
        """ Build a TOPOFLOOD message with my own address:port and send it
        to the next peers so they can append their address:port to the same
        """
        source = self.getClient(sock)
        if not source:
            logging.warning("Client not found in clientList")
            return
        logging.info("Received TOPOREQ from client %s:%d" % (source[0],
                                                             source[1]))
        trace = "%s:%s" % (self.ipaddr, self.port)
        response = messageFactory(MESSAGETYPES["RESP"],
                                  nseq=message["nseq"],
                                  size=len(trace),
                                  value=trace)
        interact(self.clientList[source], response)
        logging.info("Answer sent to %s:%s" % (source[0], source[1]))

        topoFlood = messageFactory(MESSAGETYPES["TOPOFLOOD"],
                                   ttl=3,
                                   nseq=message["nseq"],
                                   sourceIp=source[0],
                                   sourcePort=source[1],
                                   size=len(trace),
                                   info=trace)
        self.propagate(topoFlood)
        logging.info("TOPOFLOOD message created and sent to peers")

    def respondToTopoFlood(self, sock, message):
        """ A given TOPOFLOOD message should be checked in the messageHistory
        so it won't be answered twice

        Append my address:port to the message and send it to the next peers
        so they can do the same
        """
        t = tuple(
            [message["sourceIp"], message["sourcePort"], message["nseq"]])
        if t not in self.messageHistory:
            self.messageHistory.append(t)
            logging.info("Received TOPOFLOOD from client %s:%d"
                         % (message["sourceIp"], message["sourcePort"]))
            trace = "%s %s:%s" % (message["info"], self.ipaddr, self.port)
            message["size"] = len(trace)
            message["info"] = trace

            response = messageFactory(MESSAGETYPES["RESP"],
                                      nseq=message["nseq"],
                                      size=len(trace),
                                      value=trace)
            client = tuple([message["sourceIp"], message["sourcePort"]])
            responseSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            responseSocket.connect(client)
            interact(responseSocket, response)
            responseSocket.close()
            del responseSocket

        if message["ttl"] > 1:
            message["ttl"] -= 1
            self.propagate(message, ignorePeers=[sock])
            logging.info("TOPOFLOOD message forwarded to peers with TTL %d"
                         % message["ttl"])

    def respondToKeyFlood(self, sock, message):
        """ A given KEYFLOOD message should be checked in the messageHistory
        so it won't be answered twice

        Look into local db for the requested key and if it is found
        create a short living socket to answer directly to the client
        who has requested it. If the message TTL is higher than zero, also
        forward if to the other peers in the network, skipping the one which
        the message came from
        """
        t = tuple(
            [message["sourceIp"], message["sourcePort"], message["nseq"]])
        if t in self.messageHistory:
            return
        self.messageHistory.append(t)
        logging.info("Received KEYFLOOD from client %s:%d"
                     % (message["sourceIp"], message["sourcePort"]))
        key = self.getKey(message["info"])
        if key:
            response = messageFactory(MESSAGETYPES["RESP"],
                                      nseq=message["nseq"],
                                      size=len(key),
                                      value=key)
            client = tuple([message["sourceIp"], message["sourcePort"]])
            responseSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            responseSocket.connect(client)
            interact(responseSocket, response)
            logging.info("Response sent to client %s:%d with seqNum %d"
                         % (message["sourceIp"], message["sourcePort"],
                            message["nseq"]))
            responseSocket.close()
            del responseSocket

        if message["ttl"] > 1:
            message["ttl"] -= 1
            self.propagate(message, ignorePeers=[sock])
            logging.info("KEYFLOOD message forwarded to peers with TTL %d"
                         % message["ttl"])

    def run(self, servents=None):
        """ Main loop
        
        Expect servents to be a list of strings
        ["ipaddr:port", "ipaddr:port" ...]
        """
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.bind((self.ipaddr, self.port))
        self.sock.setblocking(0)
        self.sock.listen(MAXSERVENTS)
        self.sockList = [self.sock]

        # connect to every other servent in the network
        if servents:
            try:
                for s in servents:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    ipaddr, port = s.split(":")
                    sock.connect((ipaddr, int(port)))
                    message = messageFactory(MESSAGETYPES["ID"], port=0)
                    if interact(sock, message):
                        logging.info("ID sent to %s" % s)
                        self.sockList.append(sock)
                    else:
                        logging.warning("Error sending ID to servent %s" % s)
                        continue
            except socket.error as err:
                logging.warning(err)

        # this list will hold sockets from new peers who have not identified
        # themselves yet
        waitingID = dict()
        logging.info("Waiting for connections at port %d" % self.port)
        while True:
            readable, _, _ = select.select(self.sockList, [], [], 0)
            for sock in readable:
                try:
                    # a new servent/client has arrived
                    if sock == self.sock:
                        # -1 because the servent socket itself is also in
                        # self.sockList
                        if len(self.sockList) - 1 < MAXSERVENTS:
                            newSock, addr = sock.accept()
                            logging.info("New connection from %s:%d"
                                         % (addr[0], addr[1]))
                            newSock.setblocking(0)
                            peerTuple = tuple([addr[0], addr[1]])
                            if peerTuple not in waitingID.keys() \
                                    and peerTuple not in self.clientList.keys():
                                waitingID[peerTuple] = newSock
                            self.sockList.append(newSock)
                            continue
 
                    payload = sock.recv(MTU)
                    if not payload:
                        continue
 
                    message = self.findMessageType(payload)
                    if message["typeNumber"] == MESSAGETYPES["ID"]:
                        if not len(waitingID):
                            continue
 
                        whosTalking = None
                        for peer in waitingID:
                            if sock == waitingID[peer]:
                                whosTalking = peer
                                break
                        if not whosTalking:
                            continue
 
                        if message["port"] == 0:
                            self.peerList[whosTalking[0]] = sock
                            logging.info("ID message from peer %s"
                                         % whosTalking[0])
                        else:
                            clientTuple = tuple([whosTalking[0],
                                                 message["port"]])
                            self.clientList[clientTuple] = sock
                            logging.info("ID message from client %s:%d"
                                         % (clientTuple[0],
                                            clientTuple[1]))
                        # remove identified peer from waitingID list
                        del waitingID[whosTalking]
                    elif message["typeNumber"] == MESSAGETYPES["KEYREQ"]:
                        self.respondToKeyReq(sock, message)
                    elif message["typeNumber"] == MESSAGETYPES["TOPOREQ"]:
                        self.respondToTopoReq(sock, message)
                    elif message["typeNumber"] == MESSAGETYPES["KEYFLOOD"]:
                        self.respondToKeyFlood(sock, message)
                    elif message["typeNumber"] == MESSAGETYPES["TOPOFLOOD"]:
                        self.respondToTopoFlood(sock, message)
                except socket.error as err:
                    logging.warning(err)
                    if sock != self.sock:
                        self.sockList.remove(sock)


class Client:
    def __init__(self, ipaddr, port):
        self.ipaddr = ipaddr
        self.port = port
        self.nseq = 0
        self.sock = None
        self.serventSock = None

    def fetchMessages(self):
        """ Try to fetch any message from the client socket using a timeout.
        If an connection is detected, accept and receive its data, then parse
        it in order to (luckly) get a RESP message """
        self.sock.settimeout(SOCKETTIMEOUT)
        try:
            sock, servent = self.sock.accept()
            payload = sock.recv(MTU)
            self.sock.settimeout(None)
            if not payload:
                return 0, None
            message = unpack(MESSAGETYPES["RESP"], payload)
            if not message:
                return 1, None
            sock.close()
            return 2, message
        except socket.timeout:
            return 0, None
        except socket.error as err:
            logging.warning(err)
            return 3, None

    def sendKeyReq(self, key):
        """ Create a KEYREQ message and send to servent """
        message = messageFactory(MESSAGETYPES["KEYREQ"],
                                 nseq=self.nseq,
                                 size=len(key),
                                 key=key)
        if interact(self.serventSock, message):
            logging.info("Sent KEYREQ for key %s" % key)
            return self.nseq
        else:
            logging.warning("Error sending KEYREQ")
            return None

    def sendTopoReq(self):
        """ Create a TOPOREQ message and send to servent """
        message = messageFactory(MESSAGETYPES["TOPOREQ"],
                                 nseq=self.nseq)
        if interact(self.serventSock, message):
            logging.info("TOPOREQ sent to servent")
        else:
            logging.warning("Error sending TOPOREQ")

    def run(self, servent):
        """ Main loop

        Expects servent to be tuple(ipaddr:port
        """
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.serventSock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        logging.info("Initializing client at %s:%d" % (self.ipaddr, self.port))
        try:
            # create a ID message and identify to servent as a client
            helloMessage = messageFactory(MESSAGETYPES["ID"], port=self.port)
            if not helloMessage:
                logging.error("Error creating ID message")
                return
            self.serventSock.connect(servent)
            if interact(self.serventSock, helloMessage):
                logging.info("ID sent to servent")
            else:
                logging.warning("Error sending ID")
                return
        except socket.error:
            logging.error("Could not connect to servent (%s:%d)"
                          % (servent[0], servent[1]))
            return

        self.sockList = [self.sock, self.serventSock]
        self.sock.bind((self.ipaddr, self.port))
        self.sock.listen(1)

        while True:
            line = input()
            # end execution
            if line == "" or line[0] == "Q":
                logging.info("Bye =)")
                break
            # query for some key
            elif line[0] == "?":
                if line[1] != ' ':
                    logging.error(
                        "Invalid query format, please put at least one space "
                        "between question mark and the desired key")
                    continue
                key = line[2:].strip()
                if len(key) > 400:
                    logging.warning("Info is larger than 400 characters")
                    continue
                self.sendKeyReq(key)
            # topology request
            elif line.strip() == "T":
                self.sendTopoReq()
            else:
                logging.warning("Unknown command")
                continue

            # try to fetch responses from any servent
            responseCount = 0
            while True:
                responseCode, message = self.fetchMessages()
                # 0 - No data
                # 1 - Invalid Message
                # 2 - Valid message
                # 3 - Any king of error
                if responseCode == 0:
                    if not responseCount:
                        logging.warning("No data received")
                    break
                elif responseCode == 1:
                    logging.warning("Invalid packet received from %s:%s"
                                    % (servent[0], servent[1]))
                elif responseCode == 2 and self.nseq == message["nseq"]:
                    responseCount += 1
                    logging.info("%s %s:%s"
                                 % (message["value"], servent[0], servent[1]))
                else:
                    break
            self.nseq += 1
        self.sock.close()
        self.serventSock.close()
