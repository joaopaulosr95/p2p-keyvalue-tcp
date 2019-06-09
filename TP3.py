#!/usr/local/bin/python3
import json
import logging
import select
import socket
import struct

logging.basicConfig(level=logging.INFO,
                    format="[%(asctime)s][%(levelname)s]%(message)s",
                    datefmt="%m-%d-%Y %I:%M:%S %p")

# constants
MAXSERVENTS = 10
SOCKETTIMEOUT = 4
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
    KEYREQ="!HLH",
    TOPOREQ="!HL",
    KEYFLOOD="!HHLLHH",
    TOPOFLOOD="!HHLLHH",
    RESP="!HLH")


def messageFactory(typeNumber, **kwargs):
    """ Take a typeNumber and a given list of named arguments to build a
    human-readable message in json format
    """
    try:
        if typeNumber == MESSAGETYPES["ID"]:
            return json(typeNumber=typeNumber,
                        port=kwargs.get("port"))
        elif typeNumber == MESSAGETYPES["KEYREQ"]:
            return json(typeNumber=typeNumber,
                        nseq=kwargs.get("nseq"),
                        size=kwargs.get("size"),
                        key=kwargs.get("key"))
        elif typeNumber == MESSAGETYPES["TOPOREQ"]:
            return json(typeNumber=typeNumber,
                        nseq=kwargs.get("nseq"))
        elif typeNumber in [MESSAGETYPES["KEYFLOOD"],
                            MESSAGETYPES["TOPOFLOOD"]]:
            return json(typeNumber=typeNumber,
                        ttl=kwargs.get("ttl"),
                        nseq=kwargs.get("nseq"),
                        sourceIp=kwargs.get("sourceIp"),
                        sourcePort=kwargs.get("sourcePort"),
                        size=kwargs.get("size"),
                        info=kwargs.get("info"))
        elif typeNumber == MESSAGETYPES["RESP"]:
            return json(typeNumber=typeNumber,
                        nseq=kwargs.get("nseq"),
                        size=kwargs.get("size"),
                        value=kwargs.get("value"))
        logging.warning("Invalid message typeNumber %d" % typeNumber)
    except (json.JSONDecodeError, KeyError) as exc:
        logging.warning(exc)
    return None


def pack(typeNumber, **kwargs):
    """ Take a typeNumber and a given list of named arguments to pack a
    message to network byte format
    """

    def ipToInt(ip):
        return struct.unpack("!L", socket.inet_aton(ip))[0]

    if typeNumber not in range(4, 10):
        return None

    info = kwargs.get("info", None)
    if info and len(info) > 400:
        logging.warning("Info is larger than 400 characters")
        return None

    if typeNumber == MESSAGETYPES["ID"]:
        return struct.pack(MESSAGEHEADERS["ID"],
                           typeNumber,
                           kwargs.get("port"))
    elif typeNumber == MESSAGETYPES["KEYREQ"]:
        return struct.pack(MESSAGEHEADERS["KEYREQ"],
                           typeNumber,
                           kwargs.get("nseq"),
                           kwargs.get("size")) + kwargs.get("key")
    elif typeNumber == MESSAGETYPES["TOPOREQ"]:
        return struct.pack(MESSAGEHEADERS["TOPOREQ"],
                           typeNumber,
                           kwargs.get("nseq"))
    elif typeNumber in [MESSAGETYPES["KEYFLOOD"], MESSAGETYPES["TOPOFLOOD"]]:
        return struct.pack(MESSAGEHEADERS["KEYFLOOD"],
                           typeNumber,
                           kwargs.get("ttl"),
                           kwargs.get("nseq"),
                           ipToInt(kwargs.get("sourceIp")),
                           kwargs.get("sourcePort"),
                           kwargs.get("size")) + kwargs.get("info")
    elif typeNumber == MESSAGETYPES["RESP"]:
        return struct.pack(MESSAGEHEADERS["RESP"],
                           typeNumber,
                           kwargs.get("nseq"),
                           kwargs.get("size")) + kwargs.get("value")
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
                                     port=unpacked[0])
        elif typeNumber == MESSAGETYPES["KEYREQ"]:
            headerLimit = struct.calcsize(MESSAGEHEADERS["KEYREQ"])
            unpacked = struct.unpack(MESSAGEHEADERS["KEYREQ"],
                                     payload[:headerLimit])
            message = messageFactory(MESSAGETYPES["KEYREQ"],
                                     nseq=unpacked[0],
                                     size=unpacked[1],
                                     key=payload[headerLimit + 1:])
        elif typeNumber == MESSAGETYPES["TOPOREQ"]:
            headerLimit = struct.calcsize(MESSAGEHEADERS["TOPOREQ"])
            unpacked = struct.unpack(MESSAGEHEADERS["TOPOREQ"],
                                     payload[:headerLimit])
            message = messageFactory(MESSAGETYPES["TOPOREQ"],
                                     nseq=unpacked[0])
        elif typeNumber == MESSAGETYPES["KEYFLOOD"]:
            headerLimit = struct.calcsize(MESSAGEHEADERS["KEYFLOOD"])
            unpacked = struct.unpack(MESSAGEHEADERS["KEYFLOOD"],
                                     payload[:headerLimit])
            message = messageFactory(MESSAGETYPES["KEYFLOOD"],
                                     ttl=unpacked[0],
                                     nseq=unpacked[1],
                                     sourceIp=intToIp(unpacked[2]),
                                     sourcePort=unpacked[3],
                                     size=unpacked[4],
                                     info=payload[headerLimit + 1:])
        elif typeNumber == MESSAGEHEADERS["TOPOFLOOD"]:
            headerLimit = struct.calcsize(MESSAGEHEADERS["TOPOFLOOD"])
            unpacked = struct.unpack(MESSAGEHEADERS["TOPOFLOOD"],
                                     payload[:headerLimit])
            message = messageFactory(MESSAGETYPES["TOPOFLOOD"],
                                     ttl=unpacked[0],
                                     nseq=unpacked[1],
                                     sourceIp=intToIp(unpacked[2]),
                                     sourcePort=unpacked[3],
                                     size=unpacked[4],
                                     info=payload[headerLimit+1:])
        elif typeNumber == MESSAGETYPES["RESP"]:
            headerLimit = struct.calcsize(MESSAGEHEADERS["RESP"])
            unpacked = struct.unpack(MESSAGETYPES["RESP"],
                                     payload[:headerLimit])
            message = messageFactory(MESSAGETYPES["RESP"],
                                     nseq=unpacked[0],
                                     size=unpacked[1],
                                     value=payload[headerLimit + 1:])
    except struct.error:
        pass
    return message


def interact(sock, message):
    """ Encode and send a message to a given socket """
    try:
        encoded = pack(message)
        sock.send(encoded)
        return True
    except socket.error as err:
        logging.warning(err)
    return False


class Servent:
    def __init__(self, ipaddr, port):
        self.ipaddr = ipaddr
        self.port = port
        self.clientList = set()
        self.sockList = list()
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
        for sock in self.sockList:
            if sock == self.sock or (ignorePeers and sock in ignorePeers):
                continue
            interact(sock, message)

    def findMessageType(self, payload):
        """ Test which message type has just arrived """
        for messageType in MESSAGETYPES:
            message = unpack(messageType, payload)
            if message:
                return message

    def getClient(self, sock):
        clients = filter(lambda c: c[2] == sock, self.clientList)
        if len(clients) == 0:
            return None
        return clients[0]

    def respondToKeyReq(self, sock, message):
        """ Look into local db for the requested key and generate a KEYFLOOD
        message to ask for the same key to the other peers
        """
        source = self.getClient(sock)
        if not source:
            logging.warning("Client not found in clientList")
            return

        key = self.getKey(message["key"])
        if key:
            response = messageFactory(MESSAGETYPES["RESP"],
                                      nseq=message["nseq"],
                                      size=len(key),
                                      value=key)
            interact(sock, response)
            logging.info("Answer sent to %s:%s" % (source[0], source[1]))

        keyflood = messageFactory(MESSAGETYPES["KEYFLOOD"],
                                  ttl=3,
                                  nseq=message["nseq"],
                                  sourceIp=source[0],
                                  sourcePort=source[1],
                                  size=message["size"],
                                  info=message["key"])
        self.propagate(keyflood)

    def respondToTopoReq(self, sock, message):
        """ Build a TOPOFLOOD message with my own address:port and send it
        to the next peers so they can append their address:port to the same
        """
        source = self.getClient(sock)
        if not source:
            logging.warning("Client not found in clientList")
            return

        trace = "%s:%s" % (self.ipaddr, self.port)
        response = messageFactory(MESSAGETYPES["RESP"],
                                  nseq=message["nseq"],
                                  size=len(trace),
                                  value=trace)
        interact(sock, response)
        logging.info("Answer sent to %s:%s" % (source[0], source[1]))

        topoFlood = messageFactory(MESSAGETYPES["TOPOFLOOD"],
                                   ttl=3,
                                   nseq=message["nseq"],
                                   sourceIp=source[0],
                                   sourcePort=source[1],
                                   size=len(trace),
                                   info=trace)
        self.propagate(topoFlood)

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

            trace = "%s %s:%s" % (message["info"], self.ipaddr, self.port)
            message["size"] = len(trace)
            message["info"] = trace

            response = messageFactory(MESSAGETYPES["RESP"],
                                      nseq=message["nseq"],
                                      size=len(trace),
                                      value=trace)
            client = tuple(message["sourceIp"], message["sourcePort"])
            responseSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            responseSocket.connect(client)
            interact(responseSocket, response)
            responseSocket.close()
            del responseSocket

        if message["ttl"] > 1:
            message["ttl"] -= 1
            self.propagate(message, ignorePeers=[sock])

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

        key = self.getKey(message["key"])
        if key:
            response = messageFactory(MESSAGETYPES["RESP"],
                                      nseq=message["nseq"],
                                      size=len(key),
                                      value=key)
            client = tuple([message["sourceIp"], message["sourcePort"]])
            responseSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            responseSocket.connect(client)
            interact(responseSocket, response)
            responseSocket.close()
            del responseSocket

        if message["ttl"] > 1:
            message["ttl"] -= 1
            self.propagate(message, ignorePeers=[sock])

    def run(self, servents=None):
        """ Expect servents to be a list of strings
        ["ipaddr:port", "ipaddr:port" ...]
        """
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.bind((self.ipaddr, self.port))
        self.sock.listen()
        self.sockList = [self.sock]

        # connect to every other servent in the network
        if servents:
            try:
                for s in servents:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    ipaddr, port = s.split(":")
                    sock.connect((ipaddr, int(port)))
                    message = messageFactory(MESSAGETYPES["ID"], port=0)
                    interact(sock, message)
                    self.sockList.append(sock)
                    logging.info("Connected to peer %s" % s)
            except socket.error as err:
                logging.warning(err)

        logging.info("Waiting for connections at port %d" % self.port)
        while True:
            readable, _, _ = select.select(self.sockList, [], [], 0)
            for sock in readable:
                try:
                    # a new servent/client has arrived, so we expect it to
                    # send an ID message
                    if sock == self.sock:
                        # -1 because the servent socket itself is also in
                        # self.sockList
                        if len(self.sockList) - 1 < MAXSERVENTS:
                            sock, addr = self.sock.accept()
                            payload = sock.recv(MTU)
                            message = unpack(MESSAGETYPES["ID"], payload)
                            if not message:
                                logging.warning("Invalid ID message from %s:%s"
                                                % (addr[0], addr[1]))
                            # new client
                            if message["port"] == 0:
                                self.peerList.add(addr[0], addr[1], sock)
                                logging.info("Client %s has arrived" % addr)
                            # new servent
                            else:
                                self.clientList.add(addr[0], addr[1], sock)
                                logging.info("Servent %s has arrived" % addr)
                            continue

                    payload = sock.recv(MTU)
                    message = self.findMessageType(payload)
                    if message["typeNumber"] in MESSAGETYPES["KEYREQ"]:
                        self.respondToKeyReq(sock, message)
                    elif message["typeNumber"] == MESSAGETYPES["TOPOREQ"]:
                        self.respondToTopoReq(sock, message)
                    elif message["typeNumber"] in MESSAGETYPES["KEYFLOOD"]:
                        self.respondToKeyFlood(sock, message)
                    elif message["typeNumber"] in MESSAGETYPES["TOPOFLOOD"]:
                        self.respondToTopoFlood(sock, message)
                except socket.error as err:
                    logging.warning(err)
                    if sock != self.sock:
                        self.sockList.remove(sock)


class Client:
    def __init__(self, port):
        self.port = port
        self.nseq = 0
        self.sock = None
        self.serventSock = None

    def fetchMessages(self, sock):
        self.sock.settimeout(SOCKETTIMEOUT)
        sock, servent = self.sock.accept()
        try:
            payload = sock.recv(MTU)
            self.sock.settimeout(None)
            if payload:
                message = unpack(MESSAGETYPES["RESP"], payload)
                if not message:
                    responseCode, contents = 1, None
                responseCode, contents = 2, message
        except socket.timeout:
            responseCode, contents = 0, None
        except socket.error as err:
            logging.warning(err)
            responseCode, contents = 3, None
        try:
            sock.close()
        except socket.error:
            pass
        return responseCode, contents

    def sendKeyReq(self, key):
        # create a KEYREQ message and send to servent
        message = messageFactory(MESSAGETYPES["KEYREQ"],
                                 nseq=self.nseq,
                                 size=len(key),
                                 key=key)
        interact(self.serventSock, message)

    def sendTopoReq(self):
        message = messageFactory(MESSAGETYPES["TOPOREQ"],
                                 nseq=self.nseq)
        interact(self.serventSock, message)

    def run(self, servent):
        """ Expects servent to be tuple(ipaddr:port """
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.serventSock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        try:
            self.serventSock.connect(servent)
            # create a ID message and identify to servent as a client
            message = messageFactory(MESSAGETYPES["ID"], port=self.port)
            self.sockinteract(self.serventSock, message)
            self.nseq += 1
        except socket.error:
            logging.warning("Could not connect to servent (%s:%d)"
                            % (servent[0], servent[1]))
            return None

        self.sockList = [self.sock, self.serventSock]
        self.sock.bind((self.ipaddr, self.port))
        self.listen()

        while True:
            line = input()
            # query for some key
            if line[0] == "?":
                key = line[1:].strip()
                self.sendKeyReq(key)
            # topology request
            elif line.strip() == "T":
                self.sendTopoReq()
            # end execution
            elif line.strip() == "Q" or line == "":
                logging.info("Bye =)")
                break
            else:
                logging.warning("Unknown command")
                continue

            # try to fetch responses from any servent
            responseCount = 0
            lastNseq = message["nseq"]
            while True:
                respCode, message = self.fechMessages()

                # 0 - No data
                # 1 - Invalid Message
                # 2 - Valid message
                # 3 - Any king of error
                if respCode == 0:
                    if not responseCount:
                        logging.warning("No data received")
                    break
                elif respCode == 1:
                    logging.warning("Invalid packet received from %s:%s"
                                    % (servent[0], servent[1]))
                elif respCode == 2 and lastNseq == message["nseq"]:
                    responseCount += 1
                    logging.info("%s %s:%s"
                                 % (message["value"], servent[0], servent[1]))
                else:
                    break
            self.nseq += 1
        self.sock.close()
        self.serventSock.close()
