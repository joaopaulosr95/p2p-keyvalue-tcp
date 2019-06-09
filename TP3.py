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
    KEYREQ="!HLH",
    TOPOREQ="!HL",
    KEYFLOOD="!HHLLHH",
    TOPOFLOOD="!HHLLHH",
    RESP="!HLH")


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
                           nseq=kwargs.get("nseq"),
                           size=kwargs.get("size"),
                           key=kwargs.get("key"))
        elif typeNumber == MESSAGETYPES["TOPOREQ"]:
            message = dict(typeNumber=typeNumber,
                           nseq=kwargs.get("nseq"))
        elif typeNumber in [MESSAGETYPES["KEYFLOOD"],
                            MESSAGETYPES["TOPOFLOOD"]]:
            message = dict(typeNumber=typeNumber,
                           ttl=kwargs.get("ttl"),
                           nseq=kwargs.get("nseq"),
                           sourceIp=kwargs.get("sourceIp"),
                           sourcePort=kwargs.get("sourcePort"),
                           size=kwargs.get("size"),
                           info=kwargs.get("info"))
        elif typeNumber == MESSAGETYPES["RESP"]:
            message = dict(typeNumber=typeNumber,
                           nseq=kwargs.get("nseq"),
                           size=kwargs.get("size"),
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
        return struct.pack(MESSAGEHEADERS["KEYREQ"],
                           typeNumber,
                           kwargs["nseq"],
                           kwargs["size"]) \
               + kwargs["key"].encode()
    elif typeNumber == MESSAGETYPES["TOPOREQ"]:
        return struct.pack(MESSAGEHEADERS["TOPOREQ"],
                           typeNumber,
                           kwargs["nseq"])
    elif typeNumber in [MESSAGETYPES["KEYFLOOD"], MESSAGETYPES["TOPOFLOOD"]]:
        return struct.pack(MESSAGEHEADERS["KEYFLOOD"],
                           typeNumber,
                           kwargs["ttl"],
                           kwargs["nseq"],
                           ipToInt(kwargs["sourceIp"]),
                           kwargs["sourcePort"],
                           kwargs["size"]) \
               + kwargs["info"].encode()
    elif typeNumber == MESSAGETYPES["RESP"]:
        return struct.pack(MESSAGEHEADERS["RESP"],
                           typeNumber,
                           kwargs["nseq"],
                           kwargs["size"])\
               + kwargs["value"].encode()
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
            headerLimit = struct.calcsize(MESSAGEHEADERS["KEYREQ"])
            unpacked = struct.unpack(MESSAGEHEADERS["KEYREQ"],
                                     payload[:headerLimit])
            key = struct.unpack("!%ds" % unpacked[3],
                                payload[headerLimit + 1:])
            message = messageFactory(MESSAGETYPES["KEYREQ"],
                                     nseq=unpacked[1],
                                     size=unpacked[2],
                                     key=key)
        elif typeNumber == MESSAGETYPES["TOPOREQ"]:
            headerLimit = struct.calcsize(MESSAGEHEADERS["TOPOREQ"])
            unpacked = struct.unpack(MESSAGEHEADERS["TOPOREQ"],
                                     payload[:headerLimit])
            message = messageFactory(MESSAGETYPES["TOPOREQ"],
                                     nseq=unpacked[1])
        elif typeNumber == MESSAGETYPES["KEYFLOOD"]:
            headerLimit = struct.calcsize(MESSAGEHEADERS["KEYFLOOD"])
            unpacked = struct.unpack(MESSAGEHEADERS["KEYFLOOD"],
                                     payload[:headerLimit])
            info = struct.unpack("!%ds" % unpacked[6],
                                payload[headerLimit + 1:])
            message = messageFactory(MESSAGETYPES["KEYFLOOD"],
                                     ttl=unpacked[1],
                                     nseq=unpacked[2],
                                     sourceIp=intToIp(unpacked[3]),
                                     sourcePort=unpacked[4],
                                     size=unpacked[5],
                                     info=info)
        elif typeNumber == MESSAGEHEADERS["TOPOFLOOD"]:
            headerLimit = struct.calcsize(MESSAGEHEADERS["TOPOFLOOD"])
            unpacked = struct.unpack(MESSAGEHEADERS["TOPOFLOOD"],
                                     payload[:headerLimit])
            info = struct.unpack("!%ds" % unpacked[6],
                                 payload[headerLimit + 1:])
            message = messageFactory(MESSAGETYPES["TOPOFLOOD"],
                                     ttl=unpacked[1],
                                     nseq=unpacked[2],
                                     sourceIp=intToIp(unpacked[3]),
                                     sourcePort=unpacked[4],
                                     size=unpacked[5],
                                     info=info)
        elif typeNumber == MESSAGETYPES["RESP"]:
            headerLimit = struct.calcsize(MESSAGEHEADERS["RESP"])
            unpacked = struct.unpack(MESSAGEHEADERS["RESP"],
                                     payload[:headerLimit])
            value = struct.unpack("!%ds" % unpacked[3],
                                  payload[headerLimit + 1:])
            message = messageFactory(MESSAGETYPES["RESP"],
                                     nseq=unpacked[1],
                                     size=unpacked[2],
                                     value=value)
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
        clients = list(filter(lambda c: c[2] == sock, self.clientList))
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
        logging.info("Received KEYREQ fromo client %s:%d" % (source[0],
                                                             source[1]))
        key = self.getKey(message["key"])
        if key:
            response = messageFactory(MESSAGETYPES["RESP"],
                                      nseq=message["nseq"],
                                      size=len(key),
                                      value=key)
            interact(sock, response)
            logging.info("Response sent to client %s:%d with seqNum %d"
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
        logging.info("KEYFLOOD message created and sent to peers")


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
        """ Expect servents to be a list of strings
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

        logging.info("Waiting for connections at port %d" % self.port)
        while True:
            readable, _, exceptions = select.select(
                self.sockList, [], self.sockList, 0)
            for sock in readable:
                try:
                    # a new servent/client has arrived, so we expect it to
                    # send an ID message
                    if sock == self.sock:
                        # -1 because the servent socket itself is also in
                        # self.sockList
                        if len(self.sockList) - 1 < MAXSERVENTS:
                            newSock, addr = sock.accept()
                            newSock.setblocking(0)
                            payload = newSock.recv(MTU)
                            message = unpack(MESSAGETYPES["ID"], payload)
                            if not message:
                                logging.warning("Invalid ID message from %s:%s"
                                                % (addr[0], addr[1]))
                                continue
                            # new servent
                            if message["port"] == 0:
                                self.sockList.append(sock)
                                logging.info("Servent %s:%s has arrived"
                                             % (addr[0], addr[1]))
                            # new client
                            else:
                                self.clientList.add(
                                    tuple([addr[0], message["port"], sock]))
                                logging.info("Client %s:%s has arrived"
                                             % (addr[0], message["port"]))
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
            for sock in exceptions:
                client = self.getClient(sock)
                if client:
                    self.clientList.remove(client)
                    logging.info("Client %s:%d hangup, removing socket"
                                 % (client[0], client[1]))
                self.sockList.remove(sock)


class Client:
    def __init__(self, ipaddr, port):
        self.ipaddr = ipaddr
        self.port = port
        self.nseq = 0
        self.sock = None
        self.serventSock = None

    def fetchMessages(self):
        sock, servent = self.sock.accept()
        self.sock.settimeout(SOCKETTIMEOUT)
        try:
            payload = sock.recv(MTU)
            print(payload)
            self.sock.settimeout(None)
            if payload:
                message = unpack(MESSAGETYPES["RESP"], payload)
                if not message:
                    responseCode, contents = 1, None
                responseCode, contents = 2, message
            sock.close()
        except socket.timeout:
            responseCode, contents = 0, None
        except socket.error as err:
            logging.warning(err)
            responseCode, contents = 3, None
        return responseCode, contents

    def sendKeyReq(self, key):
        # create a KEYREQ message and send to servent
        message = messageFactory(MESSAGETYPES["KEYREQ"],
                                 nseq=self.nseq,
                                 size=len(key),
                                 key=key)
        if interact(self.serventSock, message):
            logging.info("KEYREQ sent to servent for key %s" % key)
            return self.nseq
        else:
            logging.warning("Error sending KEYREQ")
            return None

    def sendTopoReq(self):
        message = messageFactory(MESSAGETYPES["TOPOREQ"],
                                 nseq=self.nseq)
        if interact(self.serventSock, message):
            logging.info("TOPOREQ sent to servent")
        else:
            logging.warning("Error sending TOPOREQ")

    def run(self, servent):
        """ Expects servent to be tuple(ipaddr:port """
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.serventSock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        logging.info("Initializing client at %s:%d" % (self.ipaddr, self.port))
        try:
            # create a ID message and identify to servent as a client
            message = messageFactory(MESSAGETYPES["ID"], port=self.port)
            if not message:
                logging.error("Error creating ID message")
                return
            self.serventSock.connect(servent)
            if interact(self.serventSock, message):
                logging.info("ID sent to servent")
                self.nseq += 1
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
            lastNSeq = self.nseq - 1
            while True:
                respCode, message = self.fetchMessages()

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
                elif respCode == 2 and lastNSeq == message["nseq"]:
                    responseCount += 1
                    logging.info("%s %s:%s"
                                 % (message["value"], servent[0], servent[1]))
                else:
                    break
            self.nseq += 1
        self.sock.close()
        self.serventSock.close()
