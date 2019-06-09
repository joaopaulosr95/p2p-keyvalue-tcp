#!/usr/local/bin/python3
import json
import logging
import socket
import struct

logging.basicConfig(level=logging.INFO,
                    format="[%(asctime)s][%(levelname)s]%(message)s",
                    datefmt="%m-%d-%Y %I:%M:%S %p")

# constants
MAXSERVENTS = 10
SOCKETTIMEOUT = 4
MTU = 416  # keyflood/topoflood are the larger packets we implement
MESSAGETYPES = dict(ID=4, KEYREQ=5, TOPOREQ=6, KEYFLOOD=7, TOPOFLOOD=8, RESP=9)
MESSAGEHEADERS = dict(
    ID="!HH",
    KEYREQ="!HLH",
    TOPOREQ="!HL",
    KEYFLOOD="!HHLLHH",
    TOPOFLOOD="!HHLLHH",
    RESP="!HLH"
)


def messageFactory(typeNumber, **kwargs):
    try:
        # ID
        if typeNumber == 4:
            return json(typeNumber=typeNumber,
                        port=kwargs.get("port"))
        # KEYREQ
        elif typeNumber == 5:
            return json(typeNumber=typeNumber,
                        nseq=kwargs.get("nseq"),
                        size=kwargs.get("size"),
                        key=kwargs.get("key"))
        # TOPOREQ
        elif typeNumber == 6:
            return json(typeNumber=typeNumber,
                        nseq=kwargs.get("nseq"))
        # fits both KEYFLOOD and TOPOFLOOD message
        elif typeNumber in [7, 8]:
            return json(typeNumber=typeNumber,
                        ttl=kwargs.get("ttl"),
                        nseq=kwargs.get("nseq"),
                        sourceIp=kwargs.get("sourceIp"),
                        sourcePort=kwargs.get("sourcePort"),
                        size=kwargs.get("size")) + kwargs.get("info")
        # RESP
        elif typeNumber == 9:
            return json(typeNumber=typeNumber,
                        nseq=kwargs.get("nseq"),
                        size=kwargs.get("size"),
                        value=kwargs.get("value"))
        logging.warning("Invalid message typeNumber %d" % typeNumber)
    except (json.JSONDecodeError, KeyError) as exc:
        logging.warning(exc)
    return None


def pack(typeNumber, **kwargs):
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
                           kwargs.get("size")) + kwargs.get("info")
    elif typeNumber == MESSAGETYPES["TOPOREQ"]:
        return struct.pack(MESSAGEHEADERS["TOPOREQ"],
                           typeNumber,
                           kwargs.get("nseq"))
    elif typeNumber in [MESSAGETYPES["KEYFLOOD"], MESSAGETYPES["TOPOFLOOD"]]:
        return struct.pack(MESSAGEHEADERS["KEYFLOOD"],
                           typeNumber,
                           kwargs.get("ttl"),
                           kwargs.get("nseq"),
                           kwargs.get("sourceIp"),
                           kwargs.get("sourcePort"),
                           kwargs.get("size")) + kwargs.get("info")
    elif typeNumber == MESSAGETYPES["RESP"]:
        return struct.pack(MESSAGEHEADERS["RESP"],
                           typeNumber,
                           kwargs.get("nseq"),
                           kwargs.get("size")) + kwargs.get("info")
    return None


def unpack(typeNumber, payload):
    message = None
    try:
        if typeNumber == MESSAGETYPES["ID"]:
            unpacked = struct.unpack(MESSAGEHEADERS["ID"], payload[:4])
            message = messageFactory(MESSAGETYPES["ID"],
                                     port=unpacked[0])
        elif typeNumber == MESSAGETYPES["KEYREQ"]:
            unpacked = struct.unpack(MESSAGEHEADERS["KEYREQ"], payload[:6])
            message = messageFactory(MESSAGETYPES["KEYREQ"],
                                     nseq=unpacked[0],
                                     size=unpacked[1],
                                     value=payload[7:])
        elif typeNumber == MESSAGETYPES["TOPOREQ"]:
            unpacked = struct.unpack(MESSAGEHEADERS["TOPOREQ"], payload[:6])
            message = messageFactory(MESSAGETYPES["TOPOREQ"],
                                     nseq=unpacked[0])
        elif typeNumber == MESSAGETYPES["KEYFLOOD"]:
            unpacked = struct.unpack(MESSAGEHEADERS["KEYREQ"], payload[:16])
            message = messageFactory(MESSAGETYPES["KEYFLOOD"],
                                     ttl=unpacked[0],
                                     nseq=unpacked[1],
                                     sourceIp=unpacked[2],
                                     sourcePort=unpacked[3],
                                     size=unpacked[4],
                                     value=payload[:17])
        elif typeNumber == MESSAGEHEADERS["TOPOFLOOD"]:
            unpacked = struct.unpack(MESSAGEHEADERS["KEYREQ"], payload[:16])
            message = messageFactory(MESSAGETYPES["TOPOFLOOD"],
                                     ttl=unpacked[0],
                                     nseq=unpacked[1],
                                     sourceIp=unpacked[2],
                                     sourcePort=unpacked[3],
                                     size=unpacked[4],
                                     value=payload[:17])
        elif typeNumber == MESSAGETYPES["RESP"]:
            unpacked = struct.unpack(MESSAGETYPES["RESP"], payload[:6])
            message = messageFactory(MESSAGETYPES["RESP"],
                                     nseq=unpacked[0],
                                     size=unpacked[1],
                                     value=payload[:7])
    except struct.error:
        logging.warning("Invalid headerFormat provided")
    return message


class Client:
    def __init__(self, ipaddr, port):
        self._ipaddr = ipaddr
        self._port = port
        self._nseq = 0
        self._sock = None
        self._serverSock = None

    def _interact(sock, message):
        try:
            encoded = pack(message)
            sock.send(encoded)
            return True
        except socket.error as err:
            logging.warning(err)
        return False

    def _fetchMessages(self, sock):
        self._sock.settimeout(SOCKETTIMEOUT)
        sock, servent = self._sock.accept()
        try:
            payload = sock.recv(MTU)
            self._sock.settimeout(None)
            if payload:
                message = unpack(MESSAGETYPES["RESP"], payload)
                if not message:
                    return 1, None
                return 2, message
        except socket.timeout:
            return 0, None
        except socket.error as err:
            logging.warning(err)
            return 3, None

    def run(self, servent):
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._serverSock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        try:
            self._serverSock.connect(servent)
            # create a ID message and identify to servent as a client
            message = messageFactory(MESSAGETYPES["ID"], port=self._port)
            self._sockinteract(self._serverSock, message)
            self._nseq += 1
        except socket.error:
            logging.warning("Could not connect to servent (%s,%d)"
                            % (servent[0], servent[1]))
            return None

        self._sockList = [self._sock, self._serverSock]
        self._sock.bind((self._ipaddr, self._port))
        self._listen()

        while True:
            line = input()
            # query for some key
            if line[0] == "?":
                key = line[1:].strip()
                # create a KEYREQ message and send to servent
                message = messageFactory(MESSAGETYPES["KEYREQ"],
                                         nseq=self._nseq,
                                         size=len(key),
                                         key=key)
                self._interact(self._serverSock, message)
            # topology request
            elif line.strip() == "T":
                message = messageFactory(MESSAGETYPES["TOPOREQ"],
                                         nseq=self._nseq)
                self._interact(self._serverSock, message)
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
                respCode, message = self._fechMessages()
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
                                 % (message, servent[0], servent[1]))
                else:
                    break
            self._nseq += 1
        self._sock.close()
        self._serverSock.close()


if __name__ == "__main__":
    pass
