#!/usr/local/bin/python3
import json
import logging
import struct

logging.basicConfig(level=logging.INFO,
                    format="[%(asctime)s][%(levelname)s]%(message)s",
                    datefmt="%m-%d-%Y %I:%M:%S %p")


def pack(typeNumber, **kwargs):
    if typeNumber == 4:
        return struct.pack("!HH", typeNumber, kwargs.get("port"))
    elif typeNumber == 5:
        return struct.pack("!HLH",
                           typeNumber,
                           kwargs.get("nseq"),
                           kwargs.get("size")) + kwargs.get("info")
    elif typeNumber == 6:
        return struct.pack("!HL",
                           typeNumber,
                           kwargs.get("nseq"))
    elif typeNumber in [7, 8]:
        return struct.pack("!HHLLHH",
                           typeNumber,
                           kwargs.get("ttl"),
                           kwargs.get("nseq"),
                           kwargs.get("sourceIp"),
                           kwargs.get("sourcePort"),
                           kwargs.get("size")) + kwargs.get("info")
    elif typeNumber == 9:
        return struct.pack("!HLH",
                           typeNumber,
                           kwargs.get("nseq"),
                           kwargs.get("size")) + kwargs.get("info")
    return None


def unpack():
    pass


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
        # fits both KEYFLOOD and FOPOFLOOD message
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
        return None
    except (json.JSONDecodeError, KeyError) as exc:
        logging.warning(exc)
        return None


if __name__ == "__main__":
    pass
