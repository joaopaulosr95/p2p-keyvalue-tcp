#!/usr/local/bin/python3
import argparse
from TP3 import Client

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("port",
                        type=int,
                        metavar="port",
                        help="port to run client")
    parser.add_argument("servent",
                        metavar="servent",
                        help="host:port of the servent to connect to")
    args = parser.parse_args()
    ipaddr = "127.0.0.1"
    c = Client(ipaddr, args.port)
    serventIpAddr, serventPort = args.servent.split(":")
    c.run(tuple([serventIpAddr, int(serventPort)]))
