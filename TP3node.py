#!/usr/local/bin/python3
import argparse
from TP3 import Servent

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("port",
                        type=int,
                        metavar="port",
                        help="port to run servent")
    parser.add_argument("keyspath",
                        metavar="keyspath",
                        help="path of the kv database")
    parser.add_argument("servents",
                        metavar="servents",
                        nargs="*",
                        help="list of host:port servents")
    args = parser.parse_args()
    ipaddr = "127.0.0.1"
    s = Servent(ipaddr, args.port)
    s.loadKeys(args.keyspath)
    s.run(args.servents)
