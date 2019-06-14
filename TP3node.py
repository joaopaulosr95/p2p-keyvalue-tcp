#!/usr/local/bin/python3
import argparse
import logging
from TP3 import Servent

logging.basicConfig(level=logging.INFO,
                    format="[%(asctime)s][%(levelname)s]%(message)s",
                    datefmt="%m-%d-%Y %I:%M:%S %p")

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
    ipaddr = "0.0.0.0"
    s = Servent(ipaddr, args.port)
    if not s.loadKeys(args.keyspath):
        logging.error("Error loading keys")
    s.run(args.servents)
