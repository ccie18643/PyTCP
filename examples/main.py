#!/usr/bin/env python3

import os
import sys
import time

current = os.path.dirname(os.path.realpath(__file__))
parent = os.path.dirname(current)
sys.path.append(parent)

from pytcp import TcpIpStack

def main():
    stack = TcpIpStack("tap7")
    stack.start()
    time.sleep(60)
    stack.stop()



if __name__ == "__main__":
    main()
