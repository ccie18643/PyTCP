#!/usr/bin/env python3

"""

PyTCP, Python TCP/IP stack simulation version 0.1 - 2020, Sebastian Majewski
ph_arp.py - packet handler library for ARP protocol

"""

import socket
import struct


"""

   ARP packet header - IPv4 stack version

   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |         Hardware Type         |         Protocol Type         |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |  Hard Length  |  Proto Length |           Operation           |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               >
   +        Sender Mac Address     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   >                               |       Sender IP Address       >
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   >                               |                               >
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+       Target MAC Address      |
   >                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                       Target IP Address                       |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

"""


ARP_OP_REQUEST = 1
ARP_OP_REPLY = 2


class ArpPacket:
    """ ARP packet support class """

    def __init__(self, raw_packet=None, sha=None, spa=None, tha="00:00:00:00:00:00", tpa=None, operation=1):
        """ Parse raw ARP packet or initialize new one"""

        if raw_packet:
            self.raw_header = raw_packet[:28]

            self.hrtype = struct.unpack("!H", self.raw_header[0:2])[0]
            self.prtype = struct.unpack("!H", self.raw_header[2:4])[0]
            self.hrlen = self.raw_header[4]
            self.prlen = self.raw_header[5]
            self.operation = struct.unpack("!H", self.raw_header[6:8])[0]
            self.sha = ":".join([f"{_:0>2x}" for _ in self.raw_header[8:14]])
            self.spa = socket.inet_ntoa(struct.unpack("!4s", self.raw_header[14:18])[0])
            self.tha = ":".join([f"{_:0>2x}" for _ in self.raw_header[18:24]])
            self.tpa = socket.inet_ntoa(struct.unpack("!4s", self.raw_header[24:28])[0])

        else:
            self.hrtype = 1
            self.prtype = 0x0800
            self.hrlen = 6
            self.prlen = 4
            self.operation = operation
            self.sha = sha
            self.spa = spa
            self.tha = tha
            self.tpa = tpa

    @property
    def raw_packet(self):
        """ Get ARP packet in raw format """

        return struct.pack(
            "!HH BBH 6s 4s 6s 4s",
            self.hrtype,
            self.prtype,
            self.hrlen,
            self.prlen,
            self.operation,
            bytes.fromhex(self.sha.replace(":", "")),
            socket.inet_aton(self.spa),
            bytes.fromhex(self.tha.replace(":", "")),
            socket.inet_aton(self.tpa),
        )

    @property
    def log(self):
        """ Short packet log string """

        if self.operation == ARP_OP_REQUEST:
            return (f"ARP request {self.spa} / {self.sha} > {self.tpa} / {self.tha}")
        
        if self.operation == ARP_OP_REPLY:
            return (f"ARP reply {self.spa} / {self.sha} > {self.tpa} / {self.tha}")

        return (f"ARP unknown operation {self.operation}")

    @property
    def dump(self):
        """ Verbose packet debug string """

        return (
            "--------------------------------------------------------------------------------\n"
            + f"ARP      SENDER MAC {self.sha} IP {self.spa}  OPER {'Request' if self.operation == 1 else 'Reply'}\n"
            + f"         TARGET MAC {self.tha} IP {self.tpa}"
        )
