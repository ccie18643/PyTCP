#!/usr/bin/env python3

"""

PyTCP, Python TCP/IP stack simulation version 0.1 - 2020, Sebastian Majewski
eth_packet.py - support for ARP packet parsing and creation

"""

import socket
import struct
import array
import binascii


"""
   
   ARP packet header - IP stack version

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


class ArpPacket:
    """ ARP packet support class """

    def __init__(self, raw_packet=None, sha=None, spa=None, tha="00:00:00:00:00:00", tpa=None, operation=1):
        """ Parse raw ARP packet or initialize new one"""

        self.packet_header = raw_packet[:28]

        if raw_packet:
            self.hrtype = struct.unpack("!H", self.packet_header[0:2])[0]
            self.prtype = struct.unpack("!H", self.packet_header[2:4])[0]
            self.hrlen = self.packet_header[4]
            self.prlen = self.packet_header[5]
            self.operation = struct.unpack("!H", self.packet_header[6:8])[0]
            self.sha =  ":".join([f"{_:0>2x}" for _ in self.packet_header[8:14]])
            self.spa =  socket.inet_ntoa(struct.unpack("!4s", self.packet_header[14:18])[0])
            self.tha =  ":".join([f"{_:0>2x}" for _ in self.packet_header[18:24]])
            self.tpa =  socket.inet_ntoa(struct.unpack("!4s", self.packet_header[24:28])[0])

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

    def get_raw_packet(self):
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


    def __str__(self):
        """ Easy to read string reresentation """

        return (
            "--------------------------------------------------------------------------------\n"
            + f"ARP      SENDER MAC {self.sha} IP {self.spa}  OPER {'Request' if self.operation == 1 else 'Reply'}\n"
            + f"         TARGET MAC {self.tha} IP {self.tpa}"
        )

