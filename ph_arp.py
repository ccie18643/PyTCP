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
    """ Base class for Arp packet """

    @property
    def log(self):
        """ Short packet log string """

        if self.hdr_operation == ARP_OP_REQUEST:
            return f"ARP request {self.hdr_spa} / {self.hdr_sha} > {self.hdr_tpa} / {self.hdr_tha}"

        if self.hdr_operation == ARP_OP_REPLY:
            return f"ARP reply {self.hdr_spa} / {self.hdr_sha} > {self.hdr_tpa} / {self.hdr_tha}"

        return f"ARP unknown operation {self.operation}"

    @property
    def dump(self):
        """ Verbose packet debug string """

        return (
            "--------------------------------------------------------------------------------\n"
            + f"ARP      SENDER MAC {self.hdr_sha} IP {self.hdr_spa}  OPER {'Request' if self.hdr_operation == 1 else 'Reply'}\n"
            + f"         TARGET MAC {self.hdr_tha} IP {self.hdr_tpa}"
        )


class ArpPacketRx(ArpPacket):
    """ ARP packet parse class """

    def __init__(self, raw_packet):
        """ Class constructor """

        self.raw_packet = raw_packet

        self.hdr_hrtype = struct.unpack("!H", self.raw_header[0:2])[0]
        self.hdr_prtype = struct.unpack("!H", self.raw_header[2:4])[0]
        self.hdr_hrlen = self.raw_header[4]
        self.hdr_prlen = self.raw_header[5]
        self.hdr_operation = struct.unpack("!H", self.raw_header[6:8])[0]
        self.hdr_sha = ":".join([f"{_:0>2x}" for _ in self.raw_header[8:14]])
        self.hdr_spa = socket.inet_ntoa(struct.unpack("!4s", self.raw_header[14:18])[0])
        self.hdr_tha = ":".join([f"{_:0>2x}" for _ in self.raw_header[18:24]])
        self.hdr_tpa = socket.inet_ntoa(struct.unpack("!4s", self.raw_header[24:28])[0])

    @property
    def raw_header(self):
        """ Get packet header in raw format """

        return self.raw_packet[:28]


class ArpPacketTx(ArpPacket):
    """ ARP packet creation class """

    def __init__(self, hdr_sha, hdr_spa, hdr_tpa, hdr_tha="00:00:00:00:00:00", hdr_operation=ARP_OP_REQUEST):
        """ Class constructor """

        self.hdr_hrtype = 1
        self.hdr_prtype = 0x0800
        self.hdr_hrlen = 6
        self.hdr_prlen = 4
        self.hdr_operation = hdr_operation
        self.hdr_sha = hdr_sha
        self.hdr_spa = hdr_spa
        self.hdr_tha = hdr_tha
        self.hdr_tpa = hdr_tpa

    @property
    def raw_header(self):
        """ Get packet in raw format """

        return struct.pack(
            "!HH BBH 6s 4s 6s 4s",
            self.hdr_hrtype,
            self.hdr_prtype,
            self.hdr_hrlen,
            self.hdr_prlen,
            self.hdr_operation,
            bytes.fromhex(self.hdr_sha.replace(":", "")),
            socket.inet_aton(self.hdr_spa),
            bytes.fromhex(self.hdr_tha.replace(":", "")),
            socket.inet_aton(self.hdr_tpa),
        )

    @property
    def raw_packet(self):
        """ Get packet in raw format """

        return self.raw_header
