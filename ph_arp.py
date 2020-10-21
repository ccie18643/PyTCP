#!/usr/bin/env python3

"""

PyTCP, Python TCP/IP stack simulation version 0.1 - 2020, Sebastian Majewski
ph_arp.py - packet handler library for ARP protocol

"""

import socket
import struct


"""

   ARP packet header - IPv4 stack version only

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


ARP_HEADER_LEN = 28

ARP_OP_REQUEST = 1
ARP_OP_REPLY = 2


class ArpPacket:
    """ ARP packet support class """

    protocol = "ARP"

    def __init__(self, parent_packet=None, hdr_sha=None, hdr_spa=None, hdr_tpa=None, hdr_tha="00:00:00:00:00:00", hdr_oper=ARP_OP_REQUEST):
        """ Class constructor """

        # Packet parsing
        if parent_packet:
            raw_packet = parent_packet.raw_data
            raw_header = raw_packet[:ARP_HEADER_LEN]

            self.hdr_hrtype = struct.unpack("!H", raw_header[0:2])[0]
            self.hdr_prtype = struct.unpack("!H", raw_header[2:4])[0]
            self.hdr_hrlen = raw_header[4]
            self.hdr_prlen = raw_header[5]
            self.hdr_oper = struct.unpack("!H", raw_header[6:8])[0]
            self.hdr_sha = ":".join([f"{_:0>2x}" for _ in raw_header[8:14]])
            self.hdr_spa = socket.inet_ntoa(struct.unpack("!4s", raw_header[14:18])[0])
            self.hdr_tha = ":".join([f"{_:0>2x}" for _ in raw_header[18:24]])
            self.hdr_tpa = socket.inet_ntoa(struct.unpack("!4s", raw_header[24:28])[0])

        else:
            self.hdr_hrtype = 1
            self.hdr_prtype = 0x0800
            self.hdr_hrlen = 6
            self.hdr_prlen = 4
            self.hdr_oper = hdr_oper
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
            self.hdr_oper,
            bytes.fromhex(self.hdr_sha.replace(":", "")),
            socket.inet_aton(self.hdr_spa),
            bytes.fromhex(self.hdr_tha.replace(":", "")),
            socket.inet_aton(self.hdr_tpa),
        )

    @property
    def raw_packet(self):
        """ Get packet in raw format """

        return self.raw_header

    def get_raw_packet(self):
        """ Get packet in raw format ready to be processed by lower level protocol """

        return self.raw_packet

    def __str__(self):
        """ Short packet log string """

        if self.hdr_oper == ARP_OP_REQUEST:
            return f"ARP request {self.hdr_spa} / {self.hdr_sha} > {self.hdr_tpa} / {self.hdr_tha}"

        if self.hdr_oper == ARP_OP_REPLY:
            return f"ARP reply {self.hdr_spa} / {self.hdr_sha} > {self.hdr_tpa} / {self.hdr_tha}"

        return f"ARP unknown operation {self.oper}"
