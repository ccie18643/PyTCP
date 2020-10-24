#!/usr/bin/env python3

"""

PyTCP, Python TCP/IP stack simulation version 0.1 - 2020, Sebastian Majewski
ps_arp.py - protocol support library for ARP

"""


import socket
import struct

from tracker import Tracker


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

    def __init__(self, parent_packet=None, arp_sha=None, arp_spa=None, arp_tpa=None, arp_tha="00:00:00:00:00:00", arp_oper=ARP_OP_REQUEST, echo_tracker=None):
        """ Class constructor """

        # Packet parsing
        if parent_packet:
            self.tracker = parent_packet.tracker

            raw_packet = parent_packet.raw_data
            raw_header = raw_packet[:ARP_HEADER_LEN]

            self.arp_hrtype = struct.unpack("!H", raw_header[0:2])[0]
            self.arp_prtype = struct.unpack("!H", raw_header[2:4])[0]
            self.arp_hrlen = raw_header[4]
            self.arp_prlen = raw_header[5]
            self.arp_oper = struct.unpack("!H", raw_header[6:8])[0]
            self.arp_sha = ":".join([f"{_:0>2x}" for _ in raw_header[8:14]])
            self.arp_spa = socket.inet_ntoa(struct.unpack("!4s", raw_header[14:18])[0])
            self.arp_tha = ":".join([f"{_:0>2x}" for _ in raw_header[18:24]])
            self.arp_tpa = socket.inet_ntoa(struct.unpack("!4s", raw_header[24:28])[0])

        # Packet building
        else:
            self.tracker = Tracker("TX", echo_tracker)

            self.arp_hrtype = 1
            self.arp_prtype = 0x0800
            self.arp_hrlen = 6
            self.arp_prlen = 4
            self.arp_oper = arp_oper
            self.arp_sha = arp_sha
            self.arp_spa = arp_spa
            self.arp_tha = arp_tha
            self.arp_tpa = arp_tpa

    def __str__(self):
        """ Short packet log string """

        if self.arp_oper == ARP_OP_REQUEST:
            return f"ARP request {self.arp_spa} / {self.arp_sha} > {self.arp_tpa} / {self.arp_tha}"
        if self.arp_oper == ARP_OP_REPLY:
            return f"ARP reply {self.arp_spa} / {self.arp_sha} > {self.arp_tpa} / {self.arp_tha}"
        return f"ARP unknown operation {self.oper}"

    def __len__(self):
        """ Length of the packet """

        return len(self.raw_packet)

    @property
    def raw_header(self):
        """ Packet header in raw format """

        return struct.pack(
            "!HH BBH 6s 4s 6s 4s",
            self.arp_hrtype,
            self.arp_prtype,
            self.arp_hrlen,
            self.arp_prlen,
            self.arp_oper,
            bytes.fromhex(self.arp_sha.replace(":", "")),
            socket.inet_aton(self.arp_spa),
            bytes.fromhex(self.arp_tha.replace(":", "")),
            socket.inet_aton(self.arp_tpa),
        )

    @property
    def raw_packet(self):
        """ Get packet in raw format """

        return self.raw_header

    def get_raw_packet(self):
        """ Get packet in raw format ready to be processed by lower level protocol """

        return self.raw_packet
