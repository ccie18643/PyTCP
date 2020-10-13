#!/usr/bin/env python3

"""

PyTCP, Python TCP/IP stack simulation version 0.1 - 2020, Sebastian Majewski
ethernet_packet.py - supports Ethernet packet parsing and creation

"""

import socket
import struct
import array
import binascii


"""

   Ethernet packet header

   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               >
   +    Destination MAC Address    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   >                               |                               > 
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+      Source MAC Address       +
   >                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |           EtherType           |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

"""


class EthernetPacket:
    """ Ethernet packet support class """

    def __init__(self, raw_packet=None, dst=None, src=None, packet_data=b""):
        """ Parse raw Ethernet packet or initialize new one"""

        if raw_packet:
            self.packet_header = raw_packet[:14]
            self.packet_data = raw_packet[14:]

            self.dst = ":".join([f"{_:0>2x}" for _ in self.packet_header[0:6]])
            self.src =  ":".join([f"{_:0>2x}" for _ in self.packet_header[6:12]])
            self.type = struct.unpack("!H", self.packet_header[12:14])[0]

        else:
            self.dst = dst
            self.src = src
            self.type = type

    def get_raw_packet(self):
        """ Get Ethernet packet in raw format """

        return struct.pack(
            "! 6s 6s H",
            bytes.fromhex(self.dst.replace(":", "")),
            bytes.fromhex(self.src.replace(":", "")),
            self.type,
        ) + packet_data

    def __str__(self):
        """ Easy to read string reresentation """

        ethertype_table = {
            0x0800: "IP",
            0x0806: "ARP",
            0x8100: "VLAN",
            0x86DD: "IPv6",
        }

        return (
            "--------------------------------------------------------------------------------\n"
            + f"ETH      SRC {self.src}  DST {self.dst}  TYPE 0x{self.type:0>4x} ({ethertype_table.get(self.type, '???')})"
        )
