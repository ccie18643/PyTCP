#!/usr/bin/env python3

"""

PyTCP, Python TCP/IP stack simulation version 0.1 - 2020, Sebastian Majewski
eth_header.py - contains class supporting Ethernet header parsing and creation

"""

import socket
import struct
import array
import binascii


"""
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
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


class EthernetHeader:
    """ Ethernet header support class """

    def __init__(self, raw_header=None):
        """ Read raw header data """

        if raw_header:
            self.destination_mac_address = ":".join([f"{_:0>2x}" for _ in raw_header[0:6]])
            self.source_mac_address =  ":".join([f"{_:0>2x}" for _ in raw_header[6:12]])
            self.ethertype = struct.unpack("!H", raw_header[12:14])[0]

        else:
            self.destination_mac_address = "00:00:00:00:00:00"
            self.source_mac_address = "00:00:00:00:00:00"
            self.ethertype = 0

    def get_raw_header(self):
        """ Get raw ethernet header data """

        return struct.pack(
            "! 6s 6s H",
            bytes.fromhex(self.destination_mac_address.replace(":", "")),
            bytes.fromhex(self.source_mac_address.replace(":", "")),
            self.ethertype,
        )


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
            + f"ETH      SRC {self.source_mac_address}  DST {self.destination_mac_address}  TYPE 0x{self.ethertype:0>4x} "
            + f"({ethertype_table.get(self.ethertype, '')})"
        )
