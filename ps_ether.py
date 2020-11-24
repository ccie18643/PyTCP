#!/usr/bin/env python3

"""

PyTCP, Python TCP/IP stack, version 0.1 - 2020, Sebastian Majewski
ps_ethernet.py - protocol suppot libary for Ethernet

"""

import struct

from tracker import Tracker


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


ETHER_HEADER_LEN = 14

ETHER_TYPE_MIN = 0x0600
ETHER_TYPE_ARP = 0x0806
ETHER_TYPE_IPV4 = 0x0800
ETHER_TYPE_IPV6 = 0x86DD


ETHER_TYPE_TABLE = {ETHER_TYPE_ARP: "ARP", ETHER_TYPE_IPV4: "IPv4", ETHER_TYPE_IPV6: "IPv6"}


class EtherPacket:
    """ Ethernet packet support class """

    protocol = "ETHER"

    def __init__(self, raw_packet=None, ether_src="00:00:00:00:00:00", ether_dst="00:00:00:00:00:00", child_packet=None):
        """ Class constructor """

        # Packet parsing
        if raw_packet:
            self.tracker = Tracker("RX")

            raw_header = raw_packet[:ETHER_HEADER_LEN]

            self.raw_data = raw_packet[ETHER_HEADER_LEN:]
            self.ether_dst = ":".join([f"{_:0>2x}" for _ in raw_header[0:6]])
            self.ether_src = ":".join([f"{_:0>2x}" for _ in raw_header[6:12]])
            self.ether_type = struct.unpack("!H", raw_header[12:14])[0]

        # Packet building
        else:
            self.tracker = child_packet.tracker

            self.ether_dst = ether_dst
            self.ether_src = ether_src

            assert child_packet.protocol in {"IPv6", "IPv4", "ARP"}, f"Not supported protocol: {child_packet.protocol}"

            if child_packet.protocol == "IPv6":
                self.ether_type = ETHER_TYPE_IPV6

            if child_packet.protocol == "IPv4":
                self.ether_type = ETHER_TYPE_IPV4

            if child_packet.protocol == "ARP":
                self.ether_type = ETHER_TYPE_ARP

            self.raw_data = child_packet.get_raw_packet()

    def __str__(self):
        """ Short packet log string """

        return f"ETHER {self.ether_src} > {self.ether_dst}, 0x{self.ether_type:0>4x} ({ETHER_TYPE_TABLE.get(self.ether_type, '???')})"

    def __len__(self):
        """ Length of the packet """

        return len(self.raw_packet)

    @property
    def raw_header(self):
        """ Packet header in raw format """

        return struct.pack("! 6s 6s H", bytes.fromhex(self.ether_dst.replace(":", "")), bytes.fromhex(self.ether_src.replace(":", "")), self.ether_type)

    @property
    def raw_packet(self):
        """ Packet in raw format """

        return self.raw_header + self.raw_data

    def get_raw_packet(self):
        """ Get packet in raw frmat ready to be sent out """

        return self.raw_packet
