#!/usr/bin/env python3

"""

PyTCP, Python TCP/IP stack simulation version 0.1 - 2020, Sebastian Majewski
ph_ethernet.py - packet handler libary for Ethernet protocol

"""

import struct
import time


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
ETHER_TYPE_IP = 0x0800
ETHER_TYPE_IPV6 = 0x86DD


ETHER_TYPE_TABLE = {ETHER_TYPE_ARP: "ARP", ETHER_TYPE_IP: "IP", ETHER_TYPE_IPV6: "IPv6"}


class EtherPacket:
    """ Ethernet packet support class """

    protocol = "ETHER"

    serial_number_rx = 0
    serial_number_tx = 0

    def __init__(self, raw_packet=None, hdr_src="00:00:00:00:00:00", hdr_dst="00:00:00:00:00:00", child_packet=None):
        """ Class constructor """

        # Packet parsing
        if raw_packet:
            self.timestamp_rx = time.time()

            self.serial_number_rx = f"RX{EtherPacket.serial_number_rx:0>4x}".upper()
            EtherPacket.serial_number_rx += 1
            if EtherPacket.serial_number_rx > 0xFFFF:
                EtherPacket.serial_number_rx = 0

            raw_header = raw_packet[:ETHER_HEADER_LEN]

            self.raw_data = raw_packet[ETHER_HEADER_LEN:]

            self.hdr_dst = ":".join([f"{_:0>2x}" for _ in raw_header[0:6]])
            self.hdr_src = ":".join([f"{_:0>2x}" for _ in raw_header[6:12]])
            self.hdr_type = struct.unpack("!H", raw_header[12:14])[0]

        # Packet building
        else:
            self.serial_number_tx = f"TX{EtherPacket.serial_number_tx:0>4x}".upper()
            EtherPacket.serial_number_tx += 1
            if EtherPacket.serial_number_tx > 0xFFFF:
                EtherPacket.serial_number_tx = 0

            self.hdr_dst = hdr_dst
            self.hdr_src = hdr_src

            assert child_packet.protocol in {"IP", "ARP"}, f"Not supported protocol: {child_packet.protocol}"

            if child_packet.protocol == "IP":
                self.hdr_type = ETHER_TYPE_IP
                self.raw_data = child_packet.get_raw_packet()

            if child_packet.protocol == "ARP":
                self.hdr_type = ETHER_TYPE_ARP
                self.raw_data = child_packet.get_raw_packet()

    def __str__(self):
        """ Short packet log string """

        return f"ETHER {self.hdr_src} > {self.hdr_dst}, 0x{self.hdr_type:0>4x} ({ETHER_TYPE_TABLE.get(self.hdr_type, '???')})"

    @property
    def raw_header(self):
        """ Packet header in raw format """

        return struct.pack("! 6s 6s H", bytes.fromhex(self.hdr_dst.replace(":", "")), bytes.fromhex(self.hdr_src.replace(":", "")), self.hdr_type)

    @property
    def raw_packet(self):
        """ Packet in raw format """

        return self.raw_header + self.raw_data

    def get_raw_packet(self):
        """ Get packet in raw frmat ready to be sent out """

        return self.raw_packet
