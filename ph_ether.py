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
    """ Packet support base class """

    @property
    def log(self):
        """ Short packet log string """

        return f"Ethernet {self.hdr_src} > {self.hdr_dst}, 0x{self.hdr_type:0>4x} ({ETHER_TYPE_TABLE.get(self.hdr_type, '???')})"

    @property
    def dump(self):
        """ Verbose packet debug string """

        return (
            "--------------------------------------------------------------------------------\n"
            + f"ETHER    SRC {self.hdr_src}  DST {self.hdr_dst}  TYPE 0x{self.hdr_type:0>4x} ({ETHER_TYPE_TABLE.get(self.hdr_type, '???')})"
        )


class EtherPacketRx(EtherPacket):
    """ Packet parse class """

    protocol = "Ethernet"

    serial_number_rx = 0

    def __init__(self, raw_packet):
        """ Class constructor """

        self.timestamp_rx = time.time()

        self.serial_number_rx = f"RX{EtherPacketRx.serial_number_rx:0>4x}".upper()
        EtherPacketRx.serial_number_rx += 1
        if EtherPacketRx.serial_number_rx > 0xFFFF:
            EtherPacketRx.serial_number_rx = 0

        self.raw_packet = raw_packet

        self.hdr_dst = ":".join([f"{_:0>2x}" for _ in self.raw_header[0:6]])
        self.hdr_src = ":".join([f"{_:0>2x}" for _ in self.raw_header[6:12]])
        self.hdr_type = struct.unpack("!H", self.raw_header[12:14])[0]

    @property
    def raw_header(self):
        """ Get packet header in raw format """

        return self.raw_packet[:ETHER_HEADER_LEN]

    @property
    def raw_data(self):
        """ Get packet data in raw format """

        return self.raw_packet[ETHER_HEADER_LEN:]


class EtherPacketTx(EtherPacket):
    """ Packet creation class """

    serial_number_tx = 0

    def __init__(self, hdr_src, hdr_dst, child_packet):
        """ Class constructor """

        self.timestamp_tx = time.time()

        self.serial_number_tx = f"TX{EtherPacketTx.serial_number_tx:0>4x}".upper()
        EtherPacketTx.serial_number_tx += 1
        if EtherPacketTx.serial_number_tx > 0xFFFF:
            EtherPacketTx.serial_number_tx = 0

        self.hdr_dst = hdr_dst
        self.hdr_src = hdr_src

        if child_packet.protocol == "IP":
            self.hdr_type = ETHER_TYPE_IP
            self.raw_data = child_packet.get_raw_packet()

        elif child_packet.protocol == "ARP":
            self.hdr_type = ETHER_TYPE_ARP
            self.raw_data = child_packet.get_raw_packet()

        else:
            raise Exception(f"Not supported protocol: {child_packet.protocol}")

    @property
    def raw_header(self):
        """ Get packet header in raw format """

        return struct.pack("! 6s 6s H", bytes.fromhex(self.hdr_dst.replace(":", "")), bytes.fromhex(self.hdr_src.replace(":", "")), self.hdr_type)

    @property
    def raw_packet(self):
        """ Get packet header in raw format """

        return self.raw_header + self.raw_data
