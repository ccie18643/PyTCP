#!/usr/bin/env python3

"""

PyTCP, Python TCP/IP stack simulation version 0.1 - 2020, Sebastian Majewski
ph_ethernet.py - packet handler libary for Ethernet protocol

"""

import struct


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


ETHER_TYPE_MIN = 0x0600
ETHER_TYPE_ARP = 0x0806
ETHER_TYPE_IP = 0x0800


ETHER_TYPE_TABLE = {
    ETHER_TYPE_IP: "IP",
    ETHER_TYPE_ARP: "ARP",
}


class EtherPacket:
    """ Base class for Ethernet packet """

    @property
    def log(self):
        """ Short packet log string """

        return f"Ethernet {self.hdr_src} > {self.hdr_dst}, 0x{self.hdr_type:0>4x} ({ETHER_TYPE_TABLE.get(self.hdr_type, '???')})"

    @property
    def dump(self):
        """ Verbose packet debug string """

        return (
            "--------------------------------------------------------------------------------\n"
            + f"ETH      SRC {self.hdr_src}  DST {self.hdr_dst}  TYPE 0x{self.hdr_type:0>4x} ({ETHER_TYPE_TABLE.get(self.hdr_type, '???')})"
        )


class EtherPacketIn(EtherPacket):
    """ Ethernet packet parse class """

    serial_number = 0

    def __init__(self, raw_packet):
        """ Class constructor """

        self.raw_packet = raw_packet

        self.hdr_dst = ":".join([f"{_:0>2x}" for _ in self.raw_header[0:6]])
        self.hdr_src = ":".join([f"{_:0>2x}" for _ in self.raw_header[6:12]])
        self.hdr_type = struct.unpack("!H", self.raw_header[12:14])[0]
        
        self.serial_number = f"RX{EtherPacketIn.serial_number:0>4x}".upper()
        EtherPacketIn.serial_number += 1
        if EtherPacketIn.serial_number > 0xFFFF:
            EtherPacketIn.serial_number = 0

    @property
    def raw_header(self):
        """ Get packet header in raw format """

        return self.raw_packet[:14]

    @property
    def raw_data(self):
        """ Get packet data in raw format """

        return self.raw_packet[14:]


class EtherPacketOut(EtherPacket):
    """ Ethernet packet creation class """

    serial_number = 0

    def __init__(self, hdr_src, hdr_dst, hdr_type, raw_data=b""):
        """ Class constructor """

        self.hdr_dst = hdr_dst
        self.hdr_src = hdr_src
        self.hdr_type = hdr_type
        self.raw_data = raw_data

        self.serial_number = f"TX{EtherPacketOut.serial_number:0>4x}".upper()
        EtherPacketOut.serial_number += 1
        if EtherPacketOut.serial_number > 0xFFFF:
            EtherPacketOut.serial_number = 0

        self.retry_count = 0
        self.retry_time = 0

    @property
    def raw_header(self):
        """ Get packet header in raw format """

        return struct.pack(
            "! 6s 6s H",
            bytes.fromhex(self.hdr_dst.replace(":", "")),
            bytes.fromhex(self.hdr_src.replace(":", "")),
            self.hdr_type,
        )

    @property
    def raw_packet(self):
        """ Get packet header in raw format """

        return self.raw_header + self.raw_data
