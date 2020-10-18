#!/usr/bin/env python3

"""

PyTCP, Python TCP/IP stack simulation version 0.1 - 2020, Sebastian Majewski
ph_udp.py - packet handler libary for UDP  protocol

"""

import struct


"""

   UDP packet header (RFC 768)

   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |          Source port          |        Destination port       |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |             Length            |            Checksum           |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

"""


UDP_HEADER_LEN = 8


class UdpPacket:
    """ Packet support base class """

    protocol = "UDP"

    def validate_cksum(self):
        """ Validate checksum for UDP packet """

        cksum_data = list(
            struct.unpack(
                f"! {(len(self.ip_pseudo_header) + (self.hdr_len + 1 if self.hdr_len & 1 else self.hdr_len)) >> 1}H",
                self.ip_pseudo_header + self.raw_header + self.raw_data + (b"\0" if self.hdr_len & 1 else b""),
            )
        )
        cksum_data[6 + 3] = 0
        cksum = sum(cksum_data)
        return ~((cksum & 0xFFFF) + (cksum >> 16)) & 0xFFFF == self.hdr_cksum

    @property
    def log(self):
        """ Short packet log string """

        return f"UDP {self.hdr_sport} > {self.hdr_dport}, len {self.hdr_len}"

    @property
    def dump(self):
        """ Verbose packet debug string """

        return (
            "--------------------------------------------------------------------------------\n"
            + f"UDP      SPORT {self.hdr_sport}  DPORT {self.hdr_dport}  LEN {self.hdr_len}  "
            + f"CKSUM {self.hdr_cksum} ({'OK' if self.validate_cksum() else 'BAD'})"
        )


class UdpPacketRx(UdpPacket):
    """ Packet parse class """

    def __init__(self, parent_packet):
        """ Class constructor """

        self.raw_packet = parent_packet.raw_data
        self.ip_pseudo_header = parent_packet.ip_pseudo_header

        self.hdr_sport = struct.unpack("!H", self.raw_header[0:2])[0]
        self.hdr_dport = struct.unpack("!H", self.raw_header[2:4])[0]
        self.hdr_len = struct.unpack("!H", self.raw_header[4:6])[0]
        self.hdr_cksum = struct.unpack("!H", self.raw_header[6:8])[0]

    @property
    def raw_header(self):
        """ Get packet header in raw format """

        return self.raw_packet[:UDP_HEADER_LEN]

    @property
    def raw_data(self):
        """ Get packet data in raw format """

        return self.raw_packet[UDP_HEADER_LEN : struct.unpack("!H", self.raw_header[4:6])[0]]


class UdpPacketTx(UdpPacket):
    """ Packet creation class """

    serial_number_tx = 0

    def __init__(self, hdr_sport, hdr_dport, raw_data=b""):
        """ Class constructor """

        self.hdr_sport = hdr_sport
        self.hdr_dport = hdr_dport
        self.hdr_len = UDP_HEADER_LEN + len(raw_data)
        self.hdr_cksum = 0

        self.raw_data = raw_data

        ip_pseudo_header = None

    @property
    def raw_header(self):
        """ Get packet header in raw format """

        return struct.pack("! HH HH", self.hdr_sport, self.hdr_dport, self.hdr_len, self.hdr_cksum)

    @property
    def raw_packet(self):
        """ Get packet header in raw format """

        cksum_data = list(
            struct.unpack(
                f"! {(len(self.ip_pseudo_header) + (self.hdr_len + 1 if self.hdr_len & 1 else self.hdr_len)) >> 1}H",
                self.ip_pseudo_header + self.raw_header + self.raw_data + (b"\0" if self.hdr_len & 1 else b""),
            )
        )
        cksum = sum(cksum_data)
        self.hdr_cksum = ~((cksum & 0xFFFF) + (cksum >> 16)) & 0xFFFF

        return self.raw_header + self.raw_data
