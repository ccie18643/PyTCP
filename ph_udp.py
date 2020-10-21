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
    """ UDP packet support class """

    protocol = "UDP"

    def __init__(self, parent_packet=None, hdr_sport=None, hdr_dport=None, raw_data=None):
        """ Class constructor """

        # Packet parsing
        if parent_packet:
            raw_packet = parent_packet.raw_data
            raw_header = raw_packet[:UDP_HEADER_LEN]

            self.raw_data = raw_packet[UDP_HEADER_LEN : struct.unpack("!H", raw_header[4:6])[0]]
            self.ip_pseudo_header = parent_packet.ip_pseudo_header

            self.hdr_sport = struct.unpack("!H", raw_header[0:2])[0]
            self.hdr_dport = struct.unpack("!H", raw_header[2:4])[0]
            self.hdr_len = struct.unpack("!H", raw_header[4:6])[0]
            self.hdr_cksum = struct.unpack("!H", raw_header[6:8])[0]

        # Packet building
        else:
            self.hdr_sport = hdr_sport
            self.hdr_dport = hdr_dport
            self.hdr_len = UDP_HEADER_LEN + len(raw_data)
            self.hdr_cksum = 0

            self.raw_data = raw_data

    @property
    def raw_header(self):
        """ Packet header in raw format """

        return struct.pack("! HH HH", self.hdr_sport, self.hdr_dport, self.hdr_len, self.hdr_cksum)

    @property
    def raw_packet(self):
        """ Packet in raw format """

        return self.raw_header + self.raw_data

    def get_raw_packet(self, ip_pseudo_header):
        """ Get packet in raw format ready to be processed by lower level protocol """

        self.hdr_cksum = self.compute_cksum(ip_pseudo_header)

        return self.raw_packet

    def compute_cksum(self, ip_pseudo_header):
        """ Compute checksum of IP pseudo header + UDP packet """

        cksum_data = ip_pseudo_header + self.raw_packet + (b"\0" if len(self.raw_packet) & 1 else b"")
        cksum_data = list(struct.unpack(f"! {len(cksum_data) >> 1}H", cksum_data))
        cksum_data[6 + 3] = 0
        cksum = sum(cksum_data)
        return ~((cksum & 0xFFFF) + (cksum >> 16)) & 0xFFFF

    def __str__(self):
        """ Short packet log string """

        return f"UDP {self.hdr_sport} > {self.hdr_dport}, len {self.hdr_len}"
