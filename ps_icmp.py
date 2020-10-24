#!/usr/bin/env python3

"""

PyTCP, Python TCP/IP stack simulation version 0.1 - 2020, Sebastian Majewski
ps_icmp.py - protocol support libary for ICMP

"""

import struct

from tracker import Tracker


"""

   ICMP packet header - simplified support, only ping echo/reply messages

   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |     Type      |     Code      |           Checksum            |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


   Echo reply message (0/0)

   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |              Id               |              Seq              |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   ~                             Data                              ~
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


   Echo message (8/0)

   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |              Id               |              Seq              |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   ~                             Data                              ~
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

"""

ICMP_HEADER_LEN = 4

ICMP_ECHOREPLY = 0
ICMP_ECHOREPLY_LEN = 4

ICMP_ECHOREQUEST = 8
ICMP_ECHOREQUEST_LEN = 4

ICMP_UNREACHABLE = 3
ICMP_UNREACHABLE_LEN = 32
ICMP_UNREACHABLE_PORT = 3


class IcmpPacket:
    """ ICMP packet support class """

    protocol = "ICMP"

    def __init__(self, parent_packet=None, hdr_type=None, hdr_code=0, msg_id=None, msg_seq=None, msg_data=b"", echo_tracker=None):
        """ Class constructor """

        # Packet parsing
        if parent_packet:
            self.tracker = parent_packet.tracker

            raw_packet = parent_packet.raw_data
            raw_header = raw_packet[:ICMP_HEADER_LEN]
            raw_message = raw_packet[ICMP_HEADER_LEN:]

            self.hdr_type = raw_header[0]
            self.hdr_code = raw_header[1]
            self.hdr_cksum = struct.unpack("!H", raw_header[2:4])[0]

            if self.hdr_type == ICMP_ECHOREPLY:
                self.msg_id = struct.unpack("!H", raw_message[0:2])[0]
                self.msg_seq = struct.unpack("!H", raw_message[2:4])[0]
                self.msg_data = raw_message[ICMP_ECHOREPLY_LEN:]

            if self.hdr_type == ICMP_ECHOREQUEST:
                self.msg_id = struct.unpack("!H", raw_message[0:2])[0]
                self.msg_seq = struct.unpack("!H", raw_message[2:4])[0]
                self.msg_data = raw_message[ICMP_ECHOREQUEST_LEN:]

            if self.hdr_type == ICMP_UNREACHABLE:
                self.msg_ip_info = raw_message[4:]

        # Packet building
        else:
            self.tracker = Tracker("TX", echo_tracker)

            self.hdr_type = hdr_type
            self.hdr_code = hdr_code
            self.hdr_cksum = 0

            if self.hdr_type == ICMP_ECHOREPLY and self.hdr_code == 0:
                self.msg_id = msg_id
                self.msg_seq = msg_seq
                self.msg_data = msg_data

            if self.hdr_type == ICMP_ECHOREQUEST and self.hdr_code == 0:
                self.msg_id = msg_id
                self.msg_seq = msg_seq
                self.msg_data = msg_data

            if self.hdr_type == ICMP_UNREACHABLE:
                self.msg_data = msg_data[:520]

    def __str__(self):
        """ Short packet log string """

        log = f"ICMP type {self.hdr_type}, code {self.hdr_code}"

        if self.hdr_type == ICMP_ECHOREPLY:
            log += f", id {self.msg_id}, seq {self.msg_seq}"

        if self.hdr_type == ICMP_ECHOREQUEST:
            log += f", id {self.msg_id}, seq {self.msg_seq}"

        if self.hdr_type == ICMP_UNREACHABLE:
            pass

        return log

    def __len__(self):
        """ Length of the packet """

        return len(self.raw_packet)

    def compute_cksum(self):
        """ Compute checksum of the ICMP packet """

        cksum_data = self.raw_packet + (b"\0" if len(self.raw_packet) & 1 else b"")
        cksum_data = list(struct.unpack(f"! {len(cksum_data) >> 1}H", cksum_data))
        cksum_data[1] = 0
        cksum = sum(cksum_data)
        return ~((cksum & 0xFFFF) + (cksum >> 16)) & 0xFFFF

    @property
    def raw_header(self):
        """ Get packet header in raw format """

        return struct.pack("! BBH", self.hdr_type, self.hdr_code, self.hdr_cksum)

    @property
    def raw_message(self):
        """ Get packet message in raw format """

        if self.hdr_type == ICMP_ECHOREPLY:
            return struct.pack("! HH", self.msg_id, self.msg_seq) + self.msg_data

        if self.hdr_type == ICMP_ECHOREQUEST:
            return struct.pack("! HH", self.msg_id, self.msg_seq) + self.msg_data

        if self.hdr_type == ICMP_UNREACHABLE:
            return struct.pack("! L", 0) + self.msg_data

        return b""

    @property
    def raw_packet(self):
        """ Get packet in raw format """

        return self.raw_header + self.raw_message

    def get_raw_packet(self):
        """ Get packet in raw format ready to be processed by lower level protocol """

        self.hdr_cksum = self.compute_cksum()

        return self.raw_packet
