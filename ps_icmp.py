#!/usr/bin/env python3

"""

PyTCP, Python TCP/IP stack, version 0.1 - 2020, Sebastian Majewski
ps_icmp.py - protocol support libary for ICMP

"""

import struct

import inet_cksum

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

    def __init__(self, parent_packet=None, icmp_type=None, icmp_code=0, icmp_id=None, icmp_seq=None, icmp_raw_data=b"", echo_tracker=None):
        """ Class constructor """

        # Packet parsing
        if parent_packet:
            self.tracker = parent_packet.tracker

            raw_packet = parent_packet.raw_data
            raw_header = raw_packet[:ICMP_HEADER_LEN]
            raw_message = raw_packet[ICMP_HEADER_LEN:]

            self.icmp_type = raw_header[0]
            self.icmp_code = raw_header[1]
            self.icmp_cksum = struct.unpack("!H", raw_header[2:4])[0]

            if self.icmp_type == ICMP_ECHOREPLY:
                self.icmp_id = struct.unpack("!H", raw_message[0:2])[0]
                self.icmp_seq = struct.unpack("!H", raw_message[2:4])[0]
                self.icmp_raw_data = raw_message[ICMP_ECHOREPLY_LEN:]

            if self.icmp_type == ICMP_ECHOREQUEST:
                self.icmp_id = struct.unpack("!H", raw_message[0:2])[0]
                self.icmp_seq = struct.unpack("!H", raw_message[2:4])[0]
                self.icmp_raw_data = raw_message[ICMP_ECHOREQUEST_LEN:]

            if self.icmp_type == ICMP_UNREACHABLE:
                self.icmp_raw_data = raw_message[4:]

        # Packet building
        else:
            self.tracker = Tracker("TX", echo_tracker)

            self.icmp_type = icmp_type
            self.icmp_code = icmp_code
            self.icmp_cksum = 0

            if self.icmp_type == ICMP_ECHOREPLY and self.icmp_code == 0:
                self.icmp_id = icmp_id
                self.icmp_seq = icmp_seq
                self.icmp_raw_data = icmp_raw_data

            if self.icmp_type == ICMP_ECHOREQUEST and self.icmp_code == 0:
                self.icmp_id = icmp_id
                self.icmp_seq = icmp_seq
                self.icmp_raw_data = icmp_raw_data

            if self.icmp_type == ICMP_UNREACHABLE:
                self.icmp_raw_data = icmp_raw_data[:520]

    def __str__(self):
        """ Short packet log string """

        log = f"ICMP type {self.icmp_type}, code {self.icmp_code}"

        if self.icmp_type == ICMP_ECHOREPLY:
            log += f", id {self.icmp_id}, seq {self.icmp_seq}"

        if self.icmp_type == ICMP_ECHOREQUEST:
            log += f", id {self.icmp_id}, seq {self.icmp_seq}"

        if self.icmp_type == ICMP_UNREACHABLE:
            pass

        return log

    def __len__(self):
        """ Length of the packet """

        return len(self.raw_packet)

    @property
    def raw_header(self):
        """ Get packet header in raw format """

        return struct.pack("! BBH", self.icmp_type, self.icmp_code, self.icmp_cksum)

    @property
    def raw_message(self):
        """ Get packet message in raw format """

        if self.icmp_type == ICMP_ECHOREPLY:
            return struct.pack("! HH", self.icmp_id, self.icmp_seq) + self.icmp_raw_data

        if self.icmp_type == ICMP_ECHOREQUEST:
            return struct.pack("! HH", self.icmp_id, self.icmp_seq) + self.icmp_raw_data

        if self.icmp_type == ICMP_UNREACHABLE:
            return struct.pack("! L", 0) + self.icmp_raw_data

        return b""

    @property
    def raw_packet(self):
        """ Get packet in raw format """

        return self.raw_header + self.raw_message

    def get_raw_packet(self):
        """ Get packet in raw format ready to be processed by lower level protocol """

        self.icmp_cksum = inet_cksum.compute_cksum(self.raw_packet)

        return self.raw_packet

    def validate_cksum(self):
        """ Validate packet checksum """

        return not bool(inet_cksum.compute_cksum(self.raw_packet))
