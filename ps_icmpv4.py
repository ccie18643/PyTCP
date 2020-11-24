#!/usr/bin/env python3

"""

PyTCP, Python TCP/IP stack, version 0.1 - 2020, Sebastian Majewski
ps_icmpv4.py - protocol support libary for ICMPv4

"""

import struct

import inet_cksum

from tracker import Tracker


"""

   ICMPv6 packet header

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

ICMPV4_HEADER_LEN = 4

ICMPV4_ECHOREPLY = 0
ICMPV4_ECHOREPLY_LEN = 4

ICMPV4_ECHOREQUEST = 8
ICMPV4_ECHOREQUEST_LEN = 4

ICMPV4_UNREACHABLE = 3
ICMPV4_UNREACHABLE_LEN = 32
ICMPV4_UNREACHABLE_PORT = 3


class ICMPv4Packet:
    """ ICMPv4 packet support class """

    protocol = "ICMPv4"

    def __init__(self, parent_packet=None, icmpv4_type=None, icmpv4_code=0, icmpv4_id=None, icmpv4_seq=None, icmpv4_raw_data=b"", echo_tracker=None):
        """ Class constructor """

        # Packet parsing
        if parent_packet:
            self.tracker = parent_packet.tracker

            raw_packet = parent_packet.raw_data
            raw_header = raw_packet[:ICMPV4_HEADER_LEN]
            raw_message = raw_packet[ICMPV4_HEADER_LEN:]

            self.icmpv4_type = raw_header[0]
            self.icmpv4_code = raw_header[1]
            self.icmpv4_cksum = struct.unpack("!H", raw_header[2:4])[0]

            if self.icmpv4_type == ICMPV4_ECHOREPLY:
                self.icmpv4_id = struct.unpack("!H", raw_message[0:2])[0]
                self.icmpv4_seq = struct.unpack("!H", raw_message[2:4])[0]
                self.icmpv4_raw_data = raw_message[ICMPV4_ECHOREPLY_LEN:]

            if self.icmpv4_type == ICMPV4_ECHOREQUEST:
                self.icmpv4_id = struct.unpack("!H", raw_message[0:2])[0]
                self.icmpv4_seq = struct.unpack("!H", raw_message[2:4])[0]
                self.icmpv4_raw_data = raw_message[ICMPV4_ECHOREQUEST_LEN:]

            if self.icmpv4_type == ICMPV4_UNREACHABLE:
                self.icmpv4_raw_data = raw_message[4:]

        # Packet building
        else:
            self.tracker = Tracker("TX", echo_tracker)

            self.icmpv4_type = icmpv4_type
            self.icmpv4_code = icmpv4_code
            self.icmpv4_cksum = 0

            if self.icmpv4_type == ICMPV4_ECHOREPLY and self.icmpv4_code == 0:
                self.icmpv4_id = icmpv4_id
                self.icmpv4_seq = icmpv4_seq
                self.icmpv4_raw_data = icmpv4_raw_data

            if self.icmpv4_type == ICMPV4_ECHOREQUEST and self.icmpv4_code == 0:
                self.icmpv4_id = icmpv4_id
                self.icmpv4_seq = icmpv4_seq
                self.icmpv4_raw_data = icmpv4_raw_data

            if self.icmpv4_type == ICMPV4_UNREACHABLE:
                self.icmpv4_raw_data = icmpv4_raw_data[:520]

    def __str__(self):
        """ Short packet log string """

        log = f"ICMPv4 type {self.icmpv4_type}, code {self.icmpv4_code}"

        if self.icmpv4_type == ICMPV4_ECHOREPLY:
            log += f", id {self.icmpv4_id}, seq {self.icmpv4_seq}"

        if self.icmpv4_type == ICMPV4_ECHOREQUEST:
            log += f", id {self.icmpv4_id}, seq {self.icmpv4_seq}"

        if self.icmpv4_type == ICMPV4_UNREACHABLE:
            pass

        return log

    def __len__(self):
        """ Length of the packet """

        return len(self.raw_packet)

    @property
    def raw_header(self):
        """ Get packet header in raw format """

        return struct.pack("! BBH", self.icmpv4_type, self.icmpv4_code, self.icmpv4_cksum)

    @property
    def raw_message(self):
        """ Get packet message in raw format """

        if self.icmpv4_type == ICMPV4_ECHOREPLY:
            return struct.pack("! HH", self.icmpv4_id, self.icmpv4_seq) + self.icmpv4_raw_data

        if self.icmpv4_type == ICMPV4_ECHOREQUEST:
            return struct.pack("! HH", self.icmpv4_id, self.icmpv4_seq) + self.icmpv4_raw_data

        if self.icmpv4_type == ICMPV4_UNREACHABLE:
            return struct.pack("! HH", 0, stack.mtu if self.code == 4 else 0) + self.icmpv4_raw_data

        return b""

    @property
    def raw_packet(self):
        """ Get packet in raw format """

        return self.raw_header + self.raw_message

    def get_raw_packet(self):
        """ Get packet in raw format ready to be processed by lower level protocol """

        self.icmpv4_cksum = inet_cksum.compute_cksum(self.raw_packet)

        return self.raw_packet

    def validate_cksum(self):
        """ Validate packet checksum """

        return not bool(inet_cksum.compute_cksum(self.raw_packet))
