#!/usr/bin/env python3

"""

PyTCP, Python TCP/IP stack, version 0.1 - 2020, Sebastian Majewski
ps_icmpv6.py - protocol support libary for ICMPv6

"""

import struct

import inet_cksum

from tracker import Tracker


"""

   ICMPv6 packet header - simplified support, only ping echo/reply messages

   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |     Type      |     Code      |           Checksum            |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

   
   Destination Unreachable message (1/[0,1,3,4])

   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |              Id               |              Seq              |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                               0                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   ~                             Data                              ~
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

   
   Echo Request message (128/0)

   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |              Id               |              Seq              |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   ~                             Data                              ~
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

   
   Echo Reply message (129/0)

   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |              Id               |              Seq              |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   ~                             Data                              ~
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


"""

ICMPV6_HEADER_LEN = 4

ICMPV6_UNREACHABLE = 1
ICMPV6_UNREACHABLE_LEN = 32
ICMPV6_UNREACHABLE_NOROUTE = 0
ICMPV6_UNREACHABLE_PROHIBITED = 1
ICMPV6_UNREACHABLE_ADDRESS = 2
ICMPV6_UNREACHABLE_PORT = 4

ICMPV6_ECHOREQUEST = 128
ICMPV6_ECHOREQUEST_LEN = 4

ICMPV6_ECHOREPLY = 129
ICMPV6_ECHOREPLY_LEN = 4


class ICMPv6Packet:
    """ ICMPv6 packet support class """

    protocol = "ICMPv6"

    def __init__(self, parent_packet=None, icmpv6_type=None, icmpv6_code=0, icmpv6_id=None, icmpv6_seq=None, icmpv6_raw_data=b"", echo_tracker=None):
        """ Class constructor """

        # Packet parsing
        if parent_packet:
            self.tracker = parent_packet.tracker

            raw_packet = parent_packet.raw_data
            raw_header = raw_packet[:ICMPV6_HEADER_LEN]
            raw_message = raw_packet[ICMPV6_HEADER_LEN:]

            self.icmpv6_type = raw_header[0]
            self.icmpv6_code = raw_header[1]
            self.icmpv6_cksum = struct.unpack("!H", raw_header[2:4])[0]

            if self.icmpv6_type == ICMPV6_ECHOREPLY:
                self.icmpv6_id = struct.unpack("!H", raw_message[0:2])[0]
                self.icmpv6_seq = struct.unpack("!H", raw_message[2:4])[0]
                self.icmpv6_raw_data = raw_message[ICMPV6_ECHOREPLY_LEN:]

            if self.icmpv6_type == ICMPV6_ECHOREQUEST:
                self.icmpv6_id = struct.unpack("!H", raw_message[0:2])[0]
                self.icmpv6_seq = struct.unpack("!H", raw_message[2:4])[0]
                self.icmpv6_raw_data = raw_message[ICMPV6_ECHOREQUEST_LEN:]

            if self.icmpv6_type == ICMPV6_UNREACHABLE:
                self.icmpv6_raw_data = raw_message[4:]

        # Packet building
        else:
            self.tracker = Tracker("TX", echo_tracker)

            self.icmpv6_type = icmpv6_type
            self.icmpv6_code = icmpv6_code
            self.icmpv6_cksum = 0

            if self.icmpv6_type == ICMPV6_ECHOREPLY and self.icmpv6_code == 0:
                self.icmpv6_id = icmpv6_id
                self.icmpv6_seq = icmpv6_seq
                self.icmpv6_raw_data = icmpv6_raw_data

            if self.icmpv6_type == ICMPV6_ECHOREQUEST and self.icmpv6_code == 0:
                self.icmpv6_id = icmpv6_id
                self.icmpv6_seq = icmpv6_seq
                self.icmpv6_raw_data = icmpv6_raw_data

            if self.icmpv6_type == ICMPV6_UNREACHABLE:
                self.icmpv6_raw_data = icmpv6_raw_data[:520]

    def __str__(self):
        """ Short packet log string """

        log = f"ICMPv6 type {self.icmpv6_type}, code {self.icmpv6_code}"

        if self.icmpv6_type == ICMPV6_ECHOREPLY:
            log += f", id {self.icmpv6_id}, seq {self.icmpv6_seq}"

        if self.icmpv6_type == ICMPV6_ECHOREQUEST:
            log += f", id {self.icmpv6_id}, seq {self.icmpv6_seq}"

        if self.icmpv6_type == ICMPV6_UNREACHABLE:
            pass

        return log

    def __len__(self):
        """ Length of the packet """

        return len(self.raw_packet)

    @property
    def raw_header(self):
        """ Get packet header in raw format """

        return struct.pack("! BBH", self.icmpv6_type, self.icmpv6_code, self.icmpv6_cksum)

    @property
    def raw_message(self):
        """ Get packet message in raw format """

        if self.icmpv6_type == ICMPV6_ECHOREPLY:
            return struct.pack("! HH", self.icmpv6_id, self.icmpv6_seq) + self.icmpv6_raw_data

        if self.icmpv6_type == ICMPV6_ECHOREQUEST:
            return struct.pack("! HH", self.icmpv6_id, self.icmpv6_seq) + self.icmpv6_raw_data

        if self.icmpv6_type == ICMPV6_UNREACHABLE:
            return struct.pack("! HH", 0, stack.mtu if self.code == 4 else 0) + self.icmpv6_raw_data

        return b""

    @property
    def raw_packet(self):
        """ Get packet in raw format """

        return self.raw_header + self.raw_message

    def get_raw_packet(self, ipv6_pseudo_header):
        """ Get packet in raw format ready to be processed by lower level protocol """

        self.icmpv6_cksum = inet_cksum.compute_cksum(ipv4_pseudo_header + self.raw_packet)

        return self.raw_packet

    def validate_cksum(self):
        """ Validate packet checksum """

        return not bool(inet_cksum.compute_cksum(self.raw_packet))
