#!/usr/bin/env python3

"""

PyTCP, Python TCP/IP stack, version 0.1 - 2020, Sebastian Majewski
ps_icmpv4.py - protocol support libary for ICMPv4

"""

import struct
import inet_cksum
from tracker import Tracker


# Echo reply message (0/0)

# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |     Type      |     Code      |           Checksum            |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |              Id               |              Seq              |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# ~                             Data                              ~
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


# Destination Unreachable message (3/[0-3, 5-15])

# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |     Type      |     Code      |           Checksum            |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |              Id               |              Seq              |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                           Reserved                            |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# ~                             Data                              ~
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


# Destination Unreachable message (3/4)

# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |     Type      |     Code      |           Checksum            |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |              Id               |              Seq              |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |           Reserved            |          Link MTU / 0         |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# ~                             Data                              ~
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


# Echo Request message (8/0)

# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |     Type      |     Code      |           Checksum            |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |              Id               |              Seq              |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# ~                             Data                              ~
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


ICMPV4_ECHOREPLY = 0
ICMPV4_UNREACHABLE = 3
ICMPV4_UNREACHABLE_NET = 0
ICMPV4_UNREACHABLE_HOST = 1
ICMPV4_UNREACHABLE_PROTOCOL = 2
ICMPV4_UNREACHABLE_PORT = 3
ICMPV4_UNREACHABLE_FAGMENTATION = 4
ICMPV4_UNREACHABLE_SOURCE_ROUTE_FAILED = 5
ICMPV4_ECHOREQUEST = 8


class ICMPv4Packet:
    """ ICMPv4 packet support class """

    protocol = "ICMPv4"

    def __init__(
        self,
        parent_packet=None,
        icmpv4_type=None,
        icmpv4_code=0,
        icmpv4_ec_id=None,
        icmpv4_ec_seq=None,
        icmpv4_ec_raw_data=b"",
        icmpv4_un_raw_data=b"",
        echo_tracker=None,
    ):
        """ Class constructor """

        # Packet parsing
        if parent_packet:
            self.tracker = parent_packet.tracker

            raw_message = parent_packet.raw_data

            self.icmpv4_type = raw_message[0]
            self.icmpv4_code = raw_message[1]
            self.icmpv4_cksum = struct.unpack("!H", raw_message[2:4])[0]

            if self.icmpv4_type == ICMPV4_ECHOREPLY:
                self.icmpv4_ec_id = struct.unpack("!H", raw_message[4:6])[0]
                self.icmpv4_ec_seq = struct.unpack("!H", raw_message[6:8])[0]
                self.icmpv4_ec_raw_data = raw_message[8:]

            if self.icmpv4_type == ICMPV4_UNREACHABLE:
                self.icmpv4_un_reserved = struct.unpack("!L", raw_message[4:6])[0]
                self.icmpv4_un_raw_data = raw_message[8:]

            if self.icmpv4_type == ICMPV4_ECHOREQUEST:
                self.icmpv4_ec_id = struct.unpack("!H", raw_message[4:6])[0]
                self.icmpv4_ec_seq = struct.unpack("!H", raw_message[6:8])[0]
                self.icmpv4_ec_raw_data = raw_message[8:]

        # Packet building
        else:
            self.tracker = Tracker("TX", echo_tracker)

            self.icmpv4_type = icmpv4_type
            self.icmpv4_code = icmpv4_code
            self.icmpv4_cksum = 0

            if self.icmpv4_type == ICMPV4_ECHOREPLY and self.icmpv4_code == 0:
                self.icmpv4_ec_id = icmpv4_ec_id
                self.icmpv4_ec_seq = icmpv4_ec_seq
                self.icmpv4_ec_raw_data = icmpv4_ec_raw_data

            if self.icmpv4_type == ICMPV4_UNREACHABLE and self.icmpv4_code == ICMPV4_UNREACHABLE_PORT:
                self.icmpv4_un_reserved = 0
                self.icmpv4_un_raw_data = icmpv4_un_raw_data[:520]

            if self.icmpv4_type == ICMPV4_ECHOREQUEST and self.icmpv4_code == 0:
                self.icmpv4_ec_id = icmpv4_ec_id
                self.icmpv4_ec_seq = icmpv4_ec_seq
                self.icmpv4_ec_raw_data = icmpv4_ec_raw_data

    def __str__(self):
        """ Short packet log string """

        log = f"ICMPv4 type {self.icmpv4_type}, code {self.icmpv4_code}"

        if self.icmpv4_type == ICMPV4_ECHOREPLY:
            log += f", id {self.icmpv4_ec_id}, seq {self.icmpv4_ec_seq}"

        if self.icmpv4_type == ICMPV4_UNREACHABLE and self.icmpv4_code == ICMPV4_UNREACHABLE_PORT:
            pass

        if self.icmpv4_type == ICMPV4_ECHOREQUEST:
            log += f", id {self.icmpv4_ec_id}, seq {self.icmpv4_ec_seq}"

        return log

    def __len__(self):
        """ Length of the packet """

        return len(self.raw_packet)

    @property
    def raw_message(self):
        """ Get packet message in raw format """

        if self.icmpv4_type == ICMPV4_ECHOREPLY:
            return (
                struct.pack("! BBH HH", self.icmpv4_type, self.icmpv4_code, self.icmpv4_cksum, self.icmpv4_ec_id, self.icmpv4_ec_seq) + self.icmpv4_ec_raw_data
            )

        if self.icmpv4_type == ICMPV4_UNREACHABLE and self.icmpv4_code == ICMPV4_UNREACHABLE_PORT:
            return struct.pack("! BBH L", self.icmpv4_type, self.icmpv4_code, self.icmpv4_cksum, self.icmpv4_un_reserved) + self.icmpv4_un_raw_data

        if self.icmpv4_type == ICMPV4_ECHOREQUEST:
            return (
                struct.pack("! BBH HH", self.icmpv4_type, self.icmpv4_code, self.icmpv4_cksum, self.icmpv4_ec_id, self.icmpv4_ec_seq) + self.icmpv4_ec_raw_data
            )

    @property
    def raw_packet(self):
        """ Get packet in raw format """

        return self.raw_message

    def get_raw_packet(self):
        """ Get packet in raw format ready to be processed by lower level protocol """

        self.icmpv4_cksum = inet_cksum.compute_cksum(self.raw_packet)

        return self.raw_packet

    def validate_cksum(self):
        """ Validate packet checksum """

        return not bool(inet_cksum.compute_cksum(self.raw_packet))
