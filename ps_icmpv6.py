#!/usr/bin/env python3

"""

PyTCP, Python TCP/IP stack, version 0.1 - 2020, Sebastian Majewski
ps_icmpv6.py - protocol support libary for ICMPv6

"""

from ipaddress import IPv6Address

import struct

import inet_cksum

from tracker import Tracker

import stack


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


   Router Solicitation message (133/0)

   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |     Type      |     Code      |          Checksum             |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                            Reserved                           |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |   Options ...
   +-+-+-+-+-+-+-+-+-+-+-+-

   'Source link-layer address' option
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |       1       |       1       |                               >
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               |
   >                           MAC Address                         |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


   Neighbor Solicitation message (135/0)

   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |     Type      |     Code      |          Checksum             |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                           Reserved                            |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               >
   +                                                               +
   >                                                               >
   +                       Target Address                          +
   >                                                               >
   +                                                               +
   >                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |   Options ...
   +-+-+-+-+-+-+-+-+-+-+-+-

   'Source link-layer address' option
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |       1       |       1       |                               >
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               +
   >                           MAC Address                         |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


   Neighbor Advertisement message (136/0)

   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |     Type      |     Code      |          Checksum             |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |R|S|O|                     Reserved                            |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               >
   +                                                               +
   >                                                               >
   +                       Target Address                          +
   >                                                               >
   +                                                               +
   >                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |   Options ...
   +-+-+-+-+-+-+-+-+-+-+-+-

   'Target link-layer address' option
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |       2       |       1       |                               >
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               +
   >                           MAC Address                         |
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

ICMPV6_ROUTER_SOLICITATION = 133
ICMPV6_ROUTER_SOLICITATION_LEN = 4

ICMPV6_ROUTER_ADVERTISEMENT = 134
ICMPV6_ROUTER_ACVERTISEMENT_LEN = 4

ICMPV6_NEIGHBOR_SOLICITATION = 135
ICMPV6_NEIGHBOR_SOLICITATION_LEN = 4

ICMPV6_NEIGHBOR_ADVERTISEMENT = 136
ICMPV6_NEIGHBOR_ADVERTISEMENT_LEN = 4


class ICMPv6Packet:
    """ ICMPv6 packet support class """

    protocol = "ICMPv6"

    def __init__(
        self,
        parent_packet=None,
        icmpv6_type=None,
        icmpv6_code=0,
        icmpv6_id=None,
        icmpv6_seq=None,
        icmpv6_raw_data=b"",
        icmpv6_nd_flag_r=False,
        icmpv6_nd_flag_s=False,
        icmpv6_nd_flag_o=False,
        icmpv6_nd_target_address=None,
        icmpv6_nd_options=[],
        echo_tracker=None,
    ):
        """ Class constructor """

        # Packet parsing
        if parent_packet:
            self.tracker = parent_packet.tracker

            raw_packet = parent_packet.raw_data
            raw_header = raw_packet[:ICMPV6_HEADER_LEN]
            raw_message = raw_packet[ICMPV6_HEADER_LEN:]

            # from binascii import hexlify
            # print(hexlify(raw_packet))

            self.icmpv6_type = raw_header[0]
            self.icmpv6_code = raw_header[1]
            self.icmpv6_cksum = struct.unpack("!H", raw_header[2:4])[0]

            self.icmpv6_nd_options = []

            if self.icmpv6_type == ICMPV6_ECHOREPLY:
                self.icmpv6_id = struct.unpack("!H", raw_message[0:2])[0]
                self.icmpv6_seq = struct.unpack("!H", raw_message[2:4])[0]
                self.icmpv6_raw_data = raw_message[ICMPV6_ECHOREPLY_LEN:]
                return

            if self.icmpv6_type == ICMPV6_ECHOREQUEST:
                self.icmpv6_id = struct.unpack("!H", raw_message[0:2])[0]
                self.icmpv6_seq = struct.unpack("!H", raw_message[2:4])[0]
                self.icmpv6_raw_data = raw_message[ICMPV6_ECHOREQUEST_LEN:]
                return

            if self.icmpv6_type == ICMPV6_UNREACHABLE:
                self.icmpv6_raw_data = raw_message[4:]
                return

            if self.icmpv6_type == ICMPV6_ROUTER_SOLICITATION:
                return

            if self.icmpv6_type == ICMPV6_ROUTER_ADVERTISEMENT:
                return

            if self.icmpv6_type == ICMPV6_NEIGHBOR_SOLICITATION:
                self.icmpv6_nd_target_address = IPv6Address(raw_message[4:20])
                self.icmpv6_nd_options = self.__read_nd_options(raw_message[20:])
                return

            if self.icmpv6_type == ICMPV6_NEIGHBOR_ADVERTISEMENT:
                self.icmpv6_nd_target_address = IPv6Address(raw_message[4:20])
                self.icmpv6_nd_flag_r = bool(raw_message[0] & 0b10000000)
                self.icmpv6_nd_flag_s = bool(raw_message[0] & 0b01000000)
                self.icmpv6_nd_flag_o = bool(raw_message[0] & 0b00100000)
                self.icmpv6_nd_options = self.__read_nd_options(raw_message[20:])
                return

        # Packet building
        else:
            self.tracker = Tracker("TX", echo_tracker)

            self.icmpv6_type = icmpv6_type
            self.icmpv6_code = icmpv6_code
            self.icmpv6_cksum = 0

            self.icmpv6_nd_options = icmpv6_nd_options

            if self.icmpv6_type == ICMPV6_ECHOREPLY and self.icmpv6_code == 0:
                self.icmpv6_id = icmpv6_id
                self.icmpv6_seq = icmpv6_seq
                self.icmpv6_raw_data = icmpv6_raw_data
                return

            if self.icmpv6_type == ICMPV6_ECHOREQUEST and self.icmpv6_code == 0:
                self.icmpv6_id = icmpv6_id
                self.icmpv6_seq = icmpv6_seq
                self.icmpv6_raw_data = icmpv6_raw_data
                return

            if self.icmpv6_type == ICMPV6_UNREACHABLE:
                self.icmpv6_raw_data = icmpv6_raw_data[:520]
                return

            if self.icmpv6_type == ICMPV6_ROUTER_SOLICITATION:
                return

            if self.icmpv6_type == ICMPV6_ROUTER_ADVERTISEMENT:
                return

            if self.icmpv6_type == ICMPV6_NEIGHBOR_SOLICITATION:
                self.icmpv6_nd_target_address = icmpv6_nd_target_address
                return

            if self.icmpv6_type == ICMPV6_NEIGHBOR_ADVERTISEMENT:
                self.icmpv6_nd_target_address = icmpv6_nd_target_address
                self.icmpv6_nd_flag_r = icmpv6_nd_flag_r
                self.icmpv6_nd_flag_s = icmpv6_nd_flag_s
                self.icmpv6_nd_flag_o = icmpv6_nd_flag_o
                return

    def __str__(self):
        """ Short packet log string """

        log = f"ICMPv6 type {self.icmpv6_type}, code {self.icmpv6_code}"

        if self.icmpv6_type == ICMPV6_ECHOREPLY:
            log += f", id {self.icmpv6_id}, seq {self.icmpv6_seq}"

        if self.icmpv6_type == ICMPV6_ECHOREQUEST:
            log += f", id {self.icmpv6_id}, seq {self.icmpv6_seq}"

        if self.icmpv6_type == ICMPV6_UNREACHABLE:
            pass

        if self.icmpv6_type == ICMPV6_ROUTER_SOLICITATION:
            pass

        if self.icmpv6_type == ICMPV6_ROUTER_ADVERTISEMENT:
            pass

        if self.icmpv6_type == ICMPV6_NEIGHBOR_SOLICITATION:
            log += f", target {self.icmpv6_nd_target_address}"

        if self.icmpv6_type == ICMPV6_NEIGHBOR_ADVERTISEMENT:
            log += f", target {self.icmpv6_nd_target_address}"
            log += f", flags {'R' if self.icmpv6_nd_flag_r else '-'}{'S' if self.icmpv6_nd_flag_s else '-'}{'O' if self.icmpv6_nd_flag_o else '-'}"

        for nd_option in self.icmpv6_nd_options:
            log += ", " + str(nd_option)

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

        if self.icmpv6_type == ICMPV6_ROUTER_SOLICITATION:
            return struct.pack("! L BB 6s", 0, 1, 1, bytes.fromhex(self.icmpv6_source_link_layer_address.replace(":", "")))

        if self.icmpv6_type == ICMPV6_ROUTER_ADVERTISEMENT:
            # *** Need to implement this ***
            pass

        if self.icmpv6_type == ICMPV6_NEIGHBOR_SOLICITATION:
            return (
                struct.pack(
                    "! L 16s",
                    0,
                    self.icmpv6_nd_target_address.packed,
                )
                + self.raw_nd_options
            )

        if self.icmpv6_type == ICMPV6_NEIGHBOR_ADVERTISEMENT:
            return (
                struct.pack(
                    "! L 16s",
                    (self.icmpv6_nd_flag_r << 31) | (self.icmpv6_nd_flag_s << 30) | (self.icmpv6_nd_flag_o << 29),
                    self.icmpv6_nd_target_address.packed,
                )
                + self.raw_nd_options
            )

        return b""

    @property
    def raw_packet(self):
        """ Get packet in raw format """

        return self.raw_header + self.raw_message

    def get_raw_packet(self, ip_pseudo_header):
        """ Get packet in raw format ready to be processed by lower level protocol """

        self.icmpv6_cksum = inet_cksum.compute_cksum(ip_pseudo_header + self.raw_packet)

        return self.raw_packet

    @property
    def raw_nd_options(self):
        """ ICMPv6 ND packet options in raw format """

        raw_nd_options = b""

        for option in self.icmpv6_nd_options:
            raw_nd_options += option.raw_option

        return raw_nd_options

    def validate_cksum(self, ip_pseudo_header):
        """ Validate packet checksum """

        # from binascii import hexlify
        # print(hexlify(self.raw_packet))

        return not bool(inet_cksum.compute_cksum(ip_pseudo_header + self.raw_packet))

    def __read_nd_options(self, raw_nd_options):
        """ Read options for Neighbor Discovery """

        opt_cls = {
            ICMPV6_ND_OPT_SLLA: ICMPv6NdOptSLLA,
            ICMPV6_ND_OPT_TLLA: ICMPv6NdOptTLLA,
        }

        i = 0
        nd_options = []

        while i < len(raw_nd_options):
            nd_options.append(opt_cls.get(raw_nd_options[i], ICMPv6NdOptUnk)(raw_nd_options[i : i + (raw_nd_options[i + 1] << 3)]))
            i += raw_nd_options[i + 1] << 3

        return nd_options

    @property
    def icmpv6_nd_opt_slla(self):
        """ ICMPv6 ND option - Source Link Layer Address (1) """

        for option in self.icmpv6_nd_options:
            if option.opt_code == ICMPV6_ND_OPT_SLLA:
                return option.opt_slla

    @property
    def icmpv6_nd_opt_tlla(self):
        """ ICMPv6 ND option - Target Link Layer Address (2) """

        for option in self.icmpv6_nd_options:
            if option.opt_code == ICMPV6_ND_OPT_TLLA:
                return option.opt_tlla


"""

    ICMPv6 Neighbor Discovery options

"""

# ICMPv6 ND option - Source Link Layer Address (1)

ICMPV6_ND_OPT_SLLA = 1
ICMPV6_ND_OPT_SLLA_LEN = 8


class ICMPv6NdOptSLLA:
    """ ICMPv6 ND option - Source Link Layer Address (1) """

    def __init__(self, raw_option=None, opt_slla=None):
        if raw_option:
            self.opt_code = raw_option[0]
            self.opt_len = raw_option[1] << 3
            self.opt_slla = ":".join([f"{_:0>2x}" for _ in raw_option[2:8]])
        else:
            self.opt_code = ICMPV6_ND_OPT_SLLA
            self.opt_len = ICMPV6_ND_OPT_SLLA_LEN
            self.opt_slla = opt_slla

    @property
    def raw_option(self):
        return struct.pack("! BB 6s", self.opt_code, self.opt_len >> 3, bytes.fromhex(self.opt_slla.replace(":", "")))

    def __str__(self):
        return f"slla {self.opt_slla}"


# ICMPv6 ND option - Target Link Layer Address (2)

ICMPV6_ND_OPT_TLLA = 2
ICMPV6_ND_OPT_TLLA_LEN = 8


class ICMPv6NdOptTLLA:
    """ ICMPv6 ND option - Target Link Layer Address (2) """

    def __init__(self, raw_option=None, opt_tlla=None):
        if raw_option:
            self.opt_code = raw_option[0]
            self.opt_len = raw_option[1] << 3
            self.opt_tlla = ":".join([f"{_:0>2x}" for _ in raw_option[2:8]])
        else:
            self.opt_code = ICMPV6_ND_OPT_TLLA
            self.opt_len = ICMPV6_ND_OPT_TLLA_LEN
            self.opt_tlla = opt_tlla

    @property
    def raw_option(self):
        return struct.pack("! BB 6s", self.opt_code, self.opt_len >> 3, bytes.fromhex(self.opt_tlla.replace(":", "")))

    def __str__(self):
        return f"tlla {self.opt_tlla}"


# ICMPv6 ND option not supported by this stack


class ICMPv6NdOptUnk:
    """ ICMPv6 ND  option not supported by this stack """

    def __init__(self, raw_option):
        self.opt_code = raw_option[0]
        self.opt_len = raw_option[1] << 3
        self.opt_data = raw_option[2 : self.opt_len]

    @property
    def raw_option(self):
        return struct.pack("! BB", self.opt_code, self.opt_len >> 3) + self.opt_data

    def __str__(self):
        return "unk"
