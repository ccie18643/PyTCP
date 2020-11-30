#!/usr/bin/env python3

############################################################################
#                                                                          #
#  PyTCP - Python TCP/IP stack                                             #
#  Copyright (C) 2020  Sebastian Majewski                                  #
#                                                                          #
#  This program is free software: you can redistribute it and/or modify    #
#  it under the terms of the GNU General Public License as published by    #
#  the Free Software Foundation, either version 3 of the License, or       #
#  (at your option) any later version.                                     #
#                                                                          #
#  This program is distributed in the hope that it will be useful,         #
#  but WITHOUT ANY WARRANTY; without even the implied warranty of          #
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the           #
#  GNU General Public License for more details.                            #
#                                                                          #
#  You should have received a copy of the GNU General Public License       #
#  along with this program.  If not, see <https://www.gnu.org/licenses/>.  #
#                                                                          #
#  Author's email: ccie18643@gmail.com                                     #
#  Github repository: https://github.com/ccie18643/PyTCP                   #
#                                                                          #
############################################################################

##############################################################################################
#                                                                                            #
#  This program is a work in progress and it changes on daily basis due to new features      #
#  being implemented, changes being made to already implemented features, bug fixes, etc.    #
#  Therefore if the current version is not working as expected try to clone it again the     #
#  next day or shoot me an email describing the problem. Any input is appreciated. Also      #
#  keep in mind that some features may be implemented only partially (as needed for stack    #
#  operation) or they may be implemented in sub-optimal or not 100% RFC compliant way (due   #
#  to lack of time) or last but not least they may contain bug(s) that i didn't notice yet.  #
#                                                                                            #
##############################################################################################


#
# ps_tct.py - protocol support libary for TCP
#


import struct

import inet_cksum
import stack
from tracker import Tracker

# TCP packet header (RFC 793)

# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |          Source Port          |       Destination Port        |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                        Sequence Number                        |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                    Acknowledgment Number                      |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |  Hlen | Res |N|C|E|U|A|P|R|S|F|            Window             |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |           Checksum            |         Urgent Pointer        |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# ~                    Options                    ~    Padding    ~
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


TCP_HEADER_LEN = 20


class TcpPacket:
    """ TCP packet support class """

    protocol = "TCP"

    def __init__(
        self,
        parent_packet=None,
        tcp_sport=None,
        tcp_dport=None,
        tcp_seq=0,
        tcp_ack=0,
        tcp_flag_ns=False,
        tcp_flag_crw=False,
        tcp_flag_ece=False,
        tcp_flag_urg=False,
        tcp_flag_ack=False,
        tcp_flag_psh=False,
        tcp_flag_rst=False,
        tcp_flag_syn=False,
        tcp_flag_fin=False,
        tcp_win=0,
        tcp_urp=0,
        tcp_options=None,
        raw_data=b"",
        tracker=None,
        echo_tracker=None,
    ):
        """ Class constructor """

        # Packet parsing
        if parent_packet:
            self.tracker = parent_packet.tracker

            raw_packet = parent_packet.raw_data
            raw_header = raw_packet[:TCP_HEADER_LEN]
            raw_options = raw_packet[TCP_HEADER_LEN : (raw_header[12] & 0b11110000) >> 2]

            self.raw_data = raw_packet[(raw_header[12] & 0b11110000) >> 2 :]
            self.ip_pseudo_header = parent_packet.ip_pseudo_header

            self.tcp_sport = struct.unpack("!H", raw_header[0:2])[0]
            self.tcp_dport = struct.unpack("!H", raw_header[2:4])[0]
            self.tcp_seq = struct.unpack("!L", raw_header[4:8])[0]
            self.tcp_ack = struct.unpack("!L", raw_header[8:12])[0]
            self.tcp_hlen = (raw_header[12] & 0b11110000) >> 2
            self.tcp_reserved = raw_header[12] & 0b00001110
            self.tcp_flag_ns = bool(raw_header[12] & 0b00000001)
            self.tcp_flag_crw = bool(raw_header[13] & 0b10000000)
            self.tcp_flag_ece = bool(raw_header[13] & 0b01000000)
            self.tcp_flag_urg = bool(raw_header[13] & 0b00100000)
            self.tcp_flag_ack = bool(raw_header[13] & 0b00010000)
            self.tcp_flag_psh = bool(raw_header[13] & 0b00001000)
            self.tcp_flag_rst = bool(raw_header[13] & 0b00000100)
            self.tcp_flag_syn = bool(raw_header[13] & 0b00000010)
            self.tcp_flag_fin = bool(raw_header[13] & 0b00000001)
            self.tcp_win = struct.unpack("!H", raw_header[14:16])[0]
            self.tcp_cksum = struct.unpack("!H", raw_header[16:18])[0]
            self.tcp_urp = struct.unpack("!H", raw_header[18:20])[0]

            self.tcp_options = []

            opt_cls = {
                TCP_OPT_MSS: TcpOptMss,
                TCP_OPT_WSCALE: TcpOptWscale,
                TCP_OPT_SACKPERM: TcpOptSackPerm,
                TCP_OPT_TIMESTAMP: TcpOptTimestamp,
            }

            i = 0

            while i < len(raw_options):

                if raw_options[i] == TCP_OPT_EOL:
                    self.tcp_options.append(TcpOptEol())
                    break

                if raw_options[i] == TCP_OPT_NOP:
                    self.tcp_options.append(TcpOptNop())
                    i += TCP_OPT_NOP_LEN
                    continue

                self.tcp_options.append(opt_cls.get(raw_options[i], TcpOptUnk)(raw_options[i : i + raw_options[i + 1]]))
                i += self.raw_options[i + 1]

        # Packet building
        else:
            if tracker:
                self.tracker = tracker
            else:
                self.tracker = Tracker("TX", echo_tracker)

            self.tcp_sport = tcp_sport
            self.tcp_dport = tcp_dport
            self.tcp_seq = tcp_seq
            self.tcp_ack = tcp_ack
            self.tcp_reserved = 0
            self.tcp_flag_ns = tcp_flag_ns
            self.tcp_flag_crw = tcp_flag_crw
            self.tcp_flag_ece = tcp_flag_ece
            self.tcp_flag_urg = tcp_flag_urg
            self.tcp_flag_ack = tcp_flag_ack
            self.tcp_flag_psh = tcp_flag_psh
            self.tcp_flag_rst = tcp_flag_rst
            self.tcp_flag_syn = tcp_flag_syn
            self.tcp_flag_fin = tcp_flag_fin
            self.tcp_win = tcp_win
            self.tcp_cksum = 0
            self.tcp_urp = tcp_urp

            self.tcp_options = [] if tcp_options is None else tcp_options

            self.raw_data = raw_data

            self.tcp_hlen = TCP_HEADER_LEN + len(self.raw_options)

            assert self.tcp_hlen % 4 == 0, "TCP header len is not multiplcation of 4 bytes, check options"

    @property
    def raw_header(self):
        """ Packet header in raw format """

        return struct.pack(
            "! HH L L BBH HH",
            self.tcp_sport,
            self.tcp_dport,
            self.tcp_seq,
            self.tcp_ack,
            self.tcp_hlen << 2 | self.tcp_reserved | self.tcp_flag_ns,
            self.tcp_flag_crw << 7
            | self.tcp_flag_ece << 6
            | self.tcp_flag_urg << 5
            | self.tcp_flag_ack << 4
            | self.tcp_flag_psh << 3
            | self.tcp_flag_rst << 2
            | self.tcp_flag_syn << 1
            | self.tcp_flag_fin,
            self.tcp_win,
            self.tcp_cksum,
            self.tcp_urp,
        )

    def __str__(self):
        """ Short packet log string """

        log = (
            f"TCP {self.tcp_sport} > {self.tcp_dport}, {'N' if self.tcp_flag_ns else ''}{'C' if self.tcp_flag_crw else ''}"
            + f"{'E' if self.tcp_flag_ece else ''}{'U' if self.tcp_flag_urg else ''}{'A' if self.tcp_flag_ack else ''}"
            + f"{'P' if self.tcp_flag_psh else ''}{'R' if self.tcp_flag_rst else ''}{'S' if self.tcp_flag_syn else ''}"
            + f"{'F' if self.tcp_flag_fin else ''}, seq {self.tcp_seq}, ack {self.tcp_ack}, win {self.tcp_win}, dlen {len(self.raw_data)}"
        )

        for option in self.tcp_options:
            log += ", " + str(option)

        return log

    def __len__(self):
        """ Length of the packet """

        return len(self.raw_packet)

    @property
    def raw_options(self):
        """ Packet options in raw format """

        raw_options = b""

        for option in self.tcp_options:
            raw_options += option.raw_option

        return raw_options

    @property
    def raw_packet(self):
        """ Packet in raw format """

        return self.raw_header + self.raw_options + self.raw_data

    def get_raw_packet(self, ip_pseudo_header):
        """ Get packet in raw format ready to be processed by lower level protocol """

        self.tcp_cksum = inet_cksum.compute_cksum(ip_pseudo_header + self.raw_packet)

        return self.raw_packet

    def validate_cksum(self, ip_pseudo_header):
        """ Validate packet checksum """

        return not bool(inet_cksum.compute_cksum(ip_pseudo_header + self.raw_packet))

    @property
    def tcp_mss(self):
        """ TCP option - Maximum Segment Size (2) """

        for option in self.tcp_options:
            if option.opt_kind == TCP_OPT_MSS:
                return option.opt_mss
        return 536

    @property
    def tcp_wscale(self):
        """ TCP option - Window Scale (3) """

        for option in self.tcp_options:
            if option.opt_kind == TCP_OPT_WSCALE:
                return 1 << option.opt_wscale
        return None

    @property
    def tcp_sackperm(self):
        """ TCP option - Sack Permit (4) """

        for option in self.tcp_options:
            if option.opt_kind == TCP_OPT_SACKPERM:
                return True
        return None

    @property
    def tcp_timestamp(self):
        """ TCP option - Timestamp (8) """

        for option in self.tcp_options:
            if option.opt_kind == TCP_OPT_TIMESTAMP:
                return option.opt_tsval, option.opt_tsecr
        return None


#
# TCP options
#


# TCP option - End of Option List (0)

TCP_OPT_EOL = 0
TCP_OPT_EOL_LEN = 1


class TcpOptEol:
    """ TCP option - End of Option List (0) """

    def __init__(self):
        self.opt_kind = TCP_OPT_EOL

    @property
    def raw_option(self):
        return struct.pack("!B", self.opt_kind)

    def __str__(self):
        return "eol"


# TCP option - No Operation (1)

TCP_OPT_NOP = 1
TCP_OPT_NOP_LEN = 1


class TcpOptNop:
    """ TCP option - No Operation (1) """

    def __init__(self):
        self.opt_kind = TCP_OPT_NOP

    @property
    def raw_option(self):
        return struct.pack("!B", self.opt_kind)

    def __str__(self):
        return "nop"


# TCP option - Maximum Segment Size (2)

TCP_OPT_MSS = 2
TCP_OPT_MSS_LEN = 4


class TcpOptMss:
    """ TCP option - Maximum Segment Size (2) """

    def __init__(self, raw_option=None, opt_mss=None):
        if raw_option:
            self.opt_kind = raw_option[0]
            self.opt_len = raw_option[1]
            self.opt_mss = struct.unpack("!H", raw_option[2:4])[0]
        else:
            self.opt_kind = TCP_OPT_MSS
            self.opt_len = TCP_OPT_MSS_LEN
            self.opt_mss = opt_mss

    @property
    def raw_option(self):
        return struct.pack("! BB H", self.opt_kind, self.opt_len, self.opt_mss)

    def __str__(self):
        return f"mss {self.opt_mss}"


# TCP option - Window Scale (3)

TCP_OPT_WSCALE = 3
TCP_OPT_WSCALE_LEN = 3


class TcpOptWscale:
    """ TCP option - Window Scale (3) """

    def __init__(self, raw_option=None, opt_wscale=None):
        if raw_option:
            self.opt_kind = raw_option[0]
            self.opt_len = raw_option[1]
            self.opt_wscale = raw_option[2]
        else:
            self.opt_kind = TCP_OPT_WSCALE
            self.opt_len = TCP_OPT_WSCALE_LEN
            self.opt_wscale = opt_wscale

    @property
    def raw_option(self):
        return struct.pack("! BB B", self.opt_kind, self.opt_len, self.opt_wscale)

    def __str__(self):
        return f"wscale {self.opt_wscale}"


# TCP option - Sack Permit (4)

TCP_OPT_SACKPERM = 4
TCP_OPT_SACKPERM_LEN = 2


class TcpOptSackPerm:
    """ TCP option - Sack Permit (4) """

    def __init__(self, raw_option=None):
        if raw_option:
            self.opt_kind = raw_option[0]
            self.opt_len = raw_option[1]
        else:
            self.opt_kind = TCP_OPT_SACKPERM
            self.opt_len = TCP_OPT_SACKPERM_LEN

    @property
    def raw_option(self):
        return struct.pack("! BB", self.opt_kind, self.opt_len)

    def __str__(self):
        return "sack_perm"


# TCP option - Timestamp

TCP_OPT_TIMESTAMP = 8
TCP_OPT_TIMESTAMP_LEN = 10


class TcpOptTimestamp:
    """ TCP option - Timestamp (8) """

    def __init__(self, raw_option=None, opt_tsval=None, opt_tsecr=None):
        if raw_option:
            self.opt_kind = raw_option[0]
            self.opt_len = raw_option[1]
            self.opt_tsval = struct.unpack("!L", raw_option[2:6])[0]
            self.opt_tsecr = struct.unpack("!L", raw_option[6:10])[0]
        else:
            self.opt_kind = TCP_OPT_TIMESTAMP
            self.opt_len = TCP_OPT_TIMESTAMP_LEN
            self.opt_tsval = opt_tsval
            self.opt_tsecr = opt_tsecr

    @property
    def raw_option(self):
        return struct.pack("! BB LL", self.opt_kind, self.opt_len, self.opt_tsval, self.opt_tsecr)

    def __str__(self):
        return f"ts {self.opt_tsval}/{self.opt_tsecr}"


# TCP option not supported by this stack


class TcpOptUnk:
    """ TCP option not supported by this stack """

    def __init__(self, raw_option):
        self.opt_kind = raw_option[0]
        self.opt_len = raw_option[1]
        self.opt_data = raw_option[2 : self.opt_len]

    @property
    def raw_option(self):
        return struct.pack("! BB", self.opt_kind, self.opt_len) + self.opt_data

    def __str__(self):
        return f"unk-{self.opt_kind}-{self.opt_len}"


#
#   TCP sanity check functions
#


def preliminary_sanity_check(raw_packet, tracker, logger):
    """ Preliminary sanity check to be run on raw TCP packet prior to packet parsing """

    if not stack.preliminary_packet_sanity_check:
        return True

    if len(raw_packet) < 20:
        logger.critical(f"{tracker} - TCP Sanity check fail - wrong packet length (I)")
        return False

    hlen = (raw_packet[12] & 0b11110000) >> 2
    if not 20 <= hlen <= len(raw_packet):
        logger.critical(f"{tracker} - TCP Sanity check fail - wrong packet length (II)")
        return False

    index = 20
    while index < hlen:
        if raw_packet[index] == TCP_OPT_EOL:
            break
        if raw_packet[index] == TCP_OPT_NOP:
            index += 1
            if index > hlen:
                logger.critical(f"{tracker} - TCP Sanity check fail - wrong option length (I)")
                return False
            continue
        if index + 1 > hlen:
            logger.critical(f"{tracker} - TCP Sanity check fail - wrong option length (II)")
            return False
        if raw_packet[index + 1] == 0:
            logger.critical(f"{tracker} - TCP Sanity check fail - wrong option length (III)")
            return False
        index += raw_packet[index + 1]
        if index > hlen:
            logger.critical(f"{tracker} - TCP Sanity check fail - wrong option length (IV)")
            return False

    return True
