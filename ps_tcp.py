#!/usr/bin/env python3

"""

PyTCP, Python TCP/IP stack, version 0.1 - 2020, Sebastian Majewski
ps_tct.py - protocol support libary for TCP

"""


import struct

import inet_cksum

from tracker import Tracker


"""

   TCP packet header (RFC 793)

   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |          Source Port          |       Destination Port        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                        Sequence Number                        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                    Acknowledgment Number                      |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |  Data |           |U|A|P|R|S|F|                               |
   | Offset| Reserved  |R|C|S|S|Y|I|            Window             |
   |       |           |G|K|H|T|N|N|                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |           Checksum            |         Urgent Pointer        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                    Options                    |    Padding    |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                             data                              |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

"""


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
        tcp_options=[],
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

            self.tcp_options = tcp_options

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
            self.tcp_hlen << 2 | self.tcp_flag_ns,
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

        return 1

    @property
    def tcp_sackperm(self):
        """ TCP option - Sack Permit (4) """

        for option in self.tcp_options:
            if option.opt_kind == TCP_OPT_SACKPERM:
                return True

    @property
    def tcp_timestamp(self):
        """ TCP option - Timestamp (8) """

        for option in self.tcp_options:
            if option.opt_kind == TCP_OPT_TIMESTAMP:
                return option.opt_tsval, option.opt_tsecr


"""

   TCP options

"""


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
            self.opt_len = TCP_OPT_WSCLAE_LEN
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
            self.opt_kind = TCP_OPT_MSS
            self.opt_len = TCP_OPT_MSS_LEN
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

    def __init__(self, raw_option=None):
        self.opt_kind = raw_option[0]
        self.opt_len = raw_option[1]
        self.opt_data = raw_option[2 : self.opt_len - 2]

    @property
    def raw_option(self):
        return struct.pack("! BB", self.opt_kind, self.opt_len) + self.opt_data

    def __str__(self):
        return "unk"
