#!/usr/bin/env python3

"""

PyTCP, Python TCP/IP stack simulation version 0.1 - 2020, Sebastian Majewski
ph_tct.py - packet handler libary for TCP  protocol

"""

import struct


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
    """ Packet support base class """

    protocol = "TCP"

    def compute_cksum(self, ip_pseudo_header):
        """ Compute checksum of IP pseudo header + TCP packet """

        cksum_data = ip_pseudo_header + self.raw_packet + (b"\0" if len(self.raw_packet) & 1 else b"")
        cksum_data = list(struct.unpack(f"! {len(cksum_data) >> 1}H", cksum_data))
        cksum_data[6 + 8] = 0
        cksum = sum(cksum_data)
        return ~((cksum & 0xFFFF) + (cksum >> 16)) & 0xFFFF

    def __str__(self):
        """ Short packet log string """

        log =  (
            f"TCP {self.hdr_sport} > {self.hdr_dport}, "
            + f"{'N' if self.hdr_flag_ns else ''}"
            + f"{'C' if self.hdr_flag_crw else ''}"
            + f"{'E' if self.hdr_flag_ece else ''}"
            + f"{'U' if self.hdr_flag_urg else ''}"
            + f"{'A' if self.hdr_flag_ack else ''}"
            + f"{'P' if self.hdr_flag_psh else ''}"
            + f"{'R' if self.hdr_flag_rst else ''}"
            + f"{'S' if self.hdr_flag_syn else ''}"
            + f"{'F' if self.hdr_flag_fin else ''}"
            + f", seq {self.hdr_seq_num}, ack {self.hdr_ack_num}, win {self.hdr_win}"
        )

        for option in self.options:
            log += ", " + str(option)

        return log


class TcpPacketRx(TcpPacket):
    """ Packet parse class """

    def __init__(self, parent_packet):
        """ Class constructor """

        self.raw_packet = parent_packet.raw_data
        self.ip_pseudo_header = parent_packet.ip_pseudo_header

        self.hdr_sport = struct.unpack("!H", self.raw_header[0:2])[0]
        self.hdr_dport = struct.unpack("!H", self.raw_header[2:4])[0]
        self.hdr_seq_num = struct.unpack("!L", self.raw_header[4:8])[0]
        self.hdr_ack_num = struct.unpack("!L", self.raw_header[8:12])[0]
        self.hdr_hlen = (self.raw_header[12] & 0b11110000) >> 2
        self.hdr_flag_ns = bool(self.raw_header[12] & 0b00000001)
        self.hdr_flag_crw = bool(self.raw_header[13] & 0b10000000)
        self.hdr_flag_ece = bool(self.raw_header[13] & 0b01000000)
        self.hdr_flag_urg = bool(self.raw_header[13] & 0b00100000)
        self.hdr_flag_ack = bool(self.raw_header[13] & 0b00010000)
        self.hdr_flag_psh = bool(self.raw_header[13] & 0b00001000)
        self.hdr_flag_rst = bool(self.raw_header[13] & 0b00000100)
        self.hdr_flag_syn = bool(self.raw_header[13] & 0b00000010)
        self.hdr_flag_fin = bool(self.raw_header[13] & 0b00000001)
        self.hdr_win = struct.unpack("!H", self.raw_header[14:16])[0]
        self.hdr_cksum = struct.unpack("!H", self.raw_header[16:18])[0]
        self.hdr_urp = struct.unpack("!H", self.raw_header[18:20])[0]

    @property
    def raw_header(self):
        """ Get packet header in raw format """

        return self.raw_packet[:TCP_HEADER_LEN]

    @property
    def raw_options(self):
        """ Get packet options in raw format """

        return self.raw_packet[TCP_HEADER_LEN : (self.raw_header[12] & 0b11110000) >> 2]

    @property
    def raw_data(self):
        """ Get packet data in raw format """

        return self.raw_packet[(self.raw_header[12] & 0b11110000) >> 2 :]

    @property
    def options(self):
        """ Get list of options """

        options = []

        i = 0

        while i < len(self.raw_options):
            if self.raw_options[i] == TCP_OPT_EOL:
                options.append(TcpOptEol(self.raw_options[i : i + TCP_OPT_EOL_LEN]))
                break

            elif self.raw_options[i] == TCP_OPT_NOP:
                options.append(TcpOptNop(self.raw_options[i : i + TCP_OPT_NOP_LEN]))
                i += TCP_OPT_NOP_LEN

            elif self.raw_options[i] == TCP_OPT_MSS:
                options.append(TcpOptMss(self.raw_options[i : i + self.raw_options[i + 1]]))
                i += self.raw_options[i + 1]

            elif self.raw_options[i] == TCP_OPT_WSCALE:
                options.append(TcpOptWscale(self.raw_options[i : i + self.raw_options[i + 1]]))
                i += self.raw_options[i + 1]

            elif self.raw_options[i] == TCP_OPT_TIMESTAMP:
                options.append(TcpOptTimestamp(self.raw_options[i : i + self.raw_options[i + 1]]))
                i += self.raw_options[i + 1]

            else:
                i += self.raw_options[i + 1]

        return options


class TcpPacketTx(TcpPacket):
    """ Packet creation class """

    serial_number_tx = 0

    def __init__(
        self,
        hdr_sport,
        hdr_dport,
        hdr_seq_num=0,
        hdr_ack_num=0,
        hdr_flag_ns=False,
        hdr_flag_crw=False,
        hdr_flag_ece=False,
        hdr_flag_urg=False,
        hdr_flag_ack=False,
        hdr_flag_psh=False,
        hdr_flag_rst=False,
        hdr_flag_syn=False,
        hdr_flag_fin=False,
        hdr_win=0,
        hdr_urp=0,
        options=[],
        raw_data=b"",
    ):
        """ Class constructor """

        self.hdr_sport = hdr_sport
        self.hdr_dport = hdr_dport
        self.hdr_seq_num = hdr_seq_num
        self.hdr_ack_num = hdr_ack_num
        self.hdr_flag_ns = False
        self.hdr_flag_crw = False
        self.hdr_flag_ece = False
        self.hdr_flag_urg = False
        self.hdr_flag_ack = hdr_flag_ack
        self.hdr_flag_psh = False
        self.hdr_flag_rst = hdr_flag_rst
        self.hdr_flag_syn = hdr_flag_syn
        self.hdr_flag_fin = hdr_flag_fin
        self.hdr_win = hdr_win
        self.hdr_cksum = 0
        self.hdr_urp = hdr_urp

        self.options = options
        self.raw_data = raw_data

        self.hdr_hlen = TCP_HEADER_LEN + len(self.raw_options)

        assert self.hdr_hlen % 4 == 0, "TCP header len is not multiplcation of 4 bytes, check options" 

    @property
    def raw_header(self):
        """ Packet header in raw format """

        return struct.pack(
            "! HH L L BBH HH",
            self.hdr_sport,
            self.hdr_dport,
            self.hdr_seq_num,
            self.hdr_ack_num,
            self.hdr_hlen << 2 | self.hdr_flag_ns,
            self.hdr_flag_crw << 7
            | self.hdr_flag_ece << 6
            | self.hdr_flag_urg << 5
            | self.hdr_flag_ack << 4
            | self.hdr_flag_psh << 3
            | self.hdr_flag_rst << 2
            | self.hdr_flag_syn << 1
            | self.hdr_flag_fin,
            self.hdr_win,
            self.hdr_cksum,
            self.hdr_urp,
        )

    @property
    def raw_options(self):
        """ Packet options in raw format """

        raw_options = b""

        for option in self.options:
            raw_options += option.raw_option

        return raw_options

    @property
    def raw_packet(self):
        """ Packet in raw format """

        return self.raw_header + self.raw_options + self.raw_data

    def get_raw_packet(self, ip_pseudo_header):
        """ Get packet in raw format ready to be processed by lower level protocol """

        self.hdr_cksum = self.compute_cksum(ip_pseudo_header)

        return self.raw_packet


"""

   TCP options

"""


TCP_OPT_EOL = 0
TCP_OPT_EOL_LEN = 1
TCP_OPT_NOP = 1
TCP_OPT_NOP_LEN = 1
TCP_OPT_MSS = 2
TCP_OPT_MSS_LEN = 4
TCP_OPT_WSCALE = 3
TCP_OPT_WSCALE_LEN = 3
TCP_OPT_SACKPERM = 4
TCP_OPT_SACKPERM_LEN = 2
TCP_OPT_TIMESTAMP = 8
TCP_OPT_TIMESTAMP_LEN = 10


class TcpOptEol:
    """ TCP option End of Option List """

    def __init__(self, raw_option=None):
        if raw_option:
            self.opt_kind = raw_option[0]
        else:
            self.opt_kind = TCP_OPT_EOL

    @property
    def raw_option(self):
        return struct.pack("!B", self.opt_kind)

    def __str__(self):
        return "eol"


class TcpOptNop:
    """ TCP option No Operation """

    def __init__(self, raw_option=None):
        if raw_option:
            self.opt_kind = raw_option[0]
        else:
            self.opt_kind = TCP_OPT_NOP

    @property
    def raw_option(self):
        return struct.pack("!B", self.opt_kind)

    def __str__(self):
        return "nop"


class TcpOptMss:
    """ TCP option Maximum Segment Size """

    def __init__(self, raw_option=None, opt_size=None):
        if raw_option:
            self.opt_kind = raw_option[0]
            self.opt_len = raw_option[1]
            self.opt_size = struct.unpack("!H", raw_option[2:4])[0]
        else:
            self.opt_kind = TCP_OPT_MSS
            self.opt_len = TCP_OPT_MSS_LEN
            self.opt_size = opt_size

    @property
    def raw_option(self):
        return struct.pack("! BB H", self.opt_kind, self.opt_len, self.opt_size)

    def __str__(self):
        return f"mss {self.opt_size}"


class TcpOptSackperm:
    """ TCP option Sack Permit """

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
        return f"sackperm"


class TcpOptWscale:
    """ TCP option Window Scale """

    def __init__(self, raw_option=None, opt_scale=None):
        if raw_option:
            self.opt_kind = raw_option[0]
            self.opt_len = raw_option[1]
            self.opt_scale = raw_option[2]
        else:
            self.opt_kind = TCP_OPT_MSS
            self.opt_len = TCP_OPT_MSS_LEN
            self.opt_scale = opt_scale

    @property
    def raw_option(self):
        return struct.pack("! BB B", self.opt_kind, self.opt_len, self.opt_scale)

    def __str__(self):
        return f"wscale {self.opt_scale}"


class TcpOptTimestamp:
    """ TCP option Timestamp """

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

