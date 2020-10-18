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

    def validate_cksum(self):
        """ Validate checksum for UDP packet """

        cksum_data = list(
            struct.unpack(
                f"! {(len(self.ip_pseudo_header) + (len(self.raw_packet) + 1 if len(self.raw_packet) & 1 else len(self.raw_packet))) >> 1}H",
                self.ip_pseudo_header + self.raw_header + self.raw_options + self.raw_data + (b"\0" if len(self.raw_packet) & 1 else b""),
            )
        )
        cksum_data[6 + 8] = 0
        cksum = sum(cksum_data)
        return ~((cksum & 0xFFFF) + (cksum >> 16)) & 0xFFFF == self.hdr_cksum

    @property
    def log(self):
        """ Short packet log string """

        return f"TCP {self.hdr_sport} > {self.hdr_dport}, len {self.hdr_len}"

    @property
    def dump(self):
        """ Verbose packet debug string """

        return (
            "--------------------------------------------------------------------------------\n"
            + f"TCP      SPORT {self.hdr_sport}  DPORT {self.hdr_dport}  LEN {self.hdr_hlen}  "
            + f"CKSUM {self.hdr_cksum} ({'OK' if self.validate_cksum() else 'BAD'})"
        )


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


class TcpPacketTx(TcpPacket):
    """ Packet creation class """

    serial_number_tx = 0

    def __init__(
        self,
        hdr_sport,
        hdr_dport,
        hdr_seq_num=0,
        hdr_ack_num=0,
        hdr_flag_ns = False,
        hdr_flag_crw = False,
        hdr_flag_ece = False,
        hdr_flag_urg = False,
        hdr_flag_ack=False,
        hdr_flag_psh = False,
        hdr_flag_rst=False,
        hdr_flag_syn=False,
        hdr_flag_fin=False,
        hdr_win=0,
        hdr_urp = 0,
        raw_options=b"",
        raw_data=b"",
    ):
        """ Class constructor """

        self.hdr_sport = hdr_sport
        self.hdr_dport = hdr_dport
        self.hdr_seq_num = hdr_seq_num
        self.hdr_ack_num = hdr_ack_num
        self.hdr_hlen = None
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
        self.hdr_cksum = None
        self.hdr_urp = hdr_urp

        self.raw_options = raw_options
        self.raw_data = raw_data

        ip_pseudo_header = None

    @property
    def raw_header(self):
        """ Get packet header in raw format """

        return struct.pack("! HH HH", self.hdr_sport, self.hdr_dport, self.hdr_len, self.hdr_cksum)

    @property
    def raw_packet(self):
        """ Get packet header in raw format """

        cksum_data = list(
            struct.unpack(
                f"! {(len(self.ip_pseudo_header) + (self.hdr_len + 1 if self.hdr_len & 1 else self.hdr_len)) >> 1}H",
                self.ip_pseudo_header + self.raw_header + self.raw_data + (b"\0" if self.hdr_len & 1 else b""),
            )
        )
        cksum = sum(cksum_data)
        self.hdr_cksum = ~((cksum & 0xFFFF) + (cksum >> 16)) & 0xFFFF

        return self.raw_header + self.raw_data
