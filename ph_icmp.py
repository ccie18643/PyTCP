#!/usr/bin/env python3

"""

PyTCP, Python TCP/IP stack simulation version 0.1 - 2020, Sebastian Majewski
ph_icmp.py - packet handler libary for Ethernet protocol

"""

import struct


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


class IcmpPacket:
    """ Packet support base class """

    def validate_cksum(self):
        """ Validate the checksum for ICMP message """

        cksum_data = list(struct.unpack(f"! {len(self.raw_packet) >> 1}H", self.raw_packet))
        cksum_data[1] = 0
        cksum = sum(cksum_data)
        return ~((cksum & 0xFFFF) + (cksum >> 16)) & 0xFFFF == self.hdr_cksum

    @property
    def log(self):
        """ Short packet log string """

        log = f"ICMP type {self.hdr_type}, code {self.hdr_code}"

        if self.hdr_type == ICMP_ECHOREPLY and self.hdr_code == 0:
            log += f", id {self.msg_id}, seq {self.msg_seq}"

        if self.hdr_type == ICMP_ECHOREQUEST and self.hdr_code == 0:
            log += f", id {self.msg_id}, seq {self.msg_seq}"

        return log

    @property
    def dump(self):
        """ Verbose packet debug string """

        type_name = ""
        code_name = ""

        if self.hdr_type == ICMP_ECHOREPLY and self.hdr_code == 0:
            dump_message = f"\n         ID {self.msg_id}  SEQ {self.msg_seq}"
            type_name = "(Echo Reply)"

        if self.hdr_type == ICMP_ECHOREQUEST and self.hdr_code == 0:
            dump_message = f"\n         ID {self.msg_id}  SEQ {self.msg_seq}"
            type_name = "(Echo Request)"

        dump_header = (
            "--------------------------------------------------------------------------------\n"
            + f"ICMP     TYPE {self.hdr_type} {type_name}  CODE {self.hdr_code} {code_name} CKSUM {self.hdr_cksum} ({'OK' if self.validate_cksum() else 'BAD'})"
        )

        return dump_header + dump_message


class IcmpPacketRx(IcmpPacket):
    """ Packet parse class """

    def __init__(self, raw_packet):
        """ Class constructor """

        self.raw_packet = raw_packet

        self.hdr_type = self.raw_header[0]
        self.hdr_code = self.raw_header[1]
        self.hdr_cksum = struct.unpack("!H", self.raw_header[2:4])[0]

        if self.hdr_type == ICMP_ECHOREPLY and self.hdr_code == 0:
            self.msg_id = struct.unpack("!H", self.raw_message[0:2])[0]
            self.msg_seq = struct.unpack("!H", self.raw_message[2:4])[0]
            self.msg_data = self.raw_message[ICMP_ECHOREPLY_LEN:]

        if self.hdr_type == ICMP_ECHOREQUEST and self.hdr_code == 0:
            self.msg_id = struct.unpack("!H", self.raw_message[0:2])[0]
            self.msg_seq = struct.unpack("!H", self.raw_message[2:4])[0]
            self.msg_data = self.raw_message[ICMP_ECHOREQUEST_LEN:]

    @property
    def raw_header(self):
        """ Get packet header in raw format """

        return self.raw_packet[:ICMP_HEADER_LEN]

    @property
    def raw_message(self):
        """ Get packet message in raw format """

        return self.raw_packet[ICMP_HEADER_LEN:]


class IcmpPacketTx(IcmpPacket):
    """ Packet creation class """

    def __init__(self, hdr_type, hdr_code=0, msg_id=None, msg_seq=None, msg_data=b""):
        """ Class constructor """

        self.hdr_type = hdr_type
        self.hdr_code = hdr_code
        self.hdr_cksum = None

        if self.hdr_type == ICMP_ECHOREPLY and self.hdr_code == 0:
            self.msg_id = msg_id
            self.msg_seq = msg_seq
            self.msg_data = msg_data
            self.packet_len = ICMP_HEADER_LEN + ICMP_ECHOREPLY_LEN + len(msg_data)

        if self.hdr_type == ICMP_ECHOREQUEST and self.hdr_code == 0:
            self.msg_id = msg_id
            self.msg_seq = msg_seq
            self.msg_data = msg_data
            self.packet_len = ICMP_HEADER_LEN + ICMP_ECHOREQUEST_LEN + len(msg_data)

    @property
    def raw_header(self):
        """ Get packet header in raw format """

        return struct.pack("! BBH", self.hdr_type, self.hdr_code, self.hdr_cksum)

    @property
    def raw_message(self):
        """ Get packet message in raw format """

        if self.hdr_type == ICMP_ECHOREPLY and self.hdr_code == 0:
            return struct.pack("! HH", self.msg_id, self.msg_seq) + self.msg_data

        if self.hdr_type == ICMP_ECHOREQUEST and self.hdr_code == 0:
            return struct.pack("! HH", self.msg_id, self.msg_seq) + self.msg_data

        return b""

    @property
    def raw_packet(self):
        """ Get packet in raw format """

        self.hdr_cksum = 0
        cksum = sum(list(struct.unpack(f"! {self.packet_len >> 1}H", self.raw_header + self.raw_message)))
        self.hdr_cksum = ~((cksum & 0xFFFF) + (cksum >> 16)) & 0xFFFF

        return self.raw_header + self.raw_message
