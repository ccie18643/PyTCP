#!/usr/bin/env python3

"""

PyTCP, Python TCP/IP stack simulation version 0.1 - 2020, Sebastian Majewski
ip_header.py - contains class supporting IP header parsing and creation

"""

import socket
import struct
import array


"""
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |Version|  IHL  |   DSCP    |ECN|          Total Length         |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |         Identification        |Flags|      Fragment Offset    |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |  Time to Live |    Protocol   |         Header Checksum       |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                       Source Address                          |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                    Destination Address                        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                    Options                    |    Padding    |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
"""


class IpHeader:
    """ IP header support class """

    def __init__(self, raw_header=None):
        """ Read raw header data or create blank header """

        if raw_header:
            self.version = raw_header[0] >> 4
            self.header_length = (raw_header[0] & 0b00001111) << 2
            self.dscp = (raw_header[1] & 0b11111100) >> 2
            self.ecn = raw_header[1] & 0b00000011
            self.total_length = struct.unpack("!H", raw_header[2:4])[0]
            self.identification = struct.unpack("!H", raw_header[4:6])[0]
            self.fragment_flag_df = bool(struct.unpack("!H", raw_header[6:8])[0] & 0b0100000000000000)
            self.fragment_flag_mf = bool(struct.unpack("!H", raw_header[6:8])[0] & 0b0010000000000000)
            self.fragment_offset = struct.unpack("!H", raw_header[6:8])[0] & 0b0001111111111111
            self.time_to_live = raw_header[8]
            self.protocol = raw_header[9]
            self.header_checksum = struct.unpack("!H", raw_header[10:12])[0]
            self.source_address = socket.inet_ntoa(struct.unpack("!4s", raw_header[12:16])[0])
            self.destination_address = socket.inet_ntoa(struct.unpack("!4s", raw_header[16:20])[0])

        else:
            self.version = 4
            self.header_length = 20
            self.dscp = 0
            self.ecn = 0
            self.total_length = None
            self.identification = 0
            self.fragment_flag_df = False
            self.fragment_flag_mf = False
            self.fragment_offset = 0
            self.time_to_live = 64
            self.protocol = None
            self.header_checksum = 0
            self.source_address = None
            self.destination_address = None

    def get_raw_header(self, compute_header_checksum=True):
        """ Get raw ip header data """

        if compute_header_checksum:
            self.header_checksum = self.compute_header_checksum()

        return struct.pack(
            "! BBH HH BBH 4s 4s",
            self.version << 4 | self.header_length >> 2,
            self.dscp << 2 | self.ecn,
            self.total_length,
            self.identification,
            self.fragment_flag_df << 14 | self.fragment_flag_mf << 13 | self.fragment_offset,
            self.time_to_live,
            self.protocol,
            self.header_checksum,
            socket.inet_aton(self.source_address),
            socket.inet_aton(self.destination_address),
        )

    def compute_header_checksum(self):
        """ Compute the checksum for IP header """

        checksum_header = list(struct.unpack(f"! {self.header_length >> 1}H", self.get_raw_header(compute_header_checksum=False)))
        checksum_header[5] = 0
        checksum = sum(checksum_header)
        return ~((checksum & 0xFFFF) + (checksum >> 16)) & 0xFFFF

    def get_ip_pseudo_header(self):
        """ Returns IP pseudo header that is used by TCP to compute its checksum """

        return struct.unpack(
            "! HH HH HH",
            struct.pack(
                "! 4s 4s BBH",
                socket.inet_aton(self.source_address),
                socket.inet_aton(self.destination_address),
                0,
                self.protocol,
                self.total_length - self.header_length,
            ),
        )

    def __str__(self):
        """ Easy to read string reresentation """

        dscp_table = {
            0b000000: "CS0",
            0b001000: "CS1",
            0b010000: "CS2",
            0b011000: "CS3",
            0b100000: "CS4",
            0b101000: "CS5",
            0b110000: "CS6",
            0b111000: "CS7",
            0b001010: "AF11",
            0b001100: "AF12",
            0b001100: "AF13",
            0b010010: "AF11",
            0b010100: "AF12",
            0b010100: "AF13",
            0b011010: "AF11",
            0b011100: "AF12",
            0b011100: "AF13",
            0b100010: "AF11",
            0b100100: "AF12",
            0b100100: "AF13",
            0b101110: "EF",
        }

        ecn_table = {
            0b00: "Non-ECT",
            0b10: "ECT(0)",
            0b01: "ECT(1)",
            0b11: "CE",
        }

        return (
            "--------------------------------------------------------------------------------\n"
            + f"IP       SRC {self.source_address}  DST {self.destination_address}  VER {self.version}  CKSUM {self.header_checksum} "
            + f"({'OK' if self.compute_header_checksum() == self.header_checksum else 'BAD'})\n"
            + f"         DSCP {self.dscp:0>6b} ({dscp_table.get(self.dscp, 'ERR')})  ECN {self.ecn:0>2b} ({ecn_table[self.ecn]})  "
            + f"HLEN {self.header_length}  TLEN {self.total_length}\n"
            + f"         TTL {self.time_to_live}  ID {self.identification}  FRAG FLAGS |{'DF|' if self.fragment_flag_df else '  |'}"
            + f"{'MF' if self.fragment_flag_mf else '  |'} OFFSET {self.fragment_offset}  PROTO {self.protocol}"
        )
