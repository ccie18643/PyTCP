#!/usr/bin/env python3

"""

PyTCP, Python TCP/IP stack simulation version 0.1 - 2020, Sebastian Majewski
header.py - contains class supporting IP header parsing and creation

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

    def __init__(self, data):
        """ Read RAW header data """

        self.header = data[: (data[0] & 0b00001111) << 2]

    def get_header():
        """ Get raw ip header data """

        return self.header

    def get_version(self):
        """ Retrieve Version field value from IP header """

        return self.header[0] >> 4

    def get_internet_header_length(self):
        """ Retrieve Internet Header Length field value from IP header """

        return (self.header[0] & 0b00001111) << 2

    def get_dscp(self):
        """ Retrieve DSCP field value from IP header """

        return (self.header[1] & 0b11111100) >> 2

    def get_ecn(self):
        """ Retrieve ECN field value from IP header """

        return self.header[1] & 0b00000011

    def get_total_length(self):
        """ Retrieve Total Length field value from IP header """

        return struct.unpack("!H", self.header[2:4])[0]

    def get_identification(self):
        """ Retrieve Identification field value from IP header """

        return struct.unpack("!H", self.header[4:6])[0]

    def get_fragment_flag_df(self):
        """ Retrive the value of Fragment DF flag from IP header """

        return bool(struct.unpack("!H", self.header[6:8])[0] & 0b0100000000000000)

    def get_fragment_flag_mf(self):
        """ Retrive the value of Fragment MF flag from IP header """

        return bool(struct.unpack("!H", self.header[6:8])[0] & 0b0010000000000000)

    def get_fragment_offset(self):
        """ Retrive Fragment Offset field value from IP header """

        return struct.unpack("!H", self.header[6:8])[0] & 0b0001111111111111

    def get_time_to_live(self):
        """ Retrive Time to Live field value from IP header """

        return self.header[8]

    def get_protocol(self):
        """ Retrive Protocol field value from IP header """

        return self.header[9]

    def get_header_checksum(self):
        """ Retrieve Header Checksum field value from IP header """

        return struct.unpack("!H", self.header[10:12])[0]

    def get_source_address(self):
        """ Retrieve Source Address field value from IP header """

        return socket.inet_ntoa(struct.unpack("!4s", self.header[12:16])[0])

    def get_destination_address(self):
        """ Retrieve Destination Address field value from IP header """

        return socket.inet_ntoa(struct.unpack("!4s", self.header[16:20])[0])

    def compute_cksum(self):
        """ Compute the checksum for IP header """

        cksum_hdr = list(struct.unpack(f"! {self.get_internet_header_length() >> 1}H", self.header))
        cksum_hdr[5] = 0
        cksum = sum(cksum_hdr)
        return ~((cksum & 0xFFFF) + (cksum >> 16)) & 0xFFFF

    def get_pseudo_header(self):
        """ Returns IP pseudo header that is used by TCP to compute its checksum """

        return struct.unpack(
            "! HH HH HH",
            struct.pack(
                "! 4s 4s BBH",
                socket.inet_aton(self.get_source_address()),
                socket.inet_aton(self.get_destination_address()),
                0,
                self.get_protocol(),
                self.get_total_length() - self.get_internet_header_length(),
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
            + f"IP       SRC {self.get_source_address()}  DST {self.get_destination_address()}  VER {self.get_version()}  CKSUM {self.get_header_checksum()} "
            + f"({'OK' if self.compute_cksum() == self.get_header_checksum() else 'BAD'})\n"
            + f"         DSCP {self.get_dscp():0>6b} ({dscp_table.get(self.get_dscp(), 'ERR')})  ECN {self.get_ecn():0>2b} ({ecn_table[self.get_ecn()]})  "
            + f"HLEN {self.get_internet_header_length()}  TLEN {self.get_total_length()}\n"
            + f"         TTL {self.get_time_to_live()}  ID {self.get_identification()}  FRAG FLAGS |{'DF|' if self.get_fragment_flag_df() else '  |'}"
            + f"{'MF' if self.get_fragment_flag_mf() else '  |'} OFFSET {self.get_fragment_offset()}  PROTO {self.get_protocol()}"
        )
