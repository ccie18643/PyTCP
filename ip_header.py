#!/usr/bin/env python3

"""

PyTCP, Python TCP/IP stack simulation version 0.1 - 2020, Sebastian Majewski
ip_header.py - contains class supporting IP header parsing and creation

"""

import socket
import struct
import binascii


"""
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |Version|  IHL  |Type of Service|          Total Length         |
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

    def read(self, data):
        """ Read RAW header data and populate it into class variables """

        self.ver = data[0] >> 4
        self.hlen = (data[0] & 0b00001111) << 2
        self.tos, self.len, self.id, self.frag, self.ttl, self.proto, self.cksum, self.src, self.dst = struct.unpack("! xBH HH BBH 4s 4s", data[:20])

        self.dscp = (self.tos & 0b11111100) >> 2
        self.ecn = self.tos & 0b00000011
        self.tos_prec = self.tos >> 5
        self.tos_ld = bool(self.tos & 0b00010000)
        self.tos_ht = bool(self.tos & 0b00001000)
        self.tos_hr = bool(self.tos & 0b00000100)

        self.frag_df = bool(self.frag & 0b0100000000000000)
        self.frag_mf = bool(self.frag & 0b0010000000000000)
        self.frag_offset = self.frag & 0b0001111111111111

        self.src = socket.inet_ntoa(self.src)
        self.dst = socket.inet_ntoa(self.dst)

        self.raw_hdr = data[: self.hlen]

    def compute_cksum(self):
        """ Compute the checksum for IP header """

        cksum_hdr = list(struct.unpack(f"! {self.hlen >> 1}H", self.raw_hdr))
        cksum_hdr[5] = 0
        cksum = 0

        for word in cksum_hdr:
            cksum += word
            cksum = (cksum & 0xFFFF) + (cksum >> 16)

        return 0xFFFF - cksum

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

        tos_prec_table = {
            0b111: "Network Contol",
            0b110: "Internetwork Control",
            0b101: "CRITIC/ECP",
            0b100: "Flash Overide",
            0b011: "Flash",
            0b010: "Immediate",
            0b001: "Priority",
            0b000: "Routine",
        }

        if dscp_code := dscp_table.get(self.dscp, None):
            qos = f"DSCP {self.dscp:0>6b} ({dscp_table[self.dscp]})  ECN {self.ecn:0>2b} ({ecn_table[self.ecn]})"
        else:
            qos = f"TOS {self.tos:0>8b} ({tos_prec_table[self.tos_prec]}"
            qos += f"{' |LD' if self.tos_ld else ' |ND'}"
            qos += f"{'|HT' if self.tos_ht else '|NT'}"
            qos += f"{'|HR|' if self.tos_hr else '|NR|'})"

        return (
            "--------------------------------------------------------------------------------\n"
            + f"IP       SRC {self.src}  DST {self.dst}  VER {self.ver}  CKSUM {self.cksum} "
            + f"{'(OK)' if self.compute_cksum() == self.cksum else '(BAD)'}\n         {qos}\n"
            + f"         TTL {self.ttl}  ID {self.id}  FRAG FLAGS |{'DF|' if self.frag_df else '  |'}"
            + f"{'MF' if self.frag_mf else '  |'} OFFSET {self.frag_offset}\n"
            + f"         HLEN {self.hlen}  PLEN {self.len}  OLEN {self.hlen - 20}  DLEN {self.len - self.hlen}  PROTO {self.proto}"
        )
