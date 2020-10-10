#!/usr/bin/env python3

"""

PyTCP, Python TCP/IP stack simulation version 0.1 - 2020, Sebastian Majewski
tcp_header.py - contains class supporting TCP header parsing and creation

"""

import socket
import struct
import binascii


"""
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
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


class TcpHeader:
    """ Tcp header support class """

    def read(self, data, ip_pseudo_header=None):
        """ Read RAW header data and populate it into class variables """

        self.sport, self.dport, self.seq, self.ack, self.hlen, self.flags, self.win, self.cksum, self.urp = struct.unpack("! HH L L BBH HH", data[:20])

        self.hlen = self.hlen >> 2

        self.flag_urg = bool(self.flags & 32)
        self.flag_ack = bool(self.flags & 16)
        self.flag_psh = bool(self.flags & 8)
        self.flag_rst = bool(self.flags & 4)
        self.flag_syn = bool(self.flags & 2)
        self.flag_fin = bool(self.flags & 1)

        self.raw_hdr = data[: self.hlen]
        self.data = data
        self.ip_pseudo_header = ip_pseudo_header

    def compute_cksum(self):
        """ Compute the checksum for IP pseudo header and TCP header """

        if len(self.data) % 2:
            data = self.data + b"\x00"
        else:
            data = self.data

        cksum_data = list(self.ip_pseudo_header) + list(struct.unpack(f"! {len(data) >> 1}H", data))
        cksum_data[6 + 8] = 0
        cksum = sum(cksum_data)
        return ~((cksum & 0xFFFF) + (cksum >> 16)) & 0xFFFF

    def __str__(self):
        """ Easy to read string reresentation """

        return (
            "--------------------------------------------------------------------------------\n"
            + f"TCP      SPORT {self.sport}  DPORT {self.dport}  SEQ {self.seq}  ACK {self.ack}  URP {self.urp}\n"
            + f"         FLAGS {'|URG' if self.flag_urg else '|   '}"
            + f"{'|ACK' if self.flag_ack else '|   '}"
            + f"{'|PSH' if self.flag_psh else '|   '}"
            + f"{'|RST' if self.flag_rst else '|   '}"
            + f"{'|SYN' if self.flag_syn else '|   '}"
            + f"{'|FIN|' if self.flag_fin else '|   |'}"
            + f"  WIN {self.win}  CKSUM {self.cksum} ({'OK' if self.compute_cksum() == self.cksum else 'BAD'})  HLEN {self.hlen}"
        )
