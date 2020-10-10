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

    def read(self, data):
        """ Read RAW header data and populate it into class variables """

        self.sport, self.dport, self.seq, self.ack, self.hlen, self.flags, self.win, self.cksum, self.urp = struct.unpack(
            "! HH L L BBH HH", data[:20]
        )

        self.hlen = self.hlen >> 2

        self.flag_urg = bool(self.flags & 32)
        self.flag_ack = bool(self.flags & 16)
        self.flag_psh = bool(self.flags & 8)
        self.flag_rst = bool(self.flags & 4)
        self.flag_syn = bool(self.flags & 2)
        self.flag_fin = bool(self.flags & 1)

    def __str__(self):
        """ Easy to read string reresentation """

        return (
            "--------------------------------------------------------------------------------\n"
            + f"TCP      SPORT {self.sport}  DPORT {self.dport}  SEQ {self.seq}  ACK {self.ack}  HLEN {self.hlen}\n"
            + f"         FLAGS {'|URG' if self.flag_urg else '|   '}"
            + f"{'|ACK' if self.flag_ack else '|   '}"
            + f"{'|PSH' if self.flag_psh else '|   '}"
            + f"{'|RST' if self.flag_rst else '|   '}"
            + f"{'|SYN' if self.flag_syn else '|   '}"
            + f"{'|FIN|' if self.flag_fin else '|   |'}"
            + f"  WIN {self.win}  CKSUM {self.cksum} (??)  URP {self.urp}"
        )


