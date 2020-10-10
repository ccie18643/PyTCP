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

    def __init__(self, data, ip_pseudo_header=None):
        """ Read RAW header data """

        self.header = data[:data[12] >> 2]
        self.data = data[data[12] >> 2:]
        self.ip_pseudo_header = ip_pseudo_header

    @property
    def source_port(self):
        """ Retrieve Source Port field value from TCP header """

        return struct.unpack("!H", self.header[0:2])[0]

    @property
    def destination_port(self):
        """ Retrieve Destination Port field value from TCP header """

        return struct.unpack("!H", self.header[2:4])[0]

    @property
    def seq_number(self):
        """ Retrieve Sequence Number field value from TCP header """

        return struct.unpack("!L", self.header[4:8])[0]

    @property
    def ack_number(self):
        """ Retrieve Acknowledge Number field value from TCP header """

        return struct.unpack("!L", self.header[8:12])[0]

    @property
    def data_offset(self):
        """ Retrieve Data Offset field value from TCP header """

        return self.header[12] >> 2

    @property
    def flag_urg(self):
        """ Retrieve value of the URG flag from TCP header """

        return bool(self.header[13] & 0b00100000)

    @property
    def flag_ack(self):
        """ Retrieve value of the ACK flag from TCP header """

        return bool(self.header[13] & 0b00010000)

    @property
    def flag_psh(self):
        """ Retrieve value of the PSH flag from TCP header """

        return bool(self.header[13] & 0b00001000)

    @property
    def flag_rst(self):
        """ Retrieve value of the RST flag from TCP header """

        return bool(self.header[13] & 0b00000100)

    @property
    def flag_syn(self):
        """ Retrieve value of the SYN flag from TCP header """

        return bool(self.header[13] & 0b00000010)

    @property
    def flag_fin(self):
        """ Retrieve value of the FIN flag from TCP header """

        return bool(self.header[13] & 0b00000001)

    @property
    def window(self):
        """ Retrieve Window field value from TCP header """

        return struct.unpack("!H", self.header[14:16])[0]

    @property
    def checksum(self):
        """ Retrieve Checksum field value from TCP header """

        return struct.unpack("!H", self.header[16:18])[0]

    @property
    def urgent_pointer(self):
        """ Retrieve Urgent Pointer field value from TCP header """

        return struct.unpack("!H", self.header[18:20])[0]

    def compute_checksum(self):
        """ Compute the checksum for IP pseudo header, TCP header and data"""

        if len(self.data) % 2:
            data = self.data + b"\x00"
        else:
            data = self.data

        checksum_data = list(self.ip_pseudo_header) + list(struct.unpack(f"! {self.data_offset >> 1}H", self.header)) + list(struct.unpack(f"! {len(data) >> 1}H", data))

        checksum_data[6 + 8] = 0
        checksum = sum(checksum_data)
        return ~((checksum & 0xFFFF) + (checksum >> 16)) & 0xFFFF

    def __str__(self):
        """ Easy to read string reresentation """

        return (
            "--------------------------------------------------------------------------------\n"
            + f"TCP      SPORT {self.source_port}  DPORT {self.destination_port}  SEQ {self.seq_number}  ACK {self.ack_number}  URP {self.urgent_pointer}\n"
            + f"         FLAGS |{'URG' if self.flag_urg else '   '}|{'ACK' if self.flag_ack else '   '}|{'PSH' if self.flag_psh else '   '}|"
            + f"{'RST' if self.flag_rst else '   '}|{'SYN' if self.flag_syn else '   '}|{'FIN' if self.flag_fin else '   '}|"
            + f"  WIN {self.window}  CKSUM {self.checksum} ({'OK' if self.compute_checksum() == self.checksum else 'BAD'})  HLEN {self.data_offset}"
        )
