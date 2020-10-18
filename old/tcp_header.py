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


class TcpOption:
    """ Tcp option class """

    def __init__(self, data):
        """ Read RAW option data """

        self.option = data[:data[1]]

    @property
    def code(self):
        """ Get option code """

        return self.option[0]

    @property
    def length(self):
        """ Get option length """

        return self.option[1]

    def __str__(self):
        """ Easy to read string reresentation """

        return f"\n         UNK {self.option[0]}"


class TcpOptionMss(TcpOption):
    """ Tcp option MSS class """

    def __init__(self, data):
        """ Read RAW option data """

        super().__init__(data)

    @property
    def size(self):
        """ Get the value of Size field """

        return struct.unpack("!H", self.option[2:4])[0]

    def __str__(self):
        """ Easy to read string reresentation """

        return f"\n         MSS SIZE {self.size}"

class TcpOptionWscale(TcpOption):
    """ Tcp option WSCALE class """

    def __init__(self, data):
        """ Read RAW option data """

        super().__init__(data)

    @property
    def scale(self):
        """ Get the value of Scale field """

        return self.option[2]

    def __str__(self):
        """ Easy to read string reresentation """

        return f"\n         WSCALE SCALE {self.scale}"

class TcpOptionSackPerm(TcpOption):
    """ Tcp option SACKPERM class """

    def __init__(self, data):
        """ Read RAW option data """

        super().__init__(data)

    def __str__(self):
        """ Easy to read string reresentation """

        return f"\n         SACKPERM"

class TcpOptionTimestamp(TcpOption):
    """ Tcp option TIMESTAMP class """

    def __init__(self, data):
        """ Read RAW option data """

        super().__init__(data)

    @property
    def tsval(self):
        """ Get the value of TsVal field """

        return struct.unpack("!L", self.option[2:6])[0]

    @property
    def tsecr(self):
        """ Get the value of TsEcr field """

        return struct.unpack("!L", self.option[6:10])[0]

    def __str__(self):
        """ Easy to read string reresentation """

        return f"\n         TIMESTAMP TSVAL {self.tsval} TSECR {self.tsecr}"

class TcpHeader:
    """ Tcp header support class """

    def __init__(self, data, ip_pseudo_header=None):
        """ Read RAW header data """

        self.header = data[:data[12] >> 2]
        self.data = data[data[12] >> 2:]
        self.ip_pseudo_header = ip_pseudo_header

        self.hdr_sport = struct.unpack("!H", self.raw_header[0:2])[0]
        self.hdr_dport = struct.unpack("!H", self.raw_header[2:4])[0]
        self.hdr_seq_num = struct.unpack("!L", self.raw_header[4:8])[0]
        self.hdr_ack_num =  struct.unpack("!L", self.raw_header[8:12])[0]
        self.hdr_hlen = (self.raw_header[12] & 0b11110000) >> 2
        self.hdr_flag_ns =  bool(self.header[12] & 0b00000001)
        self.hdr_flag_crw =  bool(self.header[13] & 0b10000000)
        self.hdr_flag_ece =  bool(self.header[13] & 0b01000000)
        self.hdr_flag_urg =  bool(self.header[13] & 0b00100000)
        self.hdr_flag_ack =  bool(self.header[13] & 0b00010000)
        self.hdr_flag_psh =  bool(self.header[13] & 0b00001000)
        self.hdr_flag_rst =  bool(self.header[13] & 0b00000100)
        self.hdr_flag_syn =  bool(self.header[13] & 0b00000010)
        self.hdr_flag_fin =  bool(self.header[13] & 0b00000001)
        self.hdr_win =  struct.unpack("!H", self.header[14:16])[0]
        self.hdr_cksum =  struct.unpack("!H", self.header[16:18])[0]
        self.hdr_urp = struct.unpack("!H", self.header[18:20])[0]

    @property
    def options(self):
        """ Get list of options """

        options = []

        raw_options = self.header[20:self.data_offset]

        i = 0

        while i < len(raw_options):
            
            if raw_options[i] == 0:
                break
            
            elif raw_options[i] == 1:
                i += 1
                continue
            
            elif raw_options[i] == 2:
                options.append(TcpOptionMss(raw_options[i:i + raw_options[i + 1]]))
            
            elif raw_options[i] == 3:
                options.append(TcpOptionWscale(raw_options[i:i + raw_options[i + 1]]))
            
            elif raw_options[i] == 4:
                options.append(TcpOptionSackPerm(raw_options[i:i + raw_options[i + 1]]))
            
            elif raw_options[i] == 8:
                options.append(TcpOptionTimestamp(raw_options[i:i + raw_options[i + 1]]))
            
            else:
                options.append(TcpOption(raw_options[i:i + raw_options[i + 1]]))
            
            i += raw_options[i + 1]

        return options

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

        string = (
            "--------------------------------------------------------------------------------\n"
            + f"TCP      SPORT {self.source_port}  DPORT {self.destination_port}  SEQ {self.seq_number}  ACK {self.ack_number}  URP {self.urgent_pointer}\n"
            + f"         FLAGS |{'URG' if self.flag_urg else '   '}|{'ACK' if self.flag_ack else '   '}|{'PSH' if self.flag_psh else '   '}|"
            + f"{'RST' if self.flag_rst else '   '}|{'SYN' if self.flag_syn else '   '}|{'FIN' if self.flag_fin else '   '}|"
            + f"  WIN {self.window}  CKSUM {self.checksum} ({'OK' if self.compute_checksum() == self.checksum else 'BAD'})  HLEN {self.data_offset}"
        )

        for option in self.options:
            string += str(option)

        return string




