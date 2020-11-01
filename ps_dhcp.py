#!/usr/bin/env python3

"""

PyTCP, Python TCP/IP stack, version 0.1 - 2020, Sebastian Majewski
ps_dhcp.py - protocol support libary for DHCP

"""


import struct

import socket
import binascii

from tracker import Tracker


DHCP_HEADER_LEN = 236 + 4

"""

   DHCP packet header (RFC 2131)

   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |   Operation   |    HW Type    |     HW Len    |     Hops      |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                     Transaction Identifier                    |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |         Seconds Elapsed       |B|          Reserved           |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                       Client IP Address                       |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                        Your IP Address                        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                       Server IP Address                       |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                       Router IP Address                       |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               |
   |                            Client                             |
   |                          HW Address                           |
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               |
   |                                                               |
   |                                                               |
   |                                                               |
   |                                                               |
   |                                                               |
   |                                                               |
   |                             Server                            |
   |                            Hostname                           |
   |                                                               |
   |                                                               |
   |                                                               |
   |                                                               |
   |                                                               |
   |                                                               |
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               |
   |                                                               |
   |                                                               |
   |                                                               |
   |                                                               |
   |                                                               |
   |                                                               |
   |                                                               |
   |                                                               |
   |                                                               |
   |                                                               |
   |                                                               |
   |                                                               |
   |                                                               |
   |                                                               |
   |                          Bootfile                             |
   |                            Name                               |
   |                                                               |
   |                                                               |
   |                                                               |
   |                                                               |
   |                                                               |
   |                                                               |
   |                                                               |
   |                                                               |
   |                                                               |
   |                                                               |
   |                                                               |
   |                                                               |
   |                                                               |
   |                                                               |
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   ~                          Options                              ~
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

"""


DHCP_DISCOVER = 1
DHCP_OFFER = 2
DHCP_REQUEST = 3
DHCP_ACK = 5


class DhcpPacket:
    """ Dhcp packet support class """

    protocol = "DHCP"

    def __init__(
        self, raw_packet=None, dhcp_xid=None, dhcp_chaddr=None, dhcp_msg_type=None, dhcp_param_req_list=None, dhcp_req_ip_addr=None
    ):
        """ Class constructor """

        # Packet parsing
        if raw_packet:
            raw_header = raw_packet[:DHCP_HEADER_LEN]

            raw_options = raw_packet[DHCP_HEADER_LEN:]

            self.dhcp_op = raw_header[0]
            self.dhcp_htype = raw_header[1]
            self.dhcp_hlen = raw_header[2]
            self.dhcp_hops = raw_header[3]
            self.dhcp_xid = struct.unpack("!L", raw_header[4:8])[0]
            self.dhcp_secs = struct.unpack("!H", raw_header[8:10])[0]
            self.dhcp_flag_b = bool(struct.unpack("!H", raw_header[10:12])[0] & 0b1000000000000000)
            self.dhcp_ciaddr = socket.inet_ntoa(struct.unpack("!4s", raw_header[12:16])[0])
            self.dhcp_yiaddr = socket.inet_ntoa(struct.unpack("!4s", raw_header[16:20])[0])
            self.dhcp_siaddr = socket.inet_ntoa(struct.unpack("!4s", raw_header[20:24])[0])
            self.dhcp_giaddr = socket.inet_ntoa(struct.unpack("!4s", raw_header[24:28])[0])
            self.dhcp_chaddr = raw_header[28 : 28 + self.dhcp_hlen]
            self.dhcp_sname = raw_header[44:108]
            self.dhcp_file = raw_header[108:236]

            self.dhcp_options = []

            i = 0

            while i < len(raw_options):

                if raw_options[i] == DHCP_OPT_END:
                    self.dhcp_options.append(DhcpOptEnd(raw_options[i : i + DHCP_OPT_END_LEN + 1]))
                    break

                elif raw_options[i] == DHCP_OPT_PARAM_REQ_LIST:
                    self.dhcp_options.append(DhcpOptParamReqList(raw_options[i : i + raw_options[i + 1] + 2]))
                    i += self.raw_options[i + 1] + 2

                elif raw_options[i] == DHCP_OPT_REQ_IP_ADDR:
                    self.dhcp_options.append(DhcpOptReqIpAddr(raw_options[i : i + raw_options[i + 1] + 2]))
                    i += self.raw_options[i + 1] + 2

                elif raw_options[i] == DHCP_OPT_MSG_TYPE:
                    self.dhcp_options.append(DhcpOptMsgType(raw_options[i : i + raw_options[i + 1] + 2]))
                    i += self.raw_options[i + 1] + 2

                else:
                    self.dhcp_options.append(DhcpOptUnk(raw_options[i : i + raw_options[i + 1] + 2]))
                    i += self.raw_options[i + 1] + 2

        # Packet building
        else:
            self.dhcp_op = 1
            self.dhcp_htype = 1
            self.dhcp_hlen = 6
            self.dhcp_hops = 0
            self.dhcp_xid = dhcp_xid
            self.dhcp_secs = 0
            self.dhcp_flag_b = False
            self.dhcp_ciaddr = "0.0.0.0"
            self.dhcp_yiaddr = "0.0.0.0"
            self.dhcp_siaddr = "0.0.0.0"
            self.dhcp_giaddr = "0.0.0.0"
            self.dhcp_chaddr = dhcp_chaddr
            self.dhcp_sname = b"\0" * 64
            self.dhcp_file = b"\0" * 128

            self.dhcp_options = []

            if dhcp_msg_type:
                self.dhcp_options.append(DhcpOptMsgType(opt_msg_type=dhcp_msg_type))

            if dhcp_param_req_list:
                self.dhcp_options.append(DhcpOptParamReqList(opt_param_req_list=dhcp_param_req_list))

            if dhcp_req_ip_addr:
                self.dhcp_options.append(DhcpOptReqIpAddr(opt_req_ip_addr=dhcp_req_ip_addr))

            self.dhcp_options.append(DhcpOptEnd())

    def __str__(self):
        """ Short packet log string """

        return f"DHCP op {self.dhcp_op}"

    def __len__(self):
        """ Length of the packet """

        return len(self.raw_packet)

    @property
    def raw_header(self):
        """ Packet header in raw format """

        return struct.pack(
            "! BBBB L HH 4s 4s 4s 4s 16s 64s 128s 4s",
            self.dhcp_op,
            self.dhcp_htype,
            self.dhcp_hlen,
            self.dhcp_hops,
            self.dhcp_xid,
            self.dhcp_secs,
            self.dhcp_flag_b << 15,
            socket.inet_aton(self.dhcp_ciaddr),
            socket.inet_aton(self.dhcp_yiaddr),
            socket.inet_aton(self.dhcp_siaddr),
            socket.inet_aton(self.dhcp_giaddr),
            (bytes.fromhex(self.dhcp_chaddr.replace(":", "")) + b"\0" * 16)[:16],
            self.dhcp_sname,
            self.dhcp_file,
            b"\x63\x82\x53\x63",
        )

    @property
    def raw_options(self):
        """ Packet options in raw format """

        raw_options = b""

        for option in self.dhcp_options:
            raw_options += option.raw_option

        return raw_options

    @property
    def dhcp_msg_type(self):
        """ DHCP Message Type """

        for option in self.dhcp_options:
            if option.opt_code == DHCP_OPT_MSG_TYPE:
                return option.opt_msg_type

    @property
    def raw_packet(self):
        """ Packet in raw format """

        return self.raw_header + self.raw_options

    def get_raw_packet(self):
        """ Get packet in raw format ready to be processed by lower level protocol """

        return self.raw_packet



DHCP_OPT_END = 255
DHCP_OPT_END_LEN = 0
DHCP_OPT_MSG_TYPE = 53
DHCP_OPT_MSG_TYPE_LEN = 1
DHCP_OPT_PARAM_REQ_LIST = 55
DHCP_OPT_REQ_IP_ADDR = 50
DHCP_OPT_REQ_IP_ADDR_LEN = 4


class DhcpOptEnd:
    """ DHCP option End of Option List """

    def __init__(self, raw_option=None):
        if raw_option:
            self.opt_code = raw_option[0]
        else:
            self.opt_code = DHCP_OPT_END

    @property
    def raw_option(self):
        return struct.pack("!B", self.opt_code)

    def __str__(self):
        return "end"


class DhcpOptMsgType:
    """ DHCP option Message Type """

    def __init__(self, raw_option=None, opt_msg_type=None):
        if raw_option:
            self.opt_code = raw_option[0]
            self.opt_len = raw_option[1]
            self.opt_msg_type = raw_option[2]
        else:
            self.opt_code = DHCP_OPT_MSG_TYPE
            self.opt_len = DHCP_OPT_MSG_TYPE_LEN
            self.opt_msg_type = opt_msg_type

    @property
    def raw_option(self):
        return struct.pack("! BB B", self.opt_code, self.opt_len, self.opt_msg_type)

    def __str__(self):
        return f"msg_type {self.opt_size}"


class DhcpOptParamReqList:
    """ DHCP option ParameterRequestList """

    def __init__(self, raw_option=None, opt_param_req_list=None):
        if raw_option:
            self.opt_code = raw_option[0]
            self.opt_len = raw_option[1]
            self.opt_param_req_list = raw_option[2 : 2 + self.opt_len]
        else:
            self.opt_code = DHCP_OPT_PARAM_REQ_LIST
            self.opt_len = len(opt_param_req_list)
            self.opt_param_req_list = opt_param_req_list

    @property
    def raw_option(self):
        return struct.pack(f"! BB{self.opt_len}s", self.opt_code, self.opt_len, self.opt_param_req_list)

    def __str__(self):
        return f"param_req_list {binascii.hexlify(self.opt_list)}"


class DhcpOptReqIpAddr:
    """ DHCP option Requested IP Address """

    def __init__(self, raw_option=None, opt_req_ip_addr=None):
        if raw_option:
            self.opt_code = raw_option[0]
            self.opt_len = raw_option[1]
            self.opt_req_ip_addr = socket.inet_ntoa(struct.unpack("!4s", raw_option[2:6])[0])
        else:
            self.opt_code = DHCP_OPT_REQ_IP_ADDR
            self.opt_len = DHCP_OPT_REQ_IP_ADDR_LEN
            self.opt_req_ip_addr = opt_req_ip_addr

    @property
    def raw_option(self):
        return struct.pack(f"! BB 4s", self.opt_code, self.opt_len, socket.inet_aton(self.opt_req_ip_addr))

    def __str__(self):
        return f"req_ip_addr {self.opt_addr}"


class DhcpOptUnk:
    """ DHCP option not supported by this stack """

    def __init__(self, raw_option=None):
        self.opt_code = raw_option[0]
        self.opt_len = raw_option[1]
        self.opt_data = raw_option[2 : 2 + self.opt_len]

    @property
    def raw_option(self):
        return struct.pack(f"! BB{self.opt_len}s", self.opt_code, self.opt_len, self.opt_data)

    def __str__(self):
        return f"unk"
