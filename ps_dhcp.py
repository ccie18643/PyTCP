#!/usr/bin/env python3

"""

PyTCP, Python TCP/IP stack, version 0.1 - 2020, Sebastian Majewski
ps_dhcp.py - protocol support libary for DHCP

"""


import struct
from binascii import hexlify

from tracker import Tracker


DHCP_HEADER_LEN = 224

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


class DhcpPacket:
    """ Dhcp packet support class """

    protocol = "DHCP"

    def __init__(self, parent_packet=None, dhcp_id=None, dhcp_client_hw_addr, echo_tracker=None):
        """ Class constructor """

        # Packet parsing
        if parent_packet:
            self.tracker = parent_packet.tracker

            raw_packet = parent_packet.raw_data
            raw_header = raw_packet[:DHCP_HEADER_LEN]

            self.raw_options = raw_packet[DHCP_HEADER_LEN:]

            self.dhcp_operation = raw_header[0]
            self.dhcp_hw_type = raw_header[1]
            self.dhcp_hw_len = raw_header[2]
            self.dhcp_hops = raw_header[3]
            self.dhcp_id = struct.unpack("!L", raw_header[4:8])[0]
            self.dhcp_seconds = struct.unpack("!H", raw_header[8:10])[0]
            self.dhcp_flag_b = bool(struct.unpack("!H", raw_header[10:12])[0] & 0b1000000000000000)
            self.dhcp_client_ip = socket.inet_ntoa(struct.unpack("!4s", raw_header[12:16])[0])
            self.dhcp_your_ip = socket.inet_ntoa(struct.unpack("!4s", raw_header[16:20])[0])
            self.dhcp_server_ip = socket.inet_ntoa(struct.unpack("!4s", raw_header[20:24])[0])
            self.dhcp_router_ip = socket.inet_ntoa(struct.unpack("!4s", raw_header[24:28])[0])
            self.dhcp_client_hw_addr = raw_header[28 : 28 + self.dhcp_hw_len]
            self.dhcp_server_hostname = raw_header[44:108]
            self.dhcp_bootfile_name = raw_header[108:236]

        # Packet building
        else:
            self.tracker = Tracker("TX", echo_tracker)

            self.dhcp_operation = 1
            self.dhcp_hw_type = 1
            self.dhcp_hw_len = 6
            self.dhcp_hops = 0
            self.dhcp_id = dhcp_id
            self.dhcp_seconds = 0
            self.dhcp_flag_b = False
            self.dhcp_client_ip = "0.0.0.0"
            self.dhcp_your_ip = "0.0.0.0"
            self.dhcp_server_ip = "0.0.0.0"
            self.dhcp_router_ip = "0.0.0.0"
            self.dhcp_client_hw_address = dhcp_client_hw_addr
            self.dhcp_server_hostname = b"\0" * 64
            self.dhcp_bootfile_name = b"\0" * 128

            self.raw_options = b""

    def __str__(self):
        """ Short packet log string """

        return f"DHCP {self.dhcp_operation}"

    def __len__(self):
        """ Length of the packet """

        return len(self.raw_packet)

    @property
    def raw_header(self):
        """ Packet header in raw format """

        return struct.pack("! BBBB L HH L L L L 16s 64s 128s 4s",
            self.dhcp_opration,
            self.dhcp_hw_type,
            self.dhcp_hw_len,
            self.dhcp_hops,
            self.dhcp_id,
            self.dhcp_secs,
            self.dhcp_flag_b << 15,
            socket.inet_aton(self.dhcp_client_address),
            socket.inet_aton(self.dhcp_your_address),
            socket.inet_aton(self.dhcp_server_address),
            socket.inet_aton(self.dhcp_router_address),
            (self.bytes.fromhex(self.dhcp_client_hw_address.replace(":", "")) + b"\0" * 16)[:16]
            self.dhcp_server_hostname,
            self.dhcp_bootfile_name,
            b"\x63\x82\x53\x63",
        )

    @property
    def raw_packet(self):
        """ Packet in raw format """

        return self.raw_header + self.raw_options

    def get_raw_packet(self, ip_pseudo_header):
        """ Get packet in raw format ready to be processed by lower level protocol """

        return self.raw_packet


DHCP_OPT_END = 255
DHCP_OPT_END_LEN = 0
DHCP_OPT_MESSAGE_TYPE = 53
DHCP_OPT_MESSAGE_TYPE_LEN = 1
DHCP_OPT_PARAMETER_REQUEST_LIST = 55


class DhcpOptEnd:
    """ DHCP option End of Option List """

    name = "END"

    def __init__(self, raw_option=None):
        if raw_option:
            self.opt_kind = raw_option[0]
        else:
            self.opt_kind = DHCP_OPT_END

    @property
    def raw_option(self):
        return struct.pack("!B", self.opt_kind)

    def __str__(self):
        return "end"


class DhcpOptMessageType:
    """ DHCP option Message Type """

    name = "message_type"

    def __init__(self, raw_option=None, opt_message_type=None):
        if raw_option:
            self.opt_kind = raw_option[0]
            self.opt_len = raw_option[1]
            self.opt_message_type = raw_option[2]
        else:
            self.opt_kind = DHCP_OPT_MESSAGE_TYPE
            self.opt_len = DHCP_OPT_MESSAGE_TYPE_LEN
            self.opt_message_type = opt_message_type

    @property
    def raw_option(self):
        return struct.pack("! BBB", self.opt_kind, self.opt_len, self.opt_message_type)

    def __str__(self):
        return f"msg_type {self.opt_size}"


class DhcpOptParameterRequestList:
    """ DHCP option ParameterRequestList """

    name = "parameter_request_list"

    def __init__(self, raw_option=None, opt_list=None):
        if raw_option:
            self.opt_kind = raw_option[0]
            self.opt_len = raw_option[1]
            self.opt_list = raw_option[2 : 2 + self.opt_len]
        else:
            self.opt_kind = DHCP_OPT_PARAMETER_REQUEST_LIST
            self.opt_len = len(opt_list)
            self.opt_list = opt_list

    @property
    def raw_option(self):
        return struct.pack(f"! BB{self.opt_len}s", self.opt_kind, self.opt_len, self.opt_list)

    def __str__(self):
        return f"param_req_list {hexlify(self.opt_list)}"












