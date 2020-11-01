#!/usr/bin/env python3

"""

PyTCP, Python TCP/IP stack, version 0.1 - 2020, Sebastian Majewski
ps_dhcp.py - protocol support libary for DHCP

"""


import struct

import socket
import binascii


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
   |                      Gateway IP Address                       |
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

BOOT_REQUEST = 1
BOOT_REPLY = 2

DHCP_DISCOVER = 1
DHCP_OFFER = 2
DHCP_REQUEST = 3
DHCP_ACK = 5


class DhcpPacket:
    """ Dhcp packet support class """

    protocol = "DHCP"

    def __init__(
        self,
        raw_packet=None,
        dhcp_op=BOOT_REQUEST,
        dhcp_xid=None,
        dhcp_flag_b=False,
        dhcp_ciaddr="0.0.0.0",
        dhcp_yiaddr="0.0.0.0",
        dhcp_siaddr="0.0.0.0",
        dhcp_giaddr="0.0.0.0",
        dhcp_chaddr=None,
        dhcp_subnet_mask=None,
        dhcp_router=None,
        dhcp_dns=None,
        dhcp_host_name=None,
        dhcp_domain_name=None,
        dhcp_req_ip_addr=None,
        dhcp_addr_lease_time=None,
        dhcp_srv_id=None,
        dhcp_param_req_list=None,
        dhcp_msg_type=None,
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

            dhcp_opt_cls = {
                DHCP_OPT_SUBNET_MASK: DhcpOptSubnetMask,
                DHCP_OPT_ROUTER: DhcpOptRouter,
                DHCP_OPT_DNS: DhcpOptDns,
                DHCP_OPT_HOST_NAME: DhcpOptHostName,
                DHCP_OPT_DOMAIN_NAME: DhcpOptDomainName,
                DHCP_OPT_REQ_IP_ADDR: DhcpOptReqIpAddr,
                DHCP_OPT_ADDR_LEASE_TIME: DhcpOptAddrLeaseTime,
                DHCP_OPT_PARAM_REQ_LIST: DhcpOptParamReqList,
                DHCP_OPT_SRV_ID: DhcpOptSrvId,
                DHCP_OPT_MSG_TYPE: DhcpOptMsgType,
            }

            i = 0

            while i < len(raw_options):

                if raw_options[i] == DHCP_OPT_END:
                    self.dhcp_options.append(DhcpOptEnd())
                    break

                cls = dhcp_opt_cls.get(raw_options[i], DhcpOptUnk)
                self.dhcp_options.append(cls(raw_options[i : i + raw_options[i + 1] + 2]))
                i += self.raw_options[i + 1] + 2

        # Packet building
        else:
            self.dhcp_op = dhcp_op
            self.dhcp_htype = 1
            self.dhcp_hlen = 6
            self.dhcp_hops = 0
            self.dhcp_xid = dhcp_xid
            self.dhcp_secs = 0
            self.dhcp_flag_b = dhcp_flag_b
            self.dhcp_ciaddr = dhcp_ciaddr
            self.dhcp_yiaddr = dhcp_yiaddr
            self.dhcp_siaddr = dhcp_siaddr
            self.dhcp_giaddr = dhcp_giaddr
            self.dhcp_chaddr = dhcp_chaddr
            self.dhcp_sname = b"\0" * 64
            self.dhcp_file = b"\0" * 128

            self.dhcp_options = []

            if dhcp_subnet_mask:
                self.dhcp_options.append(DhcpOptSubnetMask(opt_subnet_mask=dhcp_subnet_mask))

            if dhcp_router:
                self.dhcp_options.append(DhcpOptRouter(opt_router=dhcp_router))

            if dhcp_dns:
                self.dhcp_options.append(DhcpOptDns(opt_dns=dhcp_dns))

            if dhcp_host_name:
                self.dhcp_options.append(DhcpOptHostName(opt_host_name=dhcp_host_name))

            if dhcp_domain_name:
                self.dhcp_options.append(DhcpOptDomainName(opt_domain_name=dhcp_domain_name))

            if dhcp_req_ip_addr:
                self.dhcp_options.append(DhcpOptReqIpAddr(opt_req_ip_addr=dhcp_req_ip_addr))

            if dhcp_addr_lease_time:
                self.dhcp_options.append(DhcpOptAddrLeaseTime(opt_addr_lease_time=dhcp_addr_lease_time))

            if dhcp_srv_id:
                self.dhcp_options.append(DhcpOptSrvId(opt_srv_id=dhcp_srv_id))

            if dhcp_param_req_list:
                self.dhcp_options.append(DhcpOptParamReqList(opt_param_req_list=dhcp_param_req_list))

            if dhcp_msg_type:
                self.dhcp_options.append(DhcpOptMsgType(opt_msg_type=dhcp_msg_type))

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
    def dhcp_subnet_mask(self):
        """ DHCP option - Subnet Mask (1) """

        for option in self.dhcp_options:
            if option.opt_code == DHCP_OPT_SUBNET_MASK:
                return option.opt_subnet_mask

    @property
    def dhcp_router(self):
        """ DHCP option - Router (3) """

        for option in self.dhcp_options:
            if option.opt_code == DHCP_OPT_ROUTER:
                return option.opt_router

    @property
    def dhcp_dns(self):
        """ DHCP option - Domain Name Server (6) """

        for option in self.dhcp_options:
            if option.opt_code == DHCP_OPT_DNS:
                return option.opt_dns

    @property
    def dhcp_host_name(self):
        """ DHCP option - Host Name (12) """

        for option in self.dhcp_options:
            if option.opt_code == DHCP_OPT_HOST_NAME:
                return option.opt_host_name

    @property
    def dhcp_domain_name(self):
        """ DHCP option - Domain Name (12) """

        for option in self.dhcp_options:
            if option.opt_code == DHCP_OPT_DOMAIN_NAME:
                return option.opt_domain_name

    @property
    def dhcp_req_ip_addr(self):
        """ DHCP option - Requested IP Address (50) """

        for option in self.dhcp_options:
            if option.opt_code == DHCP_OPT_REQ_IP_ADDR:
                return option.opt_req_ip_addr

    @property
    def dhcp_addr_lease_time(self):
        """ DHCP option - Address Lease Time (51) """

        for option in self.dhcp_options:
            if option.opt_code == DHCP_OPT_ADDR_LEASE_TIME:
                return option.opt_addr_lease_time

    @property
    def dhcp_msg_type(self):
        """ DHCP option - Message Type (53) """

        for option in self.dhcp_options:
            if option.opt_code == DHCP_OPT_MSG_TYPE:
                return option.opt_msg_type

    @property
    def dhcp_srv_id(self):
        """ DHCP option - Server Identivier (54) """

        for option in self.dhcp_options:
            if option.opt_code == DHCP_OPT_SRV_ID:
                return option.opt_srv_id

    @property
    def dhcp_param_req_list(self):
        """ DHCP option - Parameter Request List (55) """

        for option in self.dhcp_options:
            if option.opt_code == DHCP_OPT_PARAM_REQ_LIST:
                return option.opt_param_req_list

    @property
    def raw_packet(self):
        """ Packet in raw format """

        return self.raw_header + self.raw_options

    def get_raw_packet(self):
        """ Get packet in raw format ready to be processed by lower level protocol """

        return self.raw_packet


"""

   DHCP options

"""

# DHCP option - End (255)

DHCP_OPT_END = 255
DHCP_OPT_END_LEN = 0


class DhcpOptEnd:
    """ DHCP option - End (255) """

    def __init__(self):
        self.opt_code = DHCP_OPT_END

    @property
    def raw_option(self):
        return struct.pack("!B", self.opt_code)

    def __str__(self):
        return "end"


# DHCP option - Subnet Mask (1)

DHCP_OPT_SUBNET_MASK = 1
DHCP_OPT_SUBNET_MASK_LEN = 4


class DhcpOptSubnetMask:
    """ DHCP option - Subnet Mask (1) """

    def __init__(self, raw_option=None, opt_subnet_mask=None):
        if raw_option:
            self.opt_code = raw_option[0]
            self.opt_len = raw_option[1]
            self.opt_subnet_mask = socket.inet_ntoa(struct.unpack("!4s", raw_option[2:6])[0])
        else:
            self.opt_code = DHCP_OPT_SUBNET_MASK
            self.opt_len = DHCP_OPT_SUBNET_MASK_LEN
            self.opt_subnet_mask = opt_subnet_mask

    @property
    def raw_option(self):
        return struct.pack("! BB 4s", self.opt_code, self.opt_len, socket.inet_aton(self.opt_subnet_mask))

    def __str__(self):
        return f"subnet_mask {self.opt_subnet_mask}"


# DHCP option - Router (3)

DHCP_OPT_ROUTER = 3
DHCP_OPT_ROUTER_LEN = None


class DhcpOptRouter:
    """ DHCP option - Router (3) """

    def __init__(self, raw_option=None, opt_router=None):
        if raw_option:
            self.opt_code = raw_option[0]
            self.opt_len = raw_option[1]
            self.opt_router = [socket.inet_ntoa(struct.unpack("!4s", raw_option[_ : _ + 4])[0]) for _ in range(2, 2 + self.opt_len, 4)]
        else:
            self.opt_code = DHCP_OPT_ROUTER
            self.opt_len = len(opt_router) * 4
            self.opt_router = opt_router

    @property
    def raw_option(self):
        return struct.pack(f"! BB {len(self.opt_router) * 4}s", self.opt_code, self.opt_len, b"".join(socket.inet_aton(_) for _ in self.opt_router))

    def __str__(self):
        return f"router {self.router}"


# DHCP option - Domain Name Server (6)

DHCP_OPT_DNS = 6
DHCP_OPT_DNS_LEN = None


class DhcpOptDns:
    """ DHCP option - Domain Name Server (6) """

    def __init__(self, raw_option=None, opt_dns=None):
        if raw_option:
            self.opt_code = raw_option[0]
            self.opt_len = raw_option[1]
            self.opt_dns = [socket.inet_ntoa(struct.unpack("!4s", raw_option[_ : _ + 4])[0]) for _ in range(2, 2 + self.opt_len, 4)]
        else:
            self.opt_code = DHCP_OPT_DNS
            self.opt_len = len(opt_dns) * 4
            self.opt_dns = opt_dns

    @property
    def raw_option(self):
        return struct.pack(f"! BB {len(self.opt_dns) * 4}s", self.opt_code, self.opt_len, b"".join(socket.inet_aton(_) for _ in self.opt_dns))

    def __str__(self):
        return f"router {self.dns}"


# DHCP option - Host Name (12)

DHCP_OPT_HOST_NAME = 12
DHCP_OPT_HOST_NAME_LEN = None


class DhcpOptHostName:
    """ DHCP option - Host Name (12) """

    def __init__(self, raw_option=None, opt_host_name=None):
        if raw_option:
            self.opt_code = raw_option[0]
            self.opt_len = raw_option[1]
            self.opt_host_name = str(raw_option[2 : 2 + self.opt_len], "utf-8")
        else:
            self.opt_code = DHCP_OPT_HOST_NAME
            self.opt_len = len(opt_host_name)
            self.opt_host_name = opt_host_name

    @property
    def raw_option(self):
        return struct.pack(f"! BB {self.opt_len}s", self.opt_code, self.opt_len, bytes(self.opt_host_name, "utf-8"))

    def __str__(self):
        return f"host_name {self.opt_host_name}"


# DHCP option - Domain Name (15)

DHCP_OPT_DOMAIN_NAME = 15
DHCP_OPT_DOMAIN_NAME_LEN = None


class DhcpOptDomainName:
    """ DHCP option - Domain Name (15) """

    def __init__(self, raw_option=None, opt_domain_name=None):
        if raw_option:
            self.opt_code = raw_option[0]
            self.opt_len = raw_option[1]
            self.opt_domain_name = str(raw_option[2 : 2 + self.opt_len], "utf-8")
        else:
            self.opt_code = DHCP_OPT_DOMAIN_NAME
            self.opt_len = len(opt_domain_name)
            self.opt_domain_name = opt_domain_name

    @property
    def raw_option(self):
        return struct.pack(f"! BB {self.opt_len}s", self.opt_code, self.opt_len, bytes(self.opt_domain_name, "utf-8"))

    def __str__(self):
        return f"domain_name {self.opt_domain_name}"


# DHCP option - Requested IP Address (50)

DHCP_OPT_REQ_IP_ADDR = 50
DHCP_OPT_REQ_IP_ADDR_LEN = 4


class DhcpOptReqIpAddr:
    """ DHCP option - Requested IP Address (50) """

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
        return struct.pack("! BB 4s", self.opt_code, self.opt_len, socket.inet_aton(self.opt_req_ip_addr))

    def __str__(self):
        return f"req_ip_addr {self.opt_addr}"


# DHCP option - Address Lease Time (51)

DHCP_OPT_ADDR_LEASE_TIME = 51
DHCP_OPT_ADDR_LEASE_TIME_LEN = 4


class DhcpOptAddrLeaseTime:
    """ DHCP option - Address Lease Time (51) """

    def __init__(self, raw_option=None, opt_addr_lease_time=None):
        if raw_option:
            self.opt_code = raw_option[0]
            self.opt_len = raw_option[1]
            self.opt_addr_lease_time = struct.unpack("!L", raw_option[2:6])[0]
        else:
            self.opt_code = DHCP_OPT_ADDR_LEASE_TIME
            self.opt_len = DHCP_OPT_ADDR_LEASE_TIME_LEN
            self.opt_addr_lease_time = opt_addr_lease_time

    @property
    def raw_option(self):
        return struct.pack("! BB L", self.opt_code, self.opt_len, self.opt_addr_lease_time)

    def __str__(self):
        return f"addr_lease_time {self.addr_lease_time}s"


# DHCP option - Message Type (53)

DHCP_OPT_MSG_TYPE = 53
DHCP_OPT_MSG_TYPE_LEN = 1


class DhcpOptMsgType:
    """ DHCP option - Message Type (53) """

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


# DHCP option - Server Identifier (54)

DHCP_OPT_SRV_ID = 54
DHCP_OPT_SRV_ID_LEN = 4


class DhcpOptSrvId:
    """ DHCP option - Server Identifier (54) """

    def __init__(self, raw_option=None, opt_srv_id=None):
        if raw_option:
            self.opt_code = raw_option[0]
            self.opt_len = raw_option[1]
            self.opt_srv_id = socket.inet_ntoa(struct.unpack("!4s", raw_option[2:6])[0])
        else:
            self.opt_code = DHCP_OPT_SRV_ID
            self.opt_len = DHCP_OPT_SRV_ID_LEN
            self.opt_srv_id = opt_srv_id

    @property
    def raw_option(self):
        return struct.pack("! BB 4s", self.opt_code, self.opt_len, socket.inet_aton(self.opt_srv_id))

    def __str__(self):
        return f"srv_id {self.srv_id}"


# DHCP option - Parameter Request List (55)

DHCP_OPT_PARAM_REQ_LIST = 55
DHCP_OPT_PARAM_REQ_LIST_LEN = None


class DhcpOptParamReqList:
    """ DHCP option - Parameter Request List (55) """

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
        return struct.pack(f"! BB {self.opt_len}s", self.opt_code, self.opt_len, self.opt_param_req_list)

    def __str__(self):
        return f"param_req_list {binascii.hexlify(self.opt_list)}"


# DHCP option not supported by this stack


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
        return "unk"
