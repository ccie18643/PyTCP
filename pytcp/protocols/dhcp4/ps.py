#!/usr/bin/env python3

############################################################################
#                                                                          #
#  PyTCP - Python TCP/IP stack                                             #
#  Copyright (C) 2020-present Sebastian Majewski                           #
#                                                                          #
#  This program is free software: you can redistribute it and/or modify    #
#  it under the terms of the GNU General Public License as published by    #
#  the Free Software Foundation, either version 3 of the License, or       #
#  (at your option) any later version.                                     #
#                                                                          #
#  This program is distributed in the hope that it will be useful,         #
#  but WITHOUT ANY WARRANTY; without even the implied warranty of          #
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the           #
#  GNU General Public License for more details.                            #
#                                                                          #
#  You should have received a copy of the GNU General Public License       #
#  along with this program.  If not, see <https://www.gnu.org/licenses/>.  #
#                                                                          #
#  Author's email: ccie18643@gmail.com                                     #
#  Github repository: https://github.com/ccie18643/PyTCP                   #
#                                                                          #
############################################################################

# pylint: disable = too-many-lines
# pylint: disable = too-many-instance-attributes
# pylint: disable = too-many-locals
# pylint: disable = too-many-branches
# pylint: disable = too-many-arguments
# pylint: disable = too-many-statements

"""
Module contains protocol support library for the DHCPv4 protocol.
This library uses old (pre-FPP) format and needs to be rewritten
at some point.

pytcp/protocols/dhcp4/ps.py

ver 2.7
"""


from __future__ import annotations

import struct

from pytcp.lib.ip4_address import Ip4Address, Ip4Mask

# DHCP packet header (RFC 2131)

# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |   Operation   |    HW Type    |     HW Len    |     Hops      |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                     Transaction Identifier                    |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |         Seconds Elapsed       |B|          Reserved           |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                       Client IP Address                       |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                        Your IP Address                        |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                       Server IP Address                       |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                      Gateway IP Address                       |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                                                               |
# |                            Client                             |
# |                          HW Address                           |
# |                                                               |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                                                               |
# |                                                               |
# |                                                               |
# |                                                               |
# |                                                               |
# |                                                               |
# |                                                               |
# |                             Server                            |
# |                            Hostname                           |
# |                                                               |
# |                                                               |
# |                                                               |
# |                                                               |
# |                                                               |
# |                                                               |
# |                                                               |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                                                               |
# |                                                               |
# |                                                               |
# |                                                               |
# |                                                               |
# |                                                               |
# |                                                               |
# |                                                               |
# |                                                               |
# |                                                               |
# |                                                               |
# |                                                               |
# |                                                               |
# |                                                               |
# |                                                               |
# |                          Bootfile                             |
# |                            Name                               |
# |                                                               |
# |                                                               |
# |                                                               |
# |                                                               |
# |                                                               |
# |                                                               |
# |                                                               |
# |                                                               |
# |                                                               |
# |                                                               |
# |                                                               |
# |                                                               |
# |                                                               |
# |                                                               |
# |                                                               |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# ~                          Options                              ~
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


DHCP4_HEADER_LEN = 236 + 4

DHCP4_OP_REQUEST = 1
DHCP4_OP_REPLY = 2

DHCP4_MSG_DISCOVER = 1
DHCP4_MSG_OFFER = 2
DHCP4_MSG_REQUEST = 3
DHCP4_MSG_DECLINE = 4
DHCP4_MSG_ACK = 5
DHCP4_MSG_NAK = 6
DHCP4_MSG_RELEASE = 7
DHCP4_MSG_INFORM = 8


class Dhcp4Packet:
    """Dhcp packet support class"""

    protocol = "DHCP"

    def __init__(
        self,
        raw_packet: bytes | None = None,
        dhcp_op: int | None = None,
        dhcp_xid: int | None = None,
        dhcp_flag_b: bool | None = False,
        dhcp_ciaddr: Ip4Address | None = None,
        dhcp_yiaddr: Ip4Address | None = None,
        dhcp_siaddr: Ip4Address | None = None,
        dhcp_giaddr: Ip4Address | None = None,
        dhcp_chaddr: bytes | None = None,
        dhcp_subnet_mask: Ip4Mask | None = None,
        dhcp_router: list[Ip4Address] | None = None,
        dhcp_dns: list[Ip4Address] | None = None,
        dhcp_host_name: str | None = None,
        dhcp_domain_name: str | None = None,
        dhcp_req_ip_addr: Ip4Address | None = None,
        dhcp_addr_lease_time: int | None = None,
        dhcp_srv_id: Ip4Address | None = None,
        dhcp_param_req_list: list[int] | None = None,
        dhcp_msg_type: int | None = None,
    ) -> None:
        """
        Class constructor.
        """

        # Packet parsing
        if raw_packet:
            raw_header = raw_packet[:DHCP4_HEADER_LEN]

            raw_options = raw_packet[DHCP4_HEADER_LEN:]

            self.dhcp_op = raw_header[0]
            self.dhcp_hwtype = raw_header[1]
            self.dhcp_hwlen = raw_header[2]
            self.dhcp_hops = raw_header[3]
            self.dhcp_xid = struct.unpack("!L", raw_header[4:8])[0]
            self.dhcp_secs = struct.unpack("!H", raw_header[8:10])[0]
            self.dhcp_flag_b = bool(
                struct.unpack("!H", raw_header[10:12])[0] & 0b1000000000000000
            )
            self.dhcp_ciaddr = Ip4Address(raw_header[12:16])
            self.dhcp_yiaddr = Ip4Address(raw_header[16:20])
            self.dhcp_siaddr = Ip4Address(raw_header[20:24])
            self.dhcp_giaddr = Ip4Address(raw_header[24:28])
            self.dhcp_chaddr = raw_header[28 : 28 + self.dhcp_hwlen]
            self.dhcp_sname = raw_header[44:108]
            self.dhcp_file = raw_header[108:236]

            self.dhcp_options: list[
                Dhcp4OptSubnetMask
                | Dhcp4OptRouter
                | Dhcp4OptDns
                | Dhcp4OptHostName
                | Dhcp4OptDomainName
                | Dhcp4OptReqIpAddr
                | Dhcp4OptAddrLeaseTime
                | Dhcp4OptParamReqList
                | Dhcp4OptSrvId
                | Dhcp4OptMsgType
                | Dhcp4OptPad
                | Dhcp4OptEnd
            ] = []

            opt_cls = {
                DHCP4_OPT_SUBNET_MASK: Dhcp4OptSubnetMask,
                DHCP4_OPT_ROUTER: Dhcp4OptRouter,
                DHCP4_OPT_DNS: Dhcp4OptDns,
                DHCP4_OPT_HOST_NAME: Dhcp4OptHostName,
                DHCP4_OPT_DOMAIN_NAME: Dhcp4OptDomainName,
                DHCP4_OPT_REQ_IP4_ADDR: Dhcp4OptReqIpAddr,
                DHCP4_OPT_ADDR_LEASE_TIME: Dhcp4OptAddrLeaseTime,
                DHCP4_OPT_PARAM_REQ_LIST: Dhcp4OptParamReqList,
                DHCP4_OPT_SRV_ID: Dhcp4OptSrvId,
                DHCP4_OPT_MSG_TYPE: Dhcp4OptMsgType,
            }

            i = 0

            while i < len(raw_options):
                if raw_options[i] == DHCP4_OPT_END:
                    self.dhcp_options.append(Dhcp4OptEnd())
                    break

                if raw_options[i] == DHCP4_OPT_PAD:
                    self.dhcp_options.append(Dhcp4OptPad())
                    i += DHCP4_OPT_PAD_LEN
                    continue

                self.dhcp_options.append(
                    opt_cls.get(raw_options[i], Dhcp4OptUnk)(
                        raw_options[i : i + raw_options[i + 1] + 2]
                    )
                )
                i += self.raw_options[i + 1] + 2

        # Packet building
        else:
            assert dhcp_op is not None
            assert dhcp_xid is not None
            assert dhcp_flag_b is not None
            assert dhcp_ciaddr is not None
            assert dhcp_yiaddr is not None
            assert dhcp_siaddr is not None
            assert dhcp_giaddr is not None
            assert dhcp_chaddr is not None

            self.dhcp_op = dhcp_op
            self.dhcp_hwtype = 1
            self.dhcp_hwlen = 6
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
                self.dhcp_options.append(
                    Dhcp4OptSubnetMask(opt_subnet_mask=dhcp_subnet_mask)
                )

            if dhcp_router:
                self.dhcp_options.append(Dhcp4OptRouter(opt_router=dhcp_router))

            if dhcp_dns:
                self.dhcp_options.append(Dhcp4OptDns(opt_dns=dhcp_dns))

            if dhcp_host_name:
                self.dhcp_options.append(
                    Dhcp4OptHostName(opt_host_name=dhcp_host_name)
                )

            if dhcp_domain_name:
                self.dhcp_options.append(
                    Dhcp4OptDomainName(opt_domain_name=dhcp_domain_name)
                )

            if dhcp_req_ip_addr:
                self.dhcp_options.append(
                    Dhcp4OptReqIpAddr(opt_req_ip_addr=dhcp_req_ip_addr)
                )

            if dhcp_addr_lease_time:
                self.dhcp_options.append(
                    Dhcp4OptAddrLeaseTime(
                        opt_addr_lease_time=dhcp_addr_lease_time
                    )
                )

            if dhcp_srv_id:
                self.dhcp_options.append(Dhcp4OptSrvId(opt_srv_id=dhcp_srv_id))

            if dhcp_param_req_list:
                self.dhcp_options.append(
                    Dhcp4OptParamReqList(opt_param_req_list=dhcp_param_req_list)
                )

            if dhcp_msg_type:
                self.dhcp_options.append(
                    Dhcp4OptMsgType(opt_msg_type=dhcp_msg_type)
                )

            self.dhcp_options.append(Dhcp4OptEnd())

    def __str__(self) -> str:
        """
        Packet log string.
        """
        return f"DHCP op {self.dhcp_op}"

    def __len__(self) -> int:
        """
        Length of the packet.
        """
        return len(self.raw_packet)

    @property
    def raw_header(self) -> bytes:
        """
        Packet header in raw format.
        """
        return struct.pack(
            "! BBBB L HH 4s 4s 4s 4s 16s 64s 128s 4s",
            self.dhcp_op,
            self.dhcp_hwtype,
            self.dhcp_hwlen,
            self.dhcp_hops,
            self.dhcp_xid,
            self.dhcp_secs,
            self.dhcp_flag_b << 15,
            bytes(self.dhcp_ciaddr),
            bytes(self.dhcp_yiaddr),
            bytes(self.dhcp_siaddr),
            bytes(self.dhcp_giaddr),
            bytes(self.dhcp_chaddr) + b"\0" * 10,
            self.dhcp_sname,
            self.dhcp_file,
            b"\x63\x82\x53\x63",
        )

    @property
    def raw_options(self) -> bytes:
        """
        Packet options in raw format.
        """
        raw_options = b""
        for option in self.dhcp_options:
            raw_options += option.raw_option
        return raw_options

    @property
    def dhcp_subnet_mask(self) -> Ip4Mask | None:
        """
        DHCP option - Subnet Mask (1).
        """
        for option in self.dhcp_options:
            if isinstance(option, Dhcp4OptSubnetMask):
                return option.opt_subnet_mask
        return None

    @property
    def dhcp_router(self) -> list[Ip4Address] | None:
        """
        DHCP option - Router (3).
        """
        for option in self.dhcp_options:
            if isinstance(option, Dhcp4OptRouter):
                return option.opt_router
        return None

    @property
    def dhcp_dns(self) -> list[Ip4Address] | None:
        """
        DHCP option - Domain Name Server (6).
        """
        for option in self.dhcp_options:
            if isinstance(option, Dhcp4OptDns):
                return option.opt_dns
        return None

    @property
    def dhcp_host_name(self) -> str | None:
        """
        DHCP option - Host Name (12).
        """
        for option in self.dhcp_options:
            if isinstance(option, Dhcp4OptHostName):
                return option.opt_host_name
        return None

    @property
    def dhcp_domain_name(self) -> str | None:
        """
        DHCP option - Domain Name (15).
        """
        for option in self.dhcp_options:
            if isinstance(option, Dhcp4OptDomainName):
                return option.opt_domain_name
        return None

    @property
    def dhcp_req_ip_addr(self) -> Ip4Address | None:
        """
        DHCP option - Requested IP Address (50).
        """
        for option in self.dhcp_options:
            if isinstance(option, Dhcp4OptReqIpAddr):
                return option.opt_req_ip_addr
        return None

    @property
    def dhcp_addr_lease_time(self) -> int | None:
        """
        DHCP option - Address Lease Time (51).
        """
        for option in self.dhcp_options:
            if isinstance(option, Dhcp4OptAddrLeaseTime):
                return option.opt_addr_lease_time
        return None

    @property
    def dhcp_msg_type(self) -> int | None:
        """
        DHCP option - Message Type (53).
        """
        for option in self.dhcp_options:
            if isinstance(option, Dhcp4OptMsgType):
                return option.opt_msg_type
        return None

    @property
    def dhcp_srv_id(self) -> Ip4Address | None:
        """
        DHCP option - Server Identifier (54).
        """
        for option in self.dhcp_options:
            if isinstance(option, Dhcp4OptSrvId):
                return option.opt_srv_id
        return None

    @property
    def dhcp_param_req_list(self) -> list[int] | None:
        """
        DHCP option - Parameter Request List (55).
        """
        for option in self.dhcp_options:
            if isinstance(option, Dhcp4OptParamReqList):
                return option.opt_param_req_list
        return None

    @property
    def raw_packet(self) -> bytes:
        """
        Packet in raw format.
        """
        return self.raw_header + self.raw_options


#
#   DHCP options
#


# DHCP option - End (255)

DHCP4_OPT_END = 255
DHCP4_OPT_END_LEN = 0


class Dhcp4OptEnd:
    """
    DHCP option - End (255).
    """

    def __init__(self) -> None:
        """
        Option constructor.
        """
        self.opt_code = DHCP4_OPT_END

    @property
    def raw_option(self) -> bytes:
        """
        Option in raw form.
        """
        return struct.pack("!B", self.opt_code)

    def __str__(self) -> str:
        """
        Option log string.
        """
        return "end"


# DHCP option - Pad (0)

DHCP4_OPT_PAD = 0
DHCP4_OPT_PAD_LEN = 0


class Dhcp4OptPad:
    """
    DHCP option - Pad (0).
    """

    def __init__(self) -> None:
        """
        Option constructor.
        """
        self.opt_code = DHCP4_OPT_PAD

    @property
    def raw_option(self) -> bytes:
        """
        Option in raw form.
        """
        return struct.pack("!B", self.opt_code)

    def __str__(self) -> str:
        """
        Option log string.
        """
        return "pad"


# DHCP option - Subnet Mask (1)

DHCP4_OPT_SUBNET_MASK = 1
DHCP4_OPT_SUBNET_MASK_LEN = 4


class Dhcp4OptSubnetMask:
    """DHCP option - Subnet Mask (1)"""

    def __init__(
        self,
        raw_option: bytes | None = None,
        opt_subnet_mask: Ip4Mask | None = None,
    ) -> None:
        """
        Option constructor.
        """
        if raw_option:
            self.opt_code = raw_option[0]
            self.opt_len = raw_option[1]
            self.opt_subnet_mask = Ip4Mask(raw_option[2:6])
        else:
            assert opt_subnet_mask is not None
            self.opt_code = DHCP4_OPT_SUBNET_MASK
            self.opt_len = DHCP4_OPT_SUBNET_MASK_LEN
            self.opt_subnet_mask = opt_subnet_mask

    @property
    def raw_option(self) -> bytes:
        """
        Option in raw form.
        """
        return struct.pack(
            "! BB 4s", self.opt_code, self.opt_len, bytes(self.opt_subnet_mask)
        )

    def __str__(self) -> str:
        """
        Option log string.
        """
        return f"subnet_mask {self.opt_subnet_mask}"


# DHCP option - Router (3)

DHCP4_OPT_ROUTER = 3
DHCP4_OPT_ROUTER_LEN = None


class Dhcp4OptRouter:
    """
    DHCP option - Router (3).
    """

    def __init__(
        self,
        raw_option: bytes | None = None,
        opt_router: list[Ip4Address] | None = None,
    ) -> None:
        """
        Option constructor.
        """
        if raw_option:
            self.opt_code = raw_option[0]
            self.opt_len = raw_option[1]
            self.opt_router = [
                Ip4Address(raw_option[_ : _ + 4])
                for _ in range(2, 2 + self.opt_len, 4)
            ]
        else:
            assert opt_router is not None
            self.opt_code = DHCP4_OPT_ROUTER
            self.opt_len = len(opt_router) * 4
            self.opt_router = [Ip4Address(_) for _ in opt_router]

    @property
    def raw_option(self) -> bytes:
        """
        Option in raw form.
        """
        return struct.pack(
            f"! BB {len(self.opt_router) * 4}s",
            self.opt_code,
            self.opt_len,
            b"".join(bytes(_) for _ in self.opt_router),
        )

    def __str__(self) -> str:
        """
        Option log string.
        """
        return f"router {self.opt_router}"


# DHCP option - Domain Name Server (6)

DHCP4_OPT_DNS = 6
DHCP4_OPT_DNS_LEN = None


class Dhcp4OptDns:
    """
    DHCP option - Domain Name Server (6).
    """

    def __init__(
        self,
        raw_option: bytes | None = None,
        opt_dns: list[Ip4Address] | None = None,
    ) -> None:
        """
        Option constructor.
        """
        if raw_option:
            self.opt_code = raw_option[0]
            self.opt_len = raw_option[1]
            self.opt_dns = [
                Ip4Address(raw_option[_ : _ + 4])
                for _ in range(2, 2 + self.opt_len, 4)
            ]
        else:
            assert opt_dns is not None
            self.opt_code = DHCP4_OPT_DNS
            self.opt_len = len(opt_dns) * 4
            self.opt_dns = [Ip4Address(_) for _ in opt_dns]

    @property
    def raw_option(self) -> bytes:
        """
        Option in raw form.
        """
        return struct.pack(
            f"! BB {len(self.opt_dns) * 4}s",
            self.opt_code,
            self.opt_len,
            b"".join(bytes(_) for _ in self.opt_dns),
        )

    def __str__(self) -> str:
        """
        Option log string.
        """
        return f"router {self.opt_dns}"


# DHCP option - Host Name (12)

DHCP4_OPT_HOST_NAME = 12
DHCP4_OPT_HOST_NAME_LEN = None


class Dhcp4OptHostName:
    """
    DHCP option - Host Name (12).
    """

    def __init__(
        self, raw_option: bytes | None = None, opt_host_name: str | None = None
    ) -> None:
        """
        Option constructor.
        """
        if raw_option:
            self.opt_code = raw_option[0]
            self.opt_len = raw_option[1]
            self.opt_host_name = str(raw_option[2 : 2 + self.opt_len], "utf-8")
        else:
            assert opt_host_name is not None
            self.opt_code = DHCP4_OPT_HOST_NAME
            self.opt_len = len(opt_host_name)
            self.opt_host_name = opt_host_name

    @property
    def raw_option(self) -> bytes:
        """
        Option in raw form.
        """
        return struct.pack(
            f"! BB {self.opt_len}s",
            self.opt_code,
            self.opt_len,
            bytes(self.opt_host_name, "utf-8"),
        )

    def __str__(self) -> str:
        """
        Option log string.
        """
        return f"host_name {self.opt_host_name}"


# DHCP option - Domain Name (15)

DHCP4_OPT_DOMAIN_NAME = 15
DHCP4_OPT_DOMAIN_NAME_LEN = None


class Dhcp4OptDomainName:
    """
    DHCP option - Domain Name (15).
    """

    def __init__(
        self,
        raw_option: bytes | None = None,
        opt_domain_name: str | None = None,
    ) -> None:
        """
        Option constructor.
        """
        if raw_option:
            self.opt_code = raw_option[0]
            self.opt_len = raw_option[1]
            self.opt_domain_name = str(
                raw_option[2 : 2 + self.opt_len], "utf-8"
            )
        else:
            assert opt_domain_name is not None
            self.opt_code = DHCP4_OPT_DOMAIN_NAME
            self.opt_len = len(opt_domain_name)
            self.opt_domain_name = opt_domain_name

    @property
    def raw_option(self) -> bytes:
        """
        Option in raw form.
        """
        return struct.pack(
            f"! BB {self.opt_len}s",
            self.opt_code,
            self.opt_len,
            bytes(self.opt_domain_name, "utf-8"),
        )

    def __str__(self) -> str:
        """
        Option log string.
        """
        return f"domain_name {self.opt_domain_name}"


# DHCP option - Requested IP Address (50)

DHCP4_OPT_REQ_IP4_ADDR = 50
DHCP4_OPT_REQ_IP4_ADDR_LEN = 4


class Dhcp4OptReqIpAddr:
    """
    DHCP option - Requested IP Address (50).
    """

    def __init__(
        self,
        raw_option: bytes | None = None,
        opt_req_ip_addr: Ip4Address | None = None,
    ) -> None:
        """
        Option constructor.
        """
        if raw_option:
            self.opt_code = raw_option[0]
            self.opt_len = raw_option[1]
            self.opt_req_ip_addr = Ip4Address(raw_option[2:6])
        else:
            assert opt_req_ip_addr is not None
            self.opt_code = DHCP4_OPT_REQ_IP4_ADDR
            self.opt_len = DHCP4_OPT_REQ_IP4_ADDR_LEN
            self.opt_req_ip_addr = Ip4Address(opt_req_ip_addr)

    @property
    def raw_option(self) -> bytes:
        """
        Option in raw form.
        """
        return struct.pack(
            "! BB 4s", self.opt_code, self.opt_len, bytes(self.opt_req_ip_addr)
        )

    def __str__(self) -> str:
        """
        Option log string.
        """
        return f"req_ip_addr {self.opt_req_ip_addr}"


# DHCP option - Address Lease Time (51)

DHCP4_OPT_ADDR_LEASE_TIME = 51
DHCP4_OPT_ADDR_LEASE_TIME_LEN = 4


class Dhcp4OptAddrLeaseTime:
    """
    DHCP option - Address Lease Time (51).
    """

    def __init__(
        self,
        raw_option: bytes | None = None,
        opt_addr_lease_time: int | None = None,
    ) -> None:
        """
        Option constructor.
        """
        if raw_option:
            self.opt_code = raw_option[0]
            self.opt_len = raw_option[1]
            self.opt_addr_lease_time: int = struct.unpack(
                "!L", raw_option[2:6]
            )[0]
        else:
            assert opt_addr_lease_time is not None
            self.opt_code = DHCP4_OPT_ADDR_LEASE_TIME
            self.opt_len = DHCP4_OPT_ADDR_LEASE_TIME_LEN
            self.opt_addr_lease_time = opt_addr_lease_time

    @property
    def raw_option(self) -> bytes:
        """
        Option in raw form.
        """
        return struct.pack(
            "! BB L", self.opt_code, self.opt_len, self.opt_addr_lease_time
        )

    def __str__(self) -> str:
        """
        Option log string.
        """
        return f"addr_lease_time {self.opt_addr_lease_time}s"


# DHCP option - Message Type (53)

DHCP4_OPT_MSG_TYPE = 53
DHCP4_OPT_MSG_TYPE_LEN = 1


class Dhcp4OptMsgType:
    """
    DHCP option - Message Type (53).
    """

    def __init__(
        self, raw_option: bytes | None = None, opt_msg_type: int | None = None
    ) -> None:
        """
        Option constructor.
        """
        if raw_option:
            self.opt_code = raw_option[0]
            self.opt_len = raw_option[1]
            self.opt_msg_type = raw_option[2]
        else:
            assert opt_msg_type is not None
            self.opt_code = DHCP4_OPT_MSG_TYPE
            self.opt_len = DHCP4_OPT_MSG_TYPE_LEN
            self.opt_msg_type = opt_msg_type

    @property
    def raw_option(self) -> bytes:
        """
        Option in raw form.
        """
        return struct.pack(
            "! BB B", self.opt_code, self.opt_len, self.opt_msg_type
        )

    def __str__(self) -> str:
        """
        Option log string.
        """
        return f"msg_type {self.opt_msg_type}"


# DHCP option - Server Identifier (54)

DHCP4_OPT_SRV_ID = 54
DHCP4_OPT_SRV_ID_LEN = 4


class Dhcp4OptSrvId:
    """
    DHCP option - Server Identifier (54).
    """

    def __init__(
        self,
        raw_option: bytes | None = None,
        opt_srv_id: Ip4Address | None = None,
    ) -> None:
        """
        Option constructor.
        """
        if raw_option:
            self.opt_code = raw_option[0]
            self.opt_len = raw_option[1]
            self.opt_srv_id = Ip4Address(raw_option[2:6])
        else:
            assert opt_srv_id is not None
            self.opt_code = DHCP4_OPT_SRV_ID
            self.opt_len = DHCP4_OPT_SRV_ID_LEN
            self.opt_srv_id = opt_srv_id

    @property
    def raw_option(self) -> bytes:
        """
        Option in raw form.
        """
        return struct.pack(
            "! BB 4s", self.opt_code, self.opt_len, bytes(self.opt_srv_id)
        )

    def __str__(self) -> str:
        """
        Option log string.
        """
        return f"srv_id {self.opt_srv_id}"


# DHCP option - Parameter Request List (55)

DHCP4_OPT_PARAM_REQ_LIST = 55
DHCP4_OPT_PARAM_REQ_LIST_LEN = None


class Dhcp4OptParamReqList:
    """
    DHCP option - Parameter Request List (55).
    """

    def __init__(
        self,
        raw_option: bytes | None = None,
        opt_param_req_list: list[int] | None = None,
    ) -> None:
        """
        Option constructor.
        """
        if raw_option:
            self.opt_code = raw_option[0]
            self.opt_len = raw_option[1]
            self.opt_param_req_list = [
                int(_) for _ in raw_option[2 : 2 + self.opt_len]
            ]
        else:
            assert opt_param_req_list is not None
            self.opt_code = DHCP4_OPT_PARAM_REQ_LIST
            self.opt_len = len(opt_param_req_list)
            self.opt_param_req_list = opt_param_req_list

    @property
    def raw_option(self) -> bytes:
        """
        Option in raw form.
        """
        return struct.pack(
            f"! BB {self.opt_len}s",
            self.opt_code,
            self.opt_len,
            bytes(self.opt_param_req_list),
        )

    def __str__(self) -> str:
        """
        Option log string.
        """
        return f"param_req_list {self.opt_param_req_list}"


# DHCP option not supported by this stack


class Dhcp4OptUnk:
    """
    DHCP option not supported by this stack.
    """

    def __init__(self, raw_option: bytes) -> None:
        """
        Option constructor.
        """
        self.opt_code = raw_option[0]
        self.opt_len = raw_option[1]
        self.opt_data = raw_option[2 : 2 + self.opt_len]

    @property
    def raw_option(self) -> bytes:
        """
        Option in raw form.
        """
        return struct.pack(
            f"! BB{self.opt_len}s", self.opt_code, self.opt_len, self.opt_data
        )

    def __str__(self) -> str:
        """
        Option log string.
        """
        return "unk"
