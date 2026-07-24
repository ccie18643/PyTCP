################################################################################
##                                                                            ##
##   PyTCP - Python TCP/IP stack                                              ##
##   Copyright (C) 2020-present Sebastian Majewski                            ##
##                                                                            ##
##   This program is free software: you can redistribute it and/or modify     ##
##   it under the terms of the GNU General Public License as published by     ##
##   the Free Software Foundation, either version 3 of the License, or        ##
##   (at your option) any later version.                                      ##
##                                                                            ##
##   This program is distributed in the hope that it will be useful,          ##
##   but WITHOUT ANY WARRANTY; without even the implied warranty of           ##
##   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the             ##
##   GNU General Public License for more details.                             ##
##                                                                            ##
##   You should have received a copy of the GNU General Public License        ##
##   along with this program. If not, see <https://www.gnu.org/licenses/>.    ##
##                                                                            ##
##   Author's email: ccie18643@gmail.com                                      ##
##   Github repository: https://github.com/ccie18643/PyTCP                    ##
##                                                                            ##
################################################################################


# pylint: disable=protected-access
# pyright: reportPrivateUsage=false


"""
Wire-level RX-path integration tests for the DHCPv4 client socket
across the three RFC 2131 FSM phases that bind / connect a
real 'UdpSocket' (port 68 -> port 67):

  - INIT (pre-lease): socket bound to 0.0.0.0:68, connected to
    255.255.255.255:67 because no IPv4 host is yet owned.
  - RENEWING (post-lease): socket bound to 0.0.0.0:68, connected
    to the leasing server's unicast address:67. Server replies
    unicast back to the owned IPv4 address.
  - REBINDING (post-lease): socket bound to 0.0.0.0:68, connected
    to 255.255.255.255:67. Server replies with broadcast.

Every case opens a real 'UdpSocket', drives a realistic
DHCPv4 reply frame through 'PacketHandlerL2._phrx_ethernet',
and asserts the socket actually receives the bytes via
'socket.recv__mv'. This pins the RX-path glue at the
'UdpMetadata.socket_ids' / 'UdpSocket._get_ip_addresses' seam
that the unit tests cannot reach because they mock the
socket layer wholesale.

pytcp/tests/integration/protocols/dhcp4/test__dhcp4__rx_socket_lookup.py

ver 3.0.8
"""

from unittest import TestCase

from net_addr import Buffer, Ip4Address, Ip4Mask, MacAddress
from net_proto.protocols.dhcp4.dhcp4__assembler import Dhcp4Assembler
from net_proto.protocols.dhcp4.dhcp4__enums import (
    Dhcp4MessageType,
    Dhcp4Operation,
)
from net_proto.protocols.dhcp4.options.dhcp4__option__end import (
    Dhcp4OptionEnd,
)
from net_proto.protocols.dhcp4.options.dhcp4__option__lease_time import (
    Dhcp4OptionLeaseTime,
)
from net_proto.protocols.dhcp4.options.dhcp4__option__message_type import (
    Dhcp4OptionMessageType,
)
from net_proto.protocols.dhcp4.options.dhcp4__option__server_id import (
    Dhcp4OptionServerId,
)
from net_proto.protocols.dhcp4.options.dhcp4__option__subnet_mask import (
    Dhcp4OptionSubnetMask,
)
from net_proto.protocols.dhcp4.options.dhcp4__options import Dhcp4Options
from net_proto.protocols.ethernet.ethernet__assembler import EthernetAssembler
from net_proto.protocols.ip4.ip4__assembler import Ip4Assembler
from net_proto.protocols.udp.udp__assembler import UdpAssembler
from pytcp.runtime.socket import AF_INET4, SOCK_DGRAM, socket
from pytcp.tests.lib.network_testcase import (
    STACK__IP4_GATEWAY,
    STACK__IP4_GATEWAY_MAC_ADDRESS,
    STACK__IP4_HOST,
    STACK__MAC_ADDRESS,
    NetworkTestCase,
)

# Per the 'NetworkTestCase' fixture topology, 'STACK__IP4_GATEWAY'
# (10.0.1.1) is on-link and has a known ARP cache entry. We reuse
# it as the DHCPv4 server identity for the post-lease RENEW unicast
# scenario — it is the canonical "in-subnet host PyTCP would
# unicast to" and avoids inventing a new ARP-cache entry.
_DHCP_SERVER_IP: Ip4Address = STACK__IP4_GATEWAY
_DHCP_SERVER_MAC: MacAddress = STACK__IP4_GATEWAY_MAC_ADDRESS

# Owned-host address ('NetworkTestCase' pre-populates the stack
# with this Ip4IfAddr on the packet handler). We pretend the lease
# was issued for this address so the RENEW reply lands unicast at
# the owned IP and the REBIND reply lands broadcast.
_STACK_IP: Ip4Address = STACK__IP4_HOST.address

# Client lease address echoed in the canned reply's 'yiaddr'. The
# value matches the stack's owned IP — the RENEW/REBIND reply
# refreshes the existing lease in place.
_LEASE_IP: Ip4Address = _STACK_IP

_LEASE_MASK: Ip4Mask = Ip4Mask("255.255.255.0")

_LEASE_TIME_SEC: int = 3600

_DHCP_XID: int = 0xDEADBEEF


def _build_dhcp4_reply_frame(
    *,
    eth_src: MacAddress,
    eth_dst: MacAddress,
    ip_src: Ip4Address,
    ip_dst: Ip4Address,
) -> bytes:
    """
    Build an Ethernet/IPv4/UDP/DHCPv4 reply frame the stack's RX
    path will demux into 'packet_handler__udp__rx' and try to
    deliver to a listening UDP socket.

    The DHCP payload is a minimal ACK carrying Message Type,
    Subnet Mask, Lease Time, and Server Identifier — enough to
    satisfy 'Dhcp4Client._do_renew_or_rebind_exchange' validation,
    though this test only inspects the raw bytes the socket
    receives.
    """

    dhcp4 = Dhcp4Assembler(
        dhcp4__operation=Dhcp4Operation.REPLY,
        dhcp4__xid=_DHCP_XID,
        dhcp4__yiaddr=_LEASE_IP,
        dhcp4__siaddr=_DHCP_SERVER_IP,
        dhcp4__chaddr=STACK__MAC_ADDRESS,
        dhcp4__options=Dhcp4Options(
            Dhcp4OptionMessageType(message_type=Dhcp4MessageType.ACK),
            Dhcp4OptionSubnetMask(subnet_mask=_LEASE_MASK),
            Dhcp4OptionLeaseTime(lease_time=_LEASE_TIME_SEC),
            Dhcp4OptionServerId(server_id=_DHCP_SERVER_IP),
            Dhcp4OptionEnd(),
        ),
    )
    udp = UdpAssembler(
        udp__sport=67,
        udp__dport=68,
        udp__payload=bytes(dhcp4),
    )
    ip4 = Ip4Assembler(
        ip4__src=ip_src,
        ip4__dst=ip_dst,
        ip4__payload=udp,
    )
    eth = EthernetAssembler(
        ethernet__src=eth_src,
        ethernet__dst=eth_dst,
        ethernet__payload=ip4,
    )
    buffers: list[Buffer] = []
    eth.assemble(buffers)
    return b"".join(bytes(buf) for buf in buffers)


class TestDhcp4ClientSocketRxDelivery(NetworkTestCase, TestCase):
    """
    Wire-level RX-path delivery tests for the DHCPv4 client socket.
    """

    def test__dhcp4__rx__init_broadcast_reply_delivered(self) -> None:
        """
        Ensure a broadcast DHCP reply (server -> 255.255.255.255:68)
        is delivered to a client socket bound to 0.0.0.0:68 and
        connected to 255.255.255.255:67 — the canonical INIT-state
        pre-lease shape. The packet handler's IPv4 host list is
        cleared for this case so 'pick_local_ip4_address' returns
        unspecified, matching the real pre-lease topology where no
        IPv4 host is owned.

        Reference: RFC 2131 §4.1 (server MUST broadcast pre-lease replies).
        """

        # Pre-lease: clear the owned-host list so the socket binds
        # at local=0.0.0.0 the way the production INIT path does.
        self._packet_handler._ip4_ifaddr = []

        client_socket = socket(family=AF_INET4, type=SOCK_DGRAM)
        try:
            client_socket.bind(("0.0.0.0", 68))
            client_socket.connect(("255.255.255.255", 67))

            frame = _build_dhcp4_reply_frame(
                eth_src=_DHCP_SERVER_MAC,
                eth_dst=MacAddress("ff:ff:ff:ff:ff:ff"),
                ip_src=_DHCP_SERVER_IP,
                ip_dst=Ip4Address("255.255.255.255"),
            )

            from net_proto.lib.packet_rx import PacketRx

            self._packet_handler._phrx_ethernet(PacketRx(frame))

            data = bytes(client_socket.recv__mv(timeout=0.5))
        finally:
            client_socket.close()

        self.assertGreater(
            len(data),
            0,
            msg=(
                "DHCPv4 INIT-state broadcast reply must reach the listening "
                "socket via UdpMetadata.socket_ids lookup. Got: 0 bytes."
            ),
        )

    def test__dhcp4__rx__renew_unicast_reply_delivered(self) -> None:
        """
        Ensure a unicast DHCP reply (server -> owned_ip:68) is
        delivered to a client socket bound to 0.0.0.0:68 and
        connected to the leasing server's unicast address. This is
        the RENEWING-state path that currently fails because the
        post-lease socket lands at '(local=owned_ip, 68, server,
        67)' but the 'socket_ids' lookup only returns
        '(0.0.0.0, 68, 255.255.255.255, 67)'.

        Reference: RFC 2131 §4.4.5 (RENEW: unicast REQUEST after T1).
        """

        client_socket = socket(family=AF_INET4, type=SOCK_DGRAM)
        try:
            client_socket.bind(("0.0.0.0", 68))
            client_socket.connect((str(_DHCP_SERVER_IP), 67))

            frame = _build_dhcp4_reply_frame(
                eth_src=_DHCP_SERVER_MAC,
                eth_dst=STACK__MAC_ADDRESS,
                ip_src=_DHCP_SERVER_IP,
                ip_dst=_STACK_IP,
            )

            from net_proto.lib.packet_rx import PacketRx

            self._packet_handler._phrx_ethernet(PacketRx(frame))

            data = bytes(client_socket.recv__mv(timeout=0.5))
        finally:
            client_socket.close()

        self.assertGreater(
            len(data),
            0,
            msg=(
                "DHCPv4 RENEWING-state unicast reply must reach the listening "
                "socket via UdpMetadata.socket_ids lookup. Got: 0 bytes — the "
                "post-lease unicast variant is missing from the special-case."
            ),
        )

    def test__dhcp4__rx__rebind_broadcast_reply_delivered(self) -> None:
        """
        Ensure a broadcast DHCP reply (server -> 255.255.255.255:68)
        is delivered to a client socket bound to 0.0.0.0:68 and
        connected to 255.255.255.255:67 after the stack already
        owns an IPv4 address. This is the REBINDING-state path that
        currently fails because 'pick_local_ip4_address' latches the
        owned IP into the socket's stored 'local_address', moving
        the socket out of the special-case lookup's '0.0.0.0'
        bucket.

        Reference: RFC 2131 §4.4.5 (REBIND: broadcast REQUEST after T2).
        """

        client_socket = socket(family=AF_INET4, type=SOCK_DGRAM)
        try:
            client_socket.bind(("0.0.0.0", 68))
            client_socket.connect(("255.255.255.255", 67))

            frame = _build_dhcp4_reply_frame(
                eth_src=_DHCP_SERVER_MAC,
                eth_dst=MacAddress("ff:ff:ff:ff:ff:ff"),
                ip_src=_DHCP_SERVER_IP,
                ip_dst=Ip4Address("255.255.255.255"),
            )

            from net_proto.lib.packet_rx import PacketRx

            self._packet_handler._phrx_ethernet(PacketRx(frame))

            data = bytes(client_socket.recv__mv(timeout=0.5))
        finally:
            client_socket.close()

        self.assertGreater(
            len(data),
            0,
            msg=(
                "DHCPv4 REBINDING-state broadcast reply must reach the "
                "listening socket via UdpMetadata.socket_ids lookup. Got: 0 "
                "bytes — pick_local latched the owned IP into the socket's "
                "stored local_address, so the '0.0.0.0' lookup misses."
            ),
        )
