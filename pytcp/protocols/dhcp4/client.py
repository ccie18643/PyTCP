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

# pylint: disable = expression-not-assigned
# pylint: disable = too-few-public-methods

"""
Module contains the DHCPv4 client that is used internally by the stack.

pytcp/protocols/dhcp4/client.py

ver 2.7
"""


from __future__ import annotations

import random
from typing import TYPE_CHECKING

from pytcp.lib import socket
from pytcp.lib.ip4_address import Ip4Address, Ip4Host, Ip4Mask
from pytcp.lib.logger import log
from pytcp.protocols.dhcp4.ps import (
    DHCP4_MSG_ACK,
    DHCP4_MSG_DISCOVER,
    DHCP4_MSG_OFFER,
    DHCP4_MSG_REQUEST,
    DHCP4_OP_REQUEST,
    DHCP4_OPT_ROUTER,
    DHCP4_OPT_SUBNET_MASK,
    Dhcp4Packet,
)

if TYPE_CHECKING:
    from pytcp.lib.mac_address import MacAddress


class Dhcp4Client:
    """
    Class supporting Dhc4 client operation.
    """

    def __init__(self, mac_address: MacAddress) -> None:
        """
        Class constructor.
        """
        self._mac_address = mac_address

    def fetch(self) -> Ip4Host | None:
        """
        IPv4 DHCP client.
        """

        client_socket = socket.socket(
            family=socket.AF_INET4, type=socket.SOCK_DGRAM
        )
        client_socket.bind(("0.0.0.0", 68))
        client_socket.connect(("255.255.255.255", 67))

        dhcp_xid = random.randint(0, 0xFFFFFFFF)

        # Send DHCP Discover
        client_socket.send(
            Dhcp4Packet(
                dhcp_op=DHCP4_OP_REQUEST,
                dhcp_xid=dhcp_xid,
                dhcp_ciaddr=Ip4Address("0.0.0.0"),
                dhcp_yiaddr=Ip4Address("0.0.0.0"),
                dhcp_siaddr=Ip4Address("0.0.0.0"),
                dhcp_giaddr=Ip4Address("0.0.0.0"),
                dhcp_chaddr=bytes(self._mac_address),
                dhcp_msg_type=DHCP4_MSG_DISCOVER,
                dhcp_param_req_list=[
                    DHCP4_OPT_SUBNET_MASK,
                    DHCP4_OPT_ROUTER,
                ],
                dhcp_host_name="PyTCP",
            ).raw_packet
        )
        __debug__ and log("dhcp4", "Sent out DHCP Discover message")

        # Wait for DHCP Offer
        try:
            dhcp_packet_rx = Dhcp4Packet(client_socket.recv(timeout=5))
        except socket.ReceiveTimeout:
            __debug__ and log(
                "dhcp4", "Didn't receive DHCP Offer message - timeout"
            )
            client_socket.close()
            return None

        if dhcp_packet_rx.dhcp_msg_type != DHCP4_MSG_OFFER:
            __debug__ and log(
                "dhcp4",
                "Didn't receive DHCP Offer message - message type error",
            )
            client_socket.close()
            return None

        dhcp_srv_id = dhcp_packet_rx.dhcp_srv_id
        dhcp_yiaddr = dhcp_packet_rx.dhcp_yiaddr
        __debug__ and log(
            "dhcp4",
            f"ClientUdpDhcp: Received DHCP Offer from "
            f"{dhcp_packet_rx.dhcp_srv_id}"
            f"IP: {dhcp_packet_rx.dhcp_yiaddr}, "
            f"Mask: {dhcp_packet_rx.dhcp_subnet_mask}, "
            f"Router: {dhcp_packet_rx.dhcp_router}"
            f"DNS: {dhcp_packet_rx.dhcp_dns}, "
            f"Domain: {dhcp_packet_rx.dhcp_domain_name}",
        )

        # Send DHCP Request
        client_socket.send(
            Dhcp4Packet(
                dhcp_op=DHCP4_OP_REQUEST,
                dhcp_xid=dhcp_xid,
                dhcp_ciaddr=Ip4Address("0.0.0.0"),
                dhcp_yiaddr=Ip4Address("0.0.0.0"),
                dhcp_siaddr=Ip4Address("0.0.0.0"),
                dhcp_giaddr=Ip4Address("0.0.0.0"),
                dhcp_chaddr=bytes(self._mac_address),
                dhcp_msg_type=DHCP4_MSG_REQUEST,
                dhcp_srv_id=dhcp_srv_id,
                dhcp_req_ip_addr=dhcp_yiaddr,
                dhcp_param_req_list=[
                    DHCP4_OPT_SUBNET_MASK,
                    DHCP4_OPT_ROUTER,
                ],
                dhcp_host_name="PyTCP",
            ).raw_packet
        )

        __debug__ and log(
            "dhcp4",
            "Sent out DHCP Request message to " f"{dhcp_packet_rx.dhcp_srv_id}",
        )

        # Wait for DHCP Ack
        try:
            dhcp_packet_rx = Dhcp4Packet(client_socket.recv(timeout=5))
        except socket.ReceiveTimeout:
            __debug__ and log(
                "dhcp4", "Didn't receive DHCP ACK message - timeout"
            )
            client_socket.close()
            return None

        if dhcp_packet_rx.dhcp_msg_type != DHCP4_MSG_ACK:
            __debug__ and log(
                "dhcp4",
                "Didn't receive DHCP ACK message - message type error",
            )
            client_socket.close()
            return None

        __debug__ and log(
            "dhcp4",
            f"Received DHCP Offer from {dhcp_packet_rx.dhcp_srv_id}"
            f"IP: {dhcp_packet_rx.dhcp_yiaddr}, "
            f"Mask: {dhcp_packet_rx.dhcp_subnet_mask}, "
            f"Router: {dhcp_packet_rx.dhcp_router}, "
            f"DNS: {dhcp_packet_rx.dhcp_dns}, "
            f"Domain: {dhcp_packet_rx.dhcp_domain_name}",
        )
        client_socket.close()

        assert dhcp_packet_rx.dhcp_subnet_mask is not None

        ip4_host = Ip4Host(
            (
                Ip4Address(dhcp_packet_rx.dhcp_yiaddr),
                Ip4Mask(dhcp_packet_rx.dhcp_subnet_mask),
            )
        )
        if dhcp_packet_rx.dhcp_router is not None:
            ip4_host.gateway = Ip4Address(dhcp_packet_rx.dhcp_router[0])

        return ip4_host
