#!/usr/bin/env python3

############################################################################
#                                                                          #
#  PyTCP - Python TCP/IP stack                                             #
#  Copyright (C) 2020-2021  Sebastian Majewski                             #
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


#
# dhcp4/client.py - DHCPv4 client function for packet handler
#


import random

import dhcp4.ps
import udp.metadata
import udp.socket
from misc.ipv4_address import IPv4Address, IPv4Interface


def _dhcp4_client(self):
    """IPv4 DHCP client"""

    def _send_dhcp_packet(dhcp_packet_tx):
        socket.send_to(
            udp.metadata.UdpMetadata(
                local_ip_address=IPv4Address("0.0.0.0"),
                local_port=68,
                remote_ip_address=IPv4Address("255.255.255.255"),
                remote_port=67,
                data=dhcp_packet_tx.get_raw_packet(),
            )
        )

    socket = udp.socket.UdpSocket()
    socket.bind(local_ip_address="0.0.0.0", local_port=68)
    dhcp_xid = random.randint(0, 0xFFFFFFFF)

    # Send DHCP Discover
    _send_dhcp_packet(
        dhcp_packet_tx=dhcp4.ps.Packet(
            dhcp_xid=dhcp_xid,
            dhcp_chaddr=self.mac_unicast,
            dhcp_msg_type=dhcp4.ps.MSG_DISCOVER,
            dhcp_param_req_list=b"\x01\x1c\x02\x03\x0f\x06\x77\x0c\x2c\x2f\x1a\x79\x2a",
            dhcp_host_name="PyTCP",
        )
    )
    if __debug__:
        self._logger.debug("Sent out DHCP Discover message")

    # Wait for DHCP Offer
    if not (packet := socket.receive_from(timeout=5)):
        if __debug__:
            self._logger.warning("Timeout waiting for DHCP Offer message")
        socket.close()
        return None, None

    dhcp_packet_rx = dhcp4.ps.Packet(packet.data)
    if dhcp_packet_rx.dhcp_msg_type != dhcp4.ps.MSG_OFFER:
        if __debug__:
            self._logger.warning("Didn't receive DHCP Offer message")
        socket.close()
        return None, None

    dhcp_srv_id = dhcp_packet_rx.dhcp_srv_id
    dhcp_yiaddr = dhcp_packet_rx.dhcp_yiaddr
    if __debug__:
        self._logger.debug(
            f"ClientUdpDhcp: Received DHCP Offer from {dhcp_packet_rx.dhcp_srv_id}"
            + f"IP: {dhcp_packet_rx.dhcp_yiaddr}, Mask: {dhcp_packet_rx.dhcp_subnet_mask}, Router: {dhcp_packet_rx.dhcp_router}"
            + f"DNS: {dhcp_packet_rx.dhcp_dns}, Domain: {dhcp_packet_rx.dhcp_domain_name}"
        )

    # Send DHCP Request
    _send_dhcp_packet(
        dhcp_packet_tx=dhcp4.ps.Packet(
            dhcp_xid=dhcp_xid,
            dhcp_chaddr=self.mac_unicast,
            dhcp_msg_type=dhcp4.ps.MSG_REQUEST,
            dhcp_srv_id=dhcp_srv_id,
            dhcp_req_ip4_addr=dhcp_yiaddr,
            dhcp_param_req_list=b"\x01\x1c\x02\x03\x0f\x06\x77\x0c\x2c\x2f\x1a\x79\x2a",
            dhcp_host_name="PyTCP",
        )
    )

    if __debug__:
        self._logger.debug(f"Sent out DHCP Request message to {dhcp_packet_rx.dhcp_srv_id}")

    # Wait for DHCP Ack
    if not (packet := socket.receive_from(timeout=5)):
        if __debug__:
            self._logger.warning("Timeout waiting for DHCP Ack message")
        return None, None

    dhcp_packet_rx = dhcp4.ps.Packet(packet.data)
    if dhcp_packet_rx.dhcp_msg_type != dhcp4.ps.MSG_ACK:
        if __debug__:
            self._logger.warning("Didn't receive DHCP Offer message")
        socket.close()
        return None, None

    if __debug__:
        self._logger.debug(
            f"Received DHCP Offer from {dhcp_packet_rx.dhcp_srv_id}"
            + f"IP: {dhcp_packet_rx.dhcp_yiaddr}, Mask: {dhcp_packet_rx.dhcp_subnet_mask}, Router: {dhcp_packet_rx.dhcp_router}"
            + f"DNS: {dhcp_packet_rx.dhcp_dns}, Domain: {dhcp_packet_rx.dhcp_domain_name}"
        )
    socket.close()
    return (
        IPv4Interface(str(dhcp_packet_rx.dhcp_yiaddr) + "/" + str(IPv4Address._make_netmask(str(dhcp_packet_rx.dhcp_subnet_mask))[1])),
        dhcp_packet_rx.dhcp_router[0],
    )
