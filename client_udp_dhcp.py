#!/usr/bin/env python3

############################################################################
#                                                                          #
#  PyTCP - Python TCP/IP stack                                             #
#  Copyright (C) 2020  Sebastian Majewski                                  #
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
# client_udp_dhcp.py - 'user space' DHCP client
#


import random
import threading

import ps_dhcp
import udp_socket


class ClientUdpDhcp:
    """ DHCP client support class """

    def __init__(self, stack_mac_unicast):
        """ Class constructor """

        self.stack_mac_unicast = stack_mac_unicast
        self.socket = udp_socket.UdpSocket(local_ipv4_address="0.0.0.0", local_port=68, remote_ipv4_address="0.0.0.0", remote_port=67)
        threading.Thread(target=self.__client).start()

    def __send(self, dhcp_packet_tx):
        """ Send out DHCP packet """

        self.socket.send_to(
            udp_socket.UdpMessage(
                raw_data=dhcp_packet_tx.get_raw_packet(),
                local_ipv4_address="0.0.0.0",
                local_port=68,
                remote_ipv4_address="255.255.255.255",
                remote_port=67,
            )
        )

    def __client(self):
        """ Obtain IP address from DHCP server """

        dhcp_xid = random.randint(0, 0xFFFFFFFF)

        # Send DHCP Discover
        self.__send(
            dhcp_packet_tx=ps_dhcp.DhcpPacket(
                dhcp_xid=dhcp_xid,
                dhcp_chaddr=self.stack_mac_unicast,
                dhcp_msg_type=ps_dhcp.DHCP_DISCOVER,
                dhcp_param_req_list=b"\x01\x1c\x02\x03\x0f\x06\x77\x0c\x2c\x2f\x1a\x79\x2a",
                dhcp_host_name="PyTCP",
            )
        )

        print("ClientUdpDhcp: Sent out DHCP Discover message")

        # Wait for DHCP Offer
        dhcp_packet_rx = ps_dhcp.DhcpPacket(self.socket.receive_from().raw_data)
        dhcp_srv_id = dhcp_packet_rx.dhcp_srv_id
        dhcp_yiaddr = dhcp_packet_rx.dhcp_yiaddr

        if dhcp_packet_rx.dhcp_msg_type == ps_dhcp.DHCP_OFFER:
            print(f"ClientUdpDhcp: Received DHCP Offer from {dhcp_packet_rx.dhcp_srv_id}")
            print(f"    IP: {dhcp_packet_rx.dhcp_yiaddr}")
            print(f"    Mask: {dhcp_packet_rx.dhcp_subnet_mask}")
            print(f"    Router: {dhcp_packet_rx.dhcp_router}")
            print(f"    DNS: {dhcp_packet_rx.dhcp_dns}")
            print(f"    Domain name: {dhcp_packet_rx.dhcp_domain_name}")

            # Send DHCP Reques
            self.__send(
                dhcp_packet_tx=ps_dhcp.DhcpPacket(
                    dhcp_xid=dhcp_xid,
                    dhcp_chaddr=self.stack_mac_unicast,
                    dhcp_msg_type=ps_dhcp.DHCP_REQUEST,
                    dhcp_srv_id=dhcp_srv_id,
                    dhcp_req_ipv4_addr=dhcp_yiaddr,
                    dhcp_param_req_list=b"\x01\x1c\x02\x03\x0f\x06\x77\x0c\x2c\x2f\x1a\x79\x2a",
                    dhcp_host_name="PyTCP",
                )
            )

            print(f"ClientUdpDhcp: Sent out DHCP Request message to {dhcp_packet_rx.dhcp_srv_id}")

            # Wait for DHCP ACK
            dhcp_packet_rx = ps_dhcp.DhcpPacket(self.socket.receive_from().raw_data)
            if dhcp_packet_rx.dhcp_msg_type == ps_dhcp.DHCP_ACK:
                print(f"ClientUdpDhcp: Received DHCP ACK from {dhcp_packet_rx.dhcp_srv_id}")
                print(f"    IP: {dhcp_packet_rx.dhcp_yiaddr}")
                print(f"    Mask: {dhcp_packet_rx.dhcp_subnet_mask}")
                print(f"    Router: {dhcp_packet_rx.dhcp_router}")
                print(f"    DNS: {dhcp_packet_rx.dhcp_dns}")
                print(f"    Domain name: {dhcp_packet_rx.dhcp_domain_name}")
