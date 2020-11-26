#!/usr/bin/env python3

"""

PyTCP, Python TCP/IP stack, version 0.1 - 2020, Sebastian Majewski
client_udp_dhcp.py - 'user space' DHCP client

Naive implementation - need error and timeout handling, also need a way to return ip data to stack

"""

import threading
import random

import udp_socket
import ps_dhcp


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
