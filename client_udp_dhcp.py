#!/usr/bin/env python3

"""

PyTCP, Python TCP/IP stack, version 0.1 - 2020, Sebastian Majewski
client_udp_dhcp.py - 'user space' DHCP client

"""

import threading

import udp_socket
import ps_dhcp

class ClientUdpDhcp:
    """ DHCP client support class """

    def __init__(self, stack_mac_address):
        """ Class constructor """

        self.socket = udp_socket.UdpSocket(local_ip_address="0.0.0.0", local_port=68, remote_ip_address="255.255.255.255", remote_port=67)

        threading.Thread(target=self.__client).start()

    def __client(self):
        """ Obtan IP address from DHCP server """
   
        dhcp_xid = random.randint(0, 0xffffffff)

        dhcp_packet_tx = ps_dhcp.DhcpPacket(
            dhcp_xid=dhcp_xid,
            dhcp_chaddr=stack_mac_address,
        )

        self.socket.send(dhcp_packet_tx.get_raw_packet())
        print("ClientUdpDhcp: sent out message")

