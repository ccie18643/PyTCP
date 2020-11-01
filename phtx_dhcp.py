#!/usr/bin/env python3

"""

PyTCP, Python TCP/IP stack, version 0.1 - 2020, Sebastian Majewski
phtx_dhcp.py - protocol support for outbound DHCP packets

"""

import ps_dhcp


def phtx_dhcp(self, dhcp_message_type, dhcp_xid, dhcp_chaddr, echo_tracker=None):
    """ Handle outbound DHCP packets """

    dhcp_packet_tx = ps_dhcp.DhcpPacket(
        dhcp_xid=dhcp_xid,
        dhcp_chaddr=dhcp_chaddr,
        echo_tracker=echo_tracker,
    )

    self.logger.opt(ansi=True).info(f"<magenta>{dhcp_packet_tx.tracker}</magenta> - {dhcp_packet_tx}")
    self.phtx_udp(ip_src="0.0.0.0", ip_dst="255.255.255.255", udp_sport=68, udp_dport=67, raw_data=dhcp_packet_tx.get_raw_packet())
