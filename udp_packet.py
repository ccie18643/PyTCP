#!/usr/bin/env python3

"""

PyTCP, Python TCP/IP stack, version 0.1 - 2020, Sebastian Majewski
udp_packet.py - module contains storage class for incoming UDP packet's metadata

"""


class UdpPacket:
    """ Store UDP metadata """

    def __init__(self, local_ip_address, local_port, remote_ip_address, remote_port, raw_data, tracker):
        self.local_ip_address = local_ip_address
        self.local_port = local_port
        self.remote_ip_address = remote_ip_address
        self.remote_port = remote_port
        self.raw_data = raw_data
        self.tracker = tracker

    @property
    def udp_session_id(self):
        """ Session ID """

        return f"UDP/{self.local_ip_address}/{self.local_port}/{self.remote_ip_address}/{self.remote_port}"

    @property
    def socket_id_patterns(self):
        """ Socket ID patterns that match this packet """

        return [
            f"UDP/{self.local_ip_address}/{self.local_port}/{self.remote_ip_address}/{self.remote_port}",
            f"UDP/{self.local_ip_address}/{self.local_port}/0.0.0.0/0",
            f"UDP/0.0.0.0/{self.local_port}/0.0.0.0/{self.remote_port}",
            f"UDP/0.0.0.0/{self.local_port}/0.0.0.0/0",
        ]
