#!/usr/bin/env python3

"""

PyTCP, Python TCP/IP stack simulation version 0.1 - 2020, Sebastian Majewski
eth_header.py - contains class supporting Ethernet header parsing and creation

"""

import socket
import struct
import array
import binascii


"""
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |         Hardware Type         |         Protocol Type         |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |  Hard Length  |  Proto Length |           Operation           |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               >
   +        Sender Mac Address     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   >                               |       Sender IP Address       >
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   >                               |                               >
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+       Target MAC Address      |
   >                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                       Target IP Address                       |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
"""


class ArpHeader:
    """ Arp header support class """

    def __init__(self, raw_header=None):
        """ Read raw header data """

        if raw_header:
            self.hardware_type = struct.unpack("!H", raw_header[0:2])[0]
            self.protocol_type = struct.unpack("!H", raw_header[2:4])[0]
            self.hardware_length = raw_header[4]
            self.protocol_length = raw_header[5]
            self.operation = struct.unpack("!H", raw_header[6:8])[0]
            self.sender_hardware_address =  ":".join([f"{_:0>2x}" for _ in raw_header[8:14]])
            self.sender_protocol_address =  socket.inet_ntoa(struct.unpack("!4s", raw_header[14:18])[0])
            self.target_hardware_address =  ":".join([f"{_:0>2x}" for _ in raw_header[18:24]])
            self.target_protocol_address =  socket.inet_ntoa(struct.unpack("!4s", raw_header[24:28])[0])

        else:
            self.hardware_type = 1
            self.protocol_type = 0x0800
            self.hardware_length = 6
            self.prorocol_length = 4
            self.operation = None
            self.sender_hardware_address = "00:00:00:00:00:00"
            self.sender_protocol_address = "0.0.0.0"
            self.target_hardware_address = "00:00:00:00:00:00"
            self.target_protocol_address = "0.0.0.0"

    def get_raw_header(self):
        """ Get raw raw header data """

        return struct.pack(
            "!HH BBH 6s 4s 6s 4s",
            self.hardware_type,
            self.protocol_type,
            self.hardware_length,
            self.protocol_length,
            self.operation,
            bytes.fromhex(self.sender_hardware_address.replace(":", "")),
            socket.inet_aton(self.sender_protocol_address),
            bytes.fromhex(self.target_hardware_address.replace(":", "")),
            socket.inet_aton(self.target_protocol_address),
        )


    def __str__(self):
        """ Easy to read string reresentation """

        return (
            "--------------------------------------------------------------------------------\n"
            + f"ARP      SENDER MAC {self.sender_hardware_address} IP {self.sender_protocol_address}  "
            + f"OPER {'Request' if self.operation == 1 else 'Reply'}\n"
            + f"         TARGET MAC {self.target_hardware_address} IP {self.target_protocol_address}"
        )

