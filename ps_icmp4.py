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

##############################################################################################
#                                                                                            #
#  This program is a work in progress and it changes on daily basis due to new features      #
#  being implemented, changes being made to already implemented features, bug fixes, etc.    #
#  Therefore if the current version is not working as expected try to clone it again the     #
#  next day or shoot me an email describing the problem. Any input is appreciated. Also      #
#  keep in mind that some features may be implemented only partially (as needed for stack    #
#  operation) or they may be implemented in sub-optimal or not 100% RFC compliant way (due   #
#  to lack of time) or last but not least they may contain bug(s) that i didn't notice yet.  #
#                                                                                            #
##############################################################################################


#
# ps_icmp4.py - protocol support libary for ICMPv4
#


import struct

import loguru

import config
from ip_helper import inet_cksum
from tracker import Tracker

# Echo reply message (0/0)

# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |     Type      |     Code      |           Checksum            |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |              Id               |              Seq              |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# ~                             Data                              ~
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


# Destination Unreachable message (3/[0-3, 5-15])

# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |     Type      |     Code      |           Checksum            |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |              Id               |              Seq              |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                           Reserved                            |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# ~                             Data                              ~
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


# Destination Unreachable message (3/4)

# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |     Type      |     Code      |           Checksum            |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |              Id               |              Seq              |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |           Reserved            |          Link MTU / 0         |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# ~                             Data                              ~
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


# Echo Request message (8/0)

# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |     Type      |     Code      |           Checksum            |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |              Id               |              Seq              |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# ~                             Data                              ~
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


ICMP4_ECHOREPLY = 0
ICMP4_UNREACHABLE = 3
ICMP4_UNREACHABLE__NET = 0
ICMP4_UNREACHABLE__HOST = 1
ICMP4_UNREACHABLE__PROTOCOL = 2
ICMP4_UNREACHABLE__PORT = 3
ICMP4_UNREACHABLE__FAGMENTATION = 4
ICMP4_UNREACHABLE__SOURCE_ROUTE_FAILED = 5
ICMP4_ECHOREQUEST = 8


class Icmp4Packet:
    """ ICMPv4 packet support class """

    protocol = "ICMPv4"

    def __init__(
        self,
        parent_packet=None,
        icmp4_type=None,
        icmp4_code=0,
        icmp4_ec_id=None,
        icmp4_ec_seq=None,
        icmp4_ec_raw_data=b"",
        icmp4_un_raw_data=b"",
        echo_tracker=None,
    ):
        """ Class constructor """

        self.logger = loguru.logger.bind(object_name="ps_icmpv4.")
        self.sanity_check_failed = False

        # Packet parsing
        if parent_packet:
            self.tracker = parent_packet.tracker

            raw_packet = parent_packet.raw_data

            if not self.__pre_parse_sanity_check(raw_packet):
                self.sanity_check_failed = True
                return

            self.icmp4_type = raw_packet[0]
            self.icmp4_code = raw_packet[1]
            self.icmp4_cksum = struct.unpack("!H", raw_packet[2:4])[0]

            if self.icmp4_type == ICMP4_ECHOREPLY:
                self.icmp4_ec_id = struct.unpack("!H", raw_packet[4:6])[0]
                self.icmp4_ec_seq = struct.unpack("!H", raw_packet[6:8])[0]
                self.icmp4_ec_raw_data = raw_packet[8:]

            elif self.icmp4_type == ICMP4_UNREACHABLE:
                self.icmp4_un_reserved = struct.unpack("!L", raw_packet[4:6])[0]
                self.icmp4_un_raw_data = raw_packet[8:]

            elif self.icmp4_type == ICMP4_ECHOREQUEST:
                self.icmp4_ec_id = struct.unpack("!H", raw_packet[4:6])[0]
                self.icmp4_ec_seq = struct.unpack("!H", raw_packet[6:8])[0]
                self.icmp4_ec_raw_data = raw_packet[8:]

            else:
                self.unknown_message = raw_packet[4:]

            if not self.__post_parse_sanity_check():
                self.sanity_check_failed = True

        # Packet building
        else:
            self.tracker = Tracker("TX", echo_tracker)

            self.icmp4_type = icmp4_type
            self.icmp4_code = icmp4_code
            self.icmp4_cksum = 0

            if self.icmp4_type == ICMP4_ECHOREPLY:
                self.icmp4_ec_id = icmp4_ec_id
                self.icmp4_ec_seq = icmp4_ec_seq
                self.icmp4_ec_raw_data = icmp4_ec_raw_data

            elif self.icmp4_type == ICMP4_UNREACHABLE and self.icmp4_code == ICMP4_UNREACHABLE__PORT:
                self.icmp4_un_reserved = 0
                self.icmp4_un_raw_data = icmp4_un_raw_data[:520]

            elif self.icmp4_type == ICMP4_ECHOREQUEST:
                self.icmp4_ec_id = icmp4_ec_id
                self.icmp4_ec_seq = icmp4_ec_seq
                self.icmp4_ec_raw_data = icmp4_ec_raw_data

    def __str__(self):
        """ Short packet log string """

        log = f"ICMPv4 type {self.icmp4_type}, code {self.icmp4_code}"

        if self.icmp4_type == ICMP4_ECHOREPLY:
            log += f", id {self.icmp4_ec_id}, seq {self.icmp4_ec_seq}"

        elif self.icmp4_type == ICMP4_UNREACHABLE and self.icmp4_code == ICMP4_UNREACHABLE__PORT:
            pass

        elif self.icmp4_type == ICMP4_ECHOREQUEST:
            log += f", id {self.icmp4_ec_id}, seq {self.icmp4_ec_seq}"

        return log

    def __len__(self):
        """ Length of the packet """

        return len(self.raw_packet)

    @property
    def raw_packet(self):
        """ Get packet in raw format """

        if self.icmp4_type == ICMP4_ECHOREPLY:
            raw_packet = (
                struct.pack("! BBH HH", self.icmp4_type, self.icmp4_code, self.icmp4_cksum, self.icmp4_ec_id, self.icmp4_ec_seq) + self.icmp4_ec_raw_data
            )

        elif self.icmp4_type == ICMP4_UNREACHABLE and self.icmp4_code == ICMP4_UNREACHABLE__PORT:
            raw_packet = struct.pack("! BBH L", self.icmp4_type, self.icmp4_code, self.icmp4_cksum, self.icmp4_un_reserved) + self.icmp4_un_raw_data

        elif self.icmp4_type == ICMP4_ECHOREQUEST:
            raw_packet = (
                struct.pack("! BBH HH", self.icmp4_type, self.icmp4_code, self.icmp4_cksum, self.icmp4_ec_id, self.icmp4_ec_seq) + self.icmp4_ec_raw_data
            )

        else:
            raw_packet = struct.pack("! BBH", self.icmp4_type, self.icmp4_code, self.icmp4_cksum) + self.unknown_message

        return raw_packet

    def get_raw_packet(self):
        """ Get packet in raw format ready to be processed by lower level protocol """

        self.icmp4_cksum = inet_cksum(self.raw_packet)

        return self.raw_packet

    def validate_cksum(self):
        """ Validate packet checksum """

        return not bool(inet_cksum(self.raw_packet))

    def __pre_parse_sanity_check(self, raw_packet):
        """ Preliminary sanity check to be run on raw ICMPv4 packet prior to packet parsing """

        if not config.pre_parse_sanity_check:
            return True

        if inet_cksum(raw_packet):
            self.logger.critical(f"{self.tracker} - ICMPv4 sanity check fail - wrong packet checksum")
            return False

        if len(raw_packet) < 4:
            self.logger.critical(f"{self.tracker} - ICMPv4 sanity check fail - wrong packet length (I)")
            return False

        if raw_packet[0] == ICMP4_ECHOREPLY:
            if len(raw_packet) < 8:
                self.logger.critical(f"{self.tracker} - ICMPv6 sanity check fail - wrong packet length (II)")
                return False

        elif raw_packet[0] == ICMP4_UNREACHABLE:
            if len(raw_packet) < 12:
                self.logger.critical(f"{self.tracker} - ICMPv6 sanity check fail - wrong packet length (II)")
                return False

        elif raw_packet[0] == ICMP4_ECHOREQUEST:
            if len(raw_packet) < 8:
                self.logger.critical(f"{self.tracker} - ICMPv6 sanity check fail - wrong packet length (II)")
                return False

        return True

    def __post_parse_sanity_check(self):
        """ Sanity check to be run on parsed ICMPv6 packet """

        if not config.post_parse_sanity_check:
            return True

        if self.icmp4_type == ICMP4_ECHOREPLY:
            # imcp4_code SHOULD be set to 0 (RFC 792)
            if not self.icmp4_code == 0:
                self.logger.critical(f"{self.tracker} - ICMPv4 sanity check warning - imcp4_code SHOULD be set to 0 (RFC 792)")

        if self.icmp4_type == ICMP4_UNREACHABLE:
            # imcp4_code MUST be set to [0-15] (RFC 792)
            if self.icmp4_code not in {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}:
                self.logger.critical(f"{self.tracker} - ICMPv4 sanity check fail - imcp4_code MUST be set to [0-15] (RFC 792)")
                return False

        elif self.icmp4_type == ICMP4_ECHOREQUEST:
            # imcp4_code SHOULD be set to 0 (RFC 792)
            if not self.icmp4_code == 0:
                self.logger.critical(f"{self.tracker} - ICMPv4 sanity check warning - imcp4_code SHOULD be set to 0 (RFC 792)")

        return True
