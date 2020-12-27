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
# fpp.py - module contains Fast Packet Parser support class
#

import loguru

import fpp_arp
import fpp_ether
import fpp_icmp4
import fpp_icmp6
import fpp_ip4
import fpp_ip6
import fpp_tcp
import fpp_udp


class FastPacketParser:
    """ Fast Packet Parser support class """

    def __init__(self, frame, tracker):
        """ Class constructor """

        if __debug__:
            self._logger = loguru.logger.bind(object_name="packet_parser.")
        self._frame = frame
        self.tracker = tracker
        self.packet_parse_failed = False

        # Ethernet packet parsing
        self.ether = fpp_ether.EtherPacket(self._frame)
        if self.ether.packet_parse_failed:
            if __debug__:
                self._logger.critical(f"{self.tracker} - {self.ether.packet_check_failed}")
            self.packet_parse_failed = True
            return
        if __debug__:
            self._logger.debug(f"{self.tracker} - {self.ether}")

        # ARP packet parsing
        if self.ether.type == fpp_ether.ETHER_TYPE_ARP:
            self.arp = fpp_arp.ArpPacket(self._frame, self.ether.dptr)
            if self.arp.packet_parse_failed:
                if __debug__:
                    self._logger.critical(f"{self.tracker} - {self.arp.sanity_check_failed}")
                self.packet_parse_failed = True
                return
            if __debug__:
                self._logger.debug(f"{self.tracker} - {self.arp}")
            return

        # IPv4 packet parsing
        if self.ether.type == fpp_ether.ETHER_TYPE_IP4:
            self.ip = self.ip4 = fpp_ip4.Ip4Packet(self._frame, self.ether.dptr)
            if self.ip4.packet_parse_failed:
                if __debug__:
                    self._logger.critical(f"{self.tracker} - {self.ip4.packet_parse_failed}")
                self.packet_parse_failed = True
                return
            if __debug__:
                self._logger.debug(f"{self.tracker} - {self.ip4}")

            # ICMPv4 packet parsing
            if self.ip4.proto == fpp_ip4.IP4_PROTO_ICMP4:
                self.icmp4 = fpp_icmp4.Icmp4Packet(self._frame, self.ip4.dptr, self.ip4.dlen)
                if self.icmp4.packet_parse_failed:
                    if __debug__:
                        self._logger.critical(f"{self.tracker} - {self.icmp4.packet_parse_failed}")
                    self.packet_parse_failed = True
                    return
                if __debug__:
                    self._logger.debug(f"{self.tracker} - {self.icmp4}")
                return

            # UDP packet parsing
            if self.ip4.proto == fpp_ip4.IP4_PROTO_UDP:
                self.udp = fpp_udp.UdpPacket(self._frame, self.ip4.dptr, self.ip4.dlen, self.ip4.pseudo_header)
                if self.udp.packet_parse_failed:
                    if __debug__:
                        self._logger.critical(f"{self.tracker} - {self.udp.packet_check_failed}")
                    self.packet_parse_failed = True
                    return
                if __debug__:
                    self._logger.debug(f"{self.tracker} - {self.udp}")
                return

            # TCP packet parsing
            if self.ip4.proto == fpp_ip4.IP4_PROTO_TCP:
                self.tcp = fpp_tcp.TcpPacket(self._frame, self.ip4.dptr, self.ip4.dlen, self.ip4.pseudo_header)
                if self.tcp.packet_parse_failed:
                    if __debug__:
                        self._logger.critical(f"{self.tracker} - {self.tcp.packet_parse_failed}")
                    self.packet_parse_failed = True
                    return
                if __debug__:
                    self._logger.debug(f"{self.tracker} - {self.tcp}")
                return

        # IPv6 packet parsing
        if self.ether.type == fpp_ether.ETHER_TYPE_IP6:
            self.ip = self.ip6 = fpp_ip6.Ip6Packet(self._frame, self.ether.dptr)
            if self.ip6.packet_parse_failed:
                if __debug__:
                    self._logger.critical(f"{self.tracker} - {self.ip6.packet_parse_failed}")
                self.packet_parse_failed = True
                return
            if __debug__:
                self._logger.debug(f"{self.tracker} - {self.ip6}")

            # ICMPv6 packet parsing
            if self.ip6.next == fpp_ip6.IP6_NEXT_HEADER_ICMP6:
                self.icmp6 = fpp_icmp6.Icmp6Packet(self._frame, self.ip6.dptr, self.ip6.dlen, self.ip6.pseudo_header, self.ip6.src, self.ip6.dst, self.ip6.hop)
                if self.icmp6.packet_parse_failed:
                    if __debug__:
                        self._logger.critical(f"{self.tracker} - {self.icmp6.packet_parse_failed}")
                    self.packet_parse_failed = True
                    return
                if __debug__:
                    self._logger.debug(f"{self.tracker} - {self.icmp6}")
                return

            # UDP packet parsing
            if self.ip6.next == fpp_ip6.IP6_NEXT_HEADER_UDP:
                self.udp = fpp_udp.UdpPacket(self._frame, self.ip6.dptr, self.ip6.dlen, self.ip6.pseudo_header)
                if self.udp.packet_parse_failed:
                    if __debug__:
                        self._logger.critical(f"{self.tracker} - {self.udp.packet_parse_failed}")
                    self.packet_parse_failed = True
                    return
                if __debug__:
                    self._logger.debug(f"{self.tracker} - {self.udp}")
                return

            # TCP packet parsing
            if self.ip6.next == fpp_ip6.IP6_NEXT_HEADER_TCP:
                self.tcp = fpp_tcp.TcpPacket(self._frame, self.ip6.dptr, self.ip6.dlen, self.ip6.pseudo_header)
                if self.tcp.packet_parse_failed:
                    if __debug__:
                        self._logger.critical(f"{self.tracker} - {self.tcp.packet_parse_failed}")
                    self.packet_parse_failed = True
                    return
                if __debug__:
                    self._logger.debug(f"{self.tracker} - {self.tcp}")
                return
