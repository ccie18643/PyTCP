################################################################################
##                                                                            ##
##   PyTCP - Python TCP/IP stack                                              ##
##   Copyright (C) 2020-present Sebastian Majewski                            ##
##                                                                            ##
##   This program is free software: you can redistribute it and/or modify     ##
##   it under the terms of the GNU General Public License as published by     ##
##   the Free Software Foundation, either version 3 of the License, or        ##
##   (at your option) any later version.                                      ##
##                                                                            ##
##   This program is distributed in the hope that it will be useful,          ##
##   but WITHOUT ANY WARRANTY; without even the implied warranty of           ##
##   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the             ##
##   GNU General Public License for more details.                             ##
##                                                                            ##
##   You should have received a copy of the GNU General Public License        ##
##   along with this program. If not, see <https://www.gnu.org/licenses/>.    ##
##                                                                            ##
##   Author's email: ccie18643@gmail.com                                      ##
##   Github repository: https://github.com/ccie18643/PyTCP                    ##
##                                                                            ##
################################################################################


"""
This module contains the DHCPv6 protocol enum classes.

net_proto/protocols/dhcp6/dhcp6__enums.py

ver 3.0.10
"""

from typing import override

from net_proto.lib.proto_enum import ProtoEnumByte, ProtoEnumWord


class Dhcp6MessageType(ProtoEnumByte):
    """
    The DHCPv6 message header 'msg-type' field values.
    """

    SOLICIT = 1  # RFC 8415 §7.3 / §16.2: Client locates servers.
    ADVERTISE = 2  # RFC 8415 §7.3 / §16.3: Server announces availability.
    REQUEST = 3  # RFC 8415 §7.3 / §16.4: Client requests configuration.
    CONFIRM = 4  # RFC 8415 §7.3 / §16.5: Client confirms addresses on-link.
    RENEW = 5  # RFC 8415 §7.3 / §16.6: Client renews a lease (to selected server).
    REBIND = 6  # RFC 8415 §7.3 / §16.7: Client rebinds a lease (to any server).
    REPLY = 7  # RFC 8415 §7.3 / §16.8: Server replies with configuration.
    RELEASE = 8  # RFC 8415 §7.3 / §16.9: Client releases assigned addresses.
    DECLINE = 9  # RFC 8415 §7.3 / §16.10: Client declines addresses (in use).
    RECONFIGURE = 10  # RFC 8415 §7.3 / §16.11: Server prompts client to reconfigure.
    INFORMATION_REQUEST = 11  # RFC 8415 §7.3 / §16.12: Client requests other config only.
    RELAY_FORW = 12  # RFC 8415 §7.3 / §9.1: Relay forwards a message to a server.
    RELAY_REPL = 13  # RFC 8415 §7.3 / §9.2: Relay returns a server reply to a relay/client.

    @override
    def __str__(self) -> str:
        """
        Get the value as a string.
        """

        match self:
            case Dhcp6MessageType.SOLICIT:
                name = "Solicit"
            case Dhcp6MessageType.ADVERTISE:
                name = "Advertise"
            case Dhcp6MessageType.REQUEST:
                name = "Request"
            case Dhcp6MessageType.CONFIRM:
                name = "Confirm"
            case Dhcp6MessageType.RENEW:
                name = "Renew"
            case Dhcp6MessageType.REBIND:
                name = "Rebind"
            case Dhcp6MessageType.REPLY:
                name = "Reply"
            case Dhcp6MessageType.RELEASE:
                name = "Release"
            case Dhcp6MessageType.DECLINE:
                name = "Decline"
            case Dhcp6MessageType.RECONFIGURE:
                name = "Reconfigure"
            case Dhcp6MessageType.INFORMATION_REQUEST:
                name = "Information-Request"
            case Dhcp6MessageType.RELAY_FORW:
                name = "Relay-Forward"
            case Dhcp6MessageType.RELAY_REPL:
                name = "Relay-Reply"
            case _:
                name = f"{self.value}"

        return name


class Dhcp6StatusCode(ProtoEnumWord):
    """
    The DHCPv6 Status Code option 'status-code' field values.
    """

    SUCCESS = 0  # RFC 8415 §21.13: Success.
    UNSPEC_FAIL = 1  # RFC 8415 §21.13: Failure, reason unspecified.
    NO_ADDRS_AVAIL = 2  # RFC 8415 §21.13: No addresses available for the IA(s).
    NO_BINDING = 3  # RFC 8415 §21.13: Client record (binding) unavailable.
    NOT_ON_LINK = 4  # RFC 8415 §21.13: Prefix not appropriate for the link.
    USE_MULTICAST = 5  # RFC 8415 §21.13: Client must use the All_DHCP multicast address.
    NO_PREFIX_AVAIL = 6  # RFC 8415 §21.13: No prefix available for the IA_PD(s).

    @override
    def __str__(self) -> str:
        """
        Get the value as a string.
        """

        match self:
            case Dhcp6StatusCode.SUCCESS:
                name = "Success"
            case Dhcp6StatusCode.UNSPEC_FAIL:
                name = "UnspecFail"
            case Dhcp6StatusCode.NO_ADDRS_AVAIL:
                name = "NoAddrsAvail"
            case Dhcp6StatusCode.NO_BINDING:
                name = "NoBinding"
            case Dhcp6StatusCode.NOT_ON_LINK:
                name = "NotOnLink"
            case Dhcp6StatusCode.USE_MULTICAST:
                name = "UseMulticast"
            case Dhcp6StatusCode.NO_PREFIX_AVAIL:
                name = "NoPrefixAvail"
            case _:
                name = f"{self.value}"

        return name
