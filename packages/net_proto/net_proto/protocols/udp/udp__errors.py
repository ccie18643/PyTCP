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
This module contains the UDP protocol error classes.

net_proto/protocols/udp/udp__errors.py

ver 3.0.10
"""

from typing import override

from net_proto.lib.errors import PacketIntegrityError, PacketSanityError


class UdpIntegrityError(PacketIntegrityError):
    """
    Exception raised when UDP packet integrity check fails.
    """

    @override
    def __init__(self, message: str, /) -> None:
        super().__init__("[UDP] " + message)


class UdpZeroCksumIp6Error(UdpIntegrityError):
    """
    Exception raised when an inbound IPv6 UDP datagram carries
    cksum=0 on a port not configured for RFC 6935 zero-checksum
    mode. Subclassed from 'UdpIntegrityError' so existing
    'PacketValidationError' catches continue to drop the packet
    correctly; the dedicated subclass lets the RX packet handler
    bump 'udp__ip6_zero_cksum__drop' separately from the generic
    'udp__failed_parse__drop' counter for operational
    observability.

    RFC 8200 §8.1 (and RFC 2460 §8.1 before it) require IPv6
    receivers to discard zero-checksum UDP packets by default.
    RFC 6935 §5 preserves the default-discard rule and adds a
    per-port opt-in for tunnel encapsulations.
    """


class UdpSanityError(PacketSanityError):
    """
    Exception raised when UDP packet sanity check fails.
    """

    @override
    def __init__(self, message: str, /) -> None:
        super().__init__("[UDP] " + message)
