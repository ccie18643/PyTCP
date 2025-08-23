#!/usr/bin/env python3

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
This module contains the IPv6 Frag packet assembler.

pytcp/protocols/ip6_frag/ip6_frag__assembler.py

ver 3.0.3
"""


from pytcp.lib.proto_assembler import ProtoAssembler
from pytcp.lib.tracker import Tracker
from pytcp.protocols.enums import IpProto
from pytcp.protocols.ip6_frag.ip6_frag__base import Ip6Frag
from pytcp.protocols.ip6_frag.ip6_frag__header import Ip6FragHeader


class Ip6FragAssembler(Ip6Frag[bytes], ProtoAssembler):
    """
    The IPv6 Frag packet assembler.
    """

    _payload: bytes

    def __init__(
        self,
        *,
        ip6_frag__next: IpProto = IpProto.RAW,
        ip6_frag__offset: int = 0,
        ip6_frag__flag_mf: bool = False,
        ip6_frag__id: int = 0,
        ip6_frag__payload: bytes = bytes(),
    ) -> None:
        """
        Initialize the IPv6 Frag packet assembler.
        """

        self._tracker: Tracker = Tracker(prefix="TX")

        self._payload = ip6_frag__payload

        self._header = Ip6FragHeader(
            next=ip6_frag__next,
            offset=ip6_frag__offset,
            flag_mf=ip6_frag__flag_mf,
            id=ip6_frag__id,
        )
