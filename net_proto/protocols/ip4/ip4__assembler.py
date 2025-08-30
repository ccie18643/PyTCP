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
This module contain the IPv4 protocol assembler classes.

net_proto/protocols/ip4/ip4__assembler.py

ver 3.0.4
"""


from net_addr import Ip4Address
from net_proto.lib.enums import IpProto
from net_proto.lib.int_checks import is_4_byte_alligned
from net_proto.lib.proto_assembler import ProtoAssembler
from net_proto.lib.tracker import Tracker
from net_proto.protocols.ip4.ip4__base import Ip4, Ip4Payload
from net_proto.protocols.ip4.ip4__defaults import IP4__DEFAULT_TTL
from net_proto.protocols.ip4.ip4__header import IP4__HEADER__LEN, Ip4Header
from net_proto.protocols.ip4.options.ip4_option__eol import Ip4OptionEol
from net_proto.protocols.ip4.options.ip4_options import (
    IP4__OPTIONS__MAX_LEN,
    Ip4Options,
)
from net_proto.protocols.raw.raw__assembler import RawAssembler


class Ip4Assembler(Ip4[Ip4Payload], ProtoAssembler):
    """
    The IPv4 packet assembler.
    """

    _payload: Ip4Payload

    def __init__(
        self,
        *,
        ip4__src: Ip4Address = Ip4Address(),
        ip4__dst: Ip4Address = Ip4Address(),
        ip4__ttl: int = IP4__DEFAULT_TTL,
        ip4__dscp: int = 0,
        ip4__ecn: int = 0,
        ip4__id: int = 0,
        ip4__flag_df: bool = False,
        ip4__options: Ip4Options = Ip4Options(),
        ip4__payload: Ip4Payload = RawAssembler(),
    ) -> None:
        """
        Initialize the IPv4 packet assembler.
        """

        assert (
            len(ip4__options) <= IP4__OPTIONS__MAX_LEN
        ), f"The IPv4 options length must be less than or equal to {IP4__OPTIONS__MAX_LEN}."

        assert is_4_byte_alligned(
            len(ip4__options)
        ), "The IPv4 options length must be 4-byte aligned."

        assert (
            Ip4OptionEol() not in ip4__options
            or ip4__options[-1] == Ip4OptionEol()
        ), "The IPv4 EOL option must be the last option."

        self._tracker = ip4__payload.tracker

        self._payload = ip4__payload

        self._options = ip4__options

        self._header = Ip4Header(
            dscp=ip4__dscp,
            hlen=IP4__HEADER__LEN + len(self._options),
            ecn=ip4__ecn,
            plen=IP4__HEADER__LEN + len(self._options) + len(self._payload),
            id=ip4__id,
            flag_df=ip4__flag_df,
            flag_mf=False,
            offset=0,
            ttl=ip4__ttl,
            proto=IpProto.from_proto(ip4__payload),
            cksum=0,
            src=ip4__src,
            dst=ip4__dst,
        )

    @property
    def payload(self) -> Ip4Payload:
        """
        Get the IPv4 packet 'payload' attribute.
        """

        return self._payload


class Ip4FragAssembler(Ip4[bytes], ProtoAssembler):
    """
    The IPv4 (Frag) packet assembler.
    """

    _payload: bytes

    def __init__(
        self,
        *,
        ip4_frag__src: Ip4Address = Ip4Address(),
        ip4_frag__dst: Ip4Address = Ip4Address(),
        ip4_frag__ttl: int = IP4__DEFAULT_TTL,
        ip4_frag__dscp: int = 0,
        ip4_frag__ecn: int = 0,
        ip4_frag__id: int = 0,
        ip4_frag__flag_mf: bool = False,
        ip4_frag__offset: int = 0,
        ip4_frag__options: Ip4Options = Ip4Options(),
        ip4_frag__proto: IpProto = IpProto.RAW,
        ip4_frag__payload: bytes = bytes(),
    ):
        """
        Initialize the IPv4 (Frag) packet assembler.
        """

        assert (
            len(ip4_frag__options) <= IP4__OPTIONS__MAX_LEN
        ), f"The IPv4 options length must be less than or equal to {IP4__OPTIONS__MAX_LEN}."

        assert is_4_byte_alligned(
            len(ip4_frag__options)
        ), "The IPv4 options length must be 4-byte aligned."

        assert (
            Ip4OptionEol() not in ip4_frag__options
            or ip4_frag__options[-1] == Ip4OptionEol()
        ), "The IPv4 EOL option must be the last option."

        self._tracker = Tracker(prefix="TX")

        self._payload = ip4_frag__payload

        self._options = ip4_frag__options

        self._header = Ip4Header(
            hlen=IP4__HEADER__LEN + len(self._options),
            dscp=ip4_frag__dscp,
            ecn=ip4_frag__ecn,
            plen=IP4__HEADER__LEN + len(self._options) + len(self._payload),
            id=ip4_frag__id,
            flag_df=False,
            flag_mf=ip4_frag__flag_mf,
            offset=ip4_frag__offset,
            ttl=ip4_frag__ttl,
            proto=ip4_frag__proto,
            cksum=0,
            src=ip4_frag__src,
            dst=ip4_frag__dst,
        )

    @property
    def payload(self) -> bytes:
        """
        Get the IPv4 (Frag) packet 'payload' attribute.
        """

        return self._payload
