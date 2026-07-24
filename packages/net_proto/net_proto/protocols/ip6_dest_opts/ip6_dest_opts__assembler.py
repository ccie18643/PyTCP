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
This module contains the IPv6 Destination Options packet assembler.

net_proto/protocols/ip6_dest_opts/ip6_dest_opts__assembler.py

ver 3.0.9
"""

from typing import override

from net_addr import Buffer
from net_proto.lib.enums import IpProto
from net_proto.lib.proto_assembler import ProtoAssembler
from net_proto.lib.tracker import Tracker
from net_proto.protocols.ip6_dest_opts.ip6_dest_opts__base import Ip6DestOpts
from net_proto.protocols.ip6_dest_opts.ip6_dest_opts__header import (
    IP6_DEST_OPTS__HEADER__LEN,
    Ip6DestOptsHeader,
)
from net_proto.protocols.ip6_dest_opts.options.ip6_dest_opts__options import (
    IP6_DEST_OPTS__OPTIONS__MAX_LEN,
    Ip6DestOptsOptions,
)


class Ip6DestOptsAssembler(Ip6DestOpts, ProtoAssembler):
    """
    The IPv6 Destination Options packet assembler.
    """

    _payload: Buffer

    def __init__(
        self,
        *,
        ip6_dest_opts__next: IpProto = IpProto.RAW,
        ip6_dest_opts__options: Ip6DestOptsOptions | None = None,
        ip6_dest_opts__payload: Buffer = bytes(),
        echo_tracker: Tracker | None = None,
    ) -> None:
        """
        Initialize the IPv6 Dest Opts packet assembler.

        The 'hdr_ext_len' field is computed automatically from the
        provided options block. RFC 8200 §4.6 requires the total HBH
        header (the 2-byte fixed prefix plus the options block) to
        be a multiple of 8 octets; the assembler asserts the option
        block was sized accordingly.
        """

        self._tracker = Tracker(prefix="TX", echo_tracker=echo_tracker)

        self._payload = ip6_dest_opts__payload
        self._options = ip6_dest_opts__options if ip6_dest_opts__options is not None else Ip6DestOptsOptions()

        options_len = len(self._options)

        assert (IP6_DEST_OPTS__HEADER__LEN + options_len) % 8 == 0, (
            "The IPv6 Dest Opts header (2-byte prefix + options) must be a multiple of "
            f"8 octets. Got: {IP6_DEST_OPTS__HEADER__LEN + options_len} bytes total."
        )

        assert options_len <= IP6_DEST_OPTS__OPTIONS__MAX_LEN, (
            "The IPv6 Dest Opts options block must not exceed "
            f"{IP6_DEST_OPTS__OPTIONS__MAX_LEN} bytes. Got: {options_len}."
        )

        # hdr_ext_len = (total_header_len / 8) - 1
        hdr_ext_len = (IP6_DEST_OPTS__HEADER__LEN + options_len) // 8 - 1

        self._header = Ip6DestOptsHeader(
            next=ip6_dest_opts__next,
            hdr_ext_len=hdr_ext_len,
        )

    @override
    def assemble(self, buffers: list[Buffer], /) -> None:
        """
        Assemble the IPv6 Dest Opts packet into list of buffers.
        """

        buffers.append(bytearray(self._header))
        buffers.append(bytearray(self._options))
        buffers.append(self._payload)
