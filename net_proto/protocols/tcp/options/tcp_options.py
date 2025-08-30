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
This module contains the TCP packet options class.

net_proto/protocols/tcp/options/tcp_options.py

ver 3.0.4
"""


from abc import ABC
from typing import Self, override

from net_proto.lib.proto_option import ProtoOptions
from net_proto.protocols.tcp.options.tcp_option import TcpOption, TcpOptionType
from net_proto.protocols.tcp.options.tcp_option__eol import TcpOptionEol
from net_proto.protocols.tcp.options.tcp_option__mss import TcpOptionMss
from net_proto.protocols.tcp.options.tcp_option__nop import (
    TCP__OPTION__NOP__LEN,
    TcpOptionNop,
)
from net_proto.protocols.tcp.options.tcp_option__sack import (
    TcpOptionSack,
    TcpSackBlock,
)
from net_proto.protocols.tcp.options.tcp_option__sackperm import (
    TcpOptionSackperm,
)
from net_proto.protocols.tcp.options.tcp_option__timestamps import (
    TcpOptionTimestamps,
    TcpTimestamps,
)
from net_proto.protocols.tcp.options.tcp_option__unknown import TcpOptionUnknown
from net_proto.protocols.tcp.options.tcp_option__wscale import TcpOptionWscale
from net_proto.protocols.tcp.tcp__errors import TcpIntegrityError
from net_proto.protocols.tcp.tcp__header import TCP__HEADER__LEN, TCP__MIN_MSS

TCP__OPTIONS__MAX_LEN = 40


class TcpOptions(ProtoOptions):
    """
    The TCP packet options.
    """

    @property
    def mss(self) -> int | None:
        """
        Get the value of the TCP Mss option if present.
        """

        for option in self._options:
            if isinstance(option, TcpOptionMss):
                return option.mss

        return None

    @property
    def wscale(self) -> int | None:
        """
        Get the value of the TCP Wscale option if present.
        """

        for option in self._options:
            if isinstance(option, TcpOptionWscale):
                return option.wscale

        return None

    @property
    def sackperm(self) -> bool | None:
        """
        Check if the TCP Sackperm option is present.
        """

        for option in self._options:
            if isinstance(option, TcpOptionSackperm):
                return True

        return None

    @property
    def sack(self) -> list[TcpSackBlock] | None:
        """
        Get the selective ACK blocks if the Sack TCP option is present.
        """

        for option in self._options:
            if isinstance(option, TcpOptionSack):
                return option.blocks

        return None

    @property
    def timestamps(self) -> TcpTimestamps | None:
        """
        Get the TCP timestamps if the Timestamps TCP option is present.
        """

        for option in self._options:
            if isinstance(option, TcpOptionTimestamps):
                return TcpTimestamps(option.tsval, option.tsecr)

        return None

    @staticmethod
    def validate_integrity(
        *,
        frame: bytes,
        hlen: int,
    ) -> None:
        """
        Run the TCP options integrity checks before parsing options.
        """

        offset = TCP__HEADER__LEN

        while offset < hlen:
            if frame[offset] == int(TcpOptionType.EOL):
                break

            if frame[offset] == int(TcpOptionType.NOP):
                offset += TCP__OPTION__NOP__LEN
                continue

            if (value := frame[offset + 1]) < 2:
                raise TcpIntegrityError(
                    f"The TCP option length must be greater than 1. "
                    f"Got: {value!r}.",
                )

            offset += frame[offset + 1]
            if offset > hlen:
                raise TcpIntegrityError(
                    f"The TCP option length must not extend past the header "
                    f"length. Got: {offset=}, {hlen=}",
                )

    @override
    @classmethod
    def from_bytes(cls, _bytes: bytes, /) -> Self:
        """
        Read the TCP options from bytes.
        """

        offset = 0
        options: list[TcpOption] = []

        while offset < len(_bytes):
            match TcpOptionType.from_bytes(_bytes[offset:]):
                case TcpOptionType.EOL:
                    options.append(TcpOptionEol.from_bytes(_bytes[offset:]))
                    break
                case TcpOptionType.NOP:
                    options.append(TcpOptionNop.from_bytes(_bytes[offset:]))
                case TcpOptionType.MSS:
                    options.append(TcpOptionMss.from_bytes(_bytes[offset:]))
                case TcpOptionType.WSCALE:
                    options.append(TcpOptionWscale.from_bytes(_bytes[offset:]))
                case TcpOptionType.SACKPERM:
                    options.append(
                        TcpOptionSackperm.from_bytes(_bytes[offset:])
                    )
                case TcpOptionType.SACK:
                    options.append(TcpOptionSack.from_bytes(_bytes[offset:]))
                case TcpOptionType.TIMESTAMPS:
                    options.append(
                        TcpOptionTimestamps.from_bytes(_bytes[offset:])
                    )
                case _:
                    options.append(TcpOptionUnknown.from_bytes(_bytes[offset:]))

            offset += options[-1].len

        return cls(*options)


class TcpOptionsProperties(ABC):
    """
    The TCP options properties mixin class.
    """

    _options: TcpOptions

    @property
    def mss(self) -> int:
        """
        Get Mss TCP option value. If option is not present then
        return the TCP protocol default Mss value.
        """

        return TCP__MIN_MSS if self._options.mss is None else self._options.mss

    @property
    def wscale(self) -> int:
        """
        Get Wscale TCP option value.
        """

        return self._options.wscale or 0

    @property
    def sackperm(self) -> bool:
        """
        Get Sackperm TCP option value.
        """

        return bool(self._options.sackperm)

    @property
    def sack(self) -> list[TcpSackBlock] | None:
        """
        Get Sack TCP option value.
        """

        return self._options.sack

    @property
    def timestamps(self) -> TcpTimestamps | None:
        """
        Get the Timestamps TCP option value.
        """

        return self._options.timestamps
