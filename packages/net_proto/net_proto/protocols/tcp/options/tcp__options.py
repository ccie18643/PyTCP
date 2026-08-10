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

net_proto/protocols/tcp/options/tcp__options.py

ver 3.0.10
"""

from abc import ABC
from typing import Self, override

from net_addr import Buffer
from net_proto.lib.proto_option import ProtoOptions
from net_proto.protocols.tcp.options.tcp__option import TcpOption, TcpOptionType
from net_proto.protocols.tcp.options.tcp__option__accecn0 import (
    TcpOptionAccecn0,
)
from net_proto.protocols.tcp.options.tcp__option__accecn1 import (
    TcpOptionAccecn1,
)
from net_proto.protocols.tcp.options.tcp__option__eol import TcpOptionEol
from net_proto.protocols.tcp.options.tcp__option__fastopen import TcpOptionFastOpen
from net_proto.protocols.tcp.options.tcp__option__mss import TcpOptionMss
from net_proto.protocols.tcp.options.tcp__option__nop import (
    TCP__OPTION__NOP__LEN,
    TcpOptionNop,
)
from net_proto.protocols.tcp.options.tcp__option__sack import (
    TcpOptionSack,
    TcpSackBlock,
)
from net_proto.protocols.tcp.options.tcp__option__sackperm import (
    TcpOptionSackperm,
)
from net_proto.protocols.tcp.options.tcp__option__timestamps import (
    TcpOptionTimestamps,
    TcpTimestamps,
)
from net_proto.protocols.tcp.options.tcp__option__unknown import (
    TcpOptionUnknown,
)
from net_proto.protocols.tcp.options.tcp__option__wscale import TcpOptionWscale
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
        Get the TCP 'mss' option value.
        """

        for option in self._options:
            if isinstance(option, TcpOptionMss):
                return option.mss

        return None

    @property
    def wscale(self) -> int | None:
        """
        Get the TCP 'wscale' option value.
        """

        for option in self._options:
            if isinstance(option, TcpOptionWscale):
                return option.wscale

        return None

    @property
    def sackperm(self) -> bool | None:
        """
        Get the TCP 'sackperm' option value.
        """

        for option in self._options:
            if isinstance(option, TcpOptionSackperm):
                return True

        return None

    @property
    def sack(self) -> list[TcpSackBlock] | None:
        """
        Get the TCP 'sack' option value.
        """

        for option in self._options:
            if isinstance(option, TcpOptionSack):
                return option.blocks

        return None

    @property
    def timestamps(self) -> TcpTimestamps | None:
        """
        Get the TCP 'timestamps' option value.
        """

        for option in self._options:
            if isinstance(option, TcpOptionTimestamps):
                return TcpTimestamps(option.tsval, option.tsecr)

        return None

    @property
    def fastopen(self) -> bytes | None:
        """
        Get the TCP 'fastopen' option value.

        Returns 'b""' for the empty-cookie request form, the
        cookie bytes for the cookie-response/use form, and
        'None' when the option is absent on the wire.
        """

        for option in self._options:
            if isinstance(option, TcpOptionFastOpen):
                return option.cookie

        return None

    @property
    def accecn(self) -> TcpOptionAccecn0 | TcpOptionAccecn1 | None:
        """
        Get the TCP 'accecn' option.

        Returns either the kind=172 (AccECN0) or kind=174 (AccECN1)
        wire-form variant, whichever the peer chose to emit
        (RFC 9768 §3.2.3).
        """

        for option in self._options:
            if isinstance(option, (TcpOptionAccecn0, TcpOptionAccecn1)):
                return option

        return None

    @staticmethod
    def validate_integrity(
        *,
        frame: Buffer,
        hlen: int,
    ) -> None:
        """
        Run the TCP options integrity checks before parsing options.
        """

        # RFC 9293 §3.2 — TCP option walker. Case-1 options (Kind
        # only: EOL and NOP) advance by 1 byte; Case-2 options
        # (Kind + Length + Data) advance by the Length byte. The
        # cumulative walk MUST stay within the TCP header region.
        offset = TCP__HEADER__LEN

        while offset < hlen:
            # RFC 9293 §3.2 — EOL (Kind 0) terminates the option list.
            if frame[offset] == int(TcpOptionType.EOL):
                break

            # RFC 9293 §3.2 — NOP (Kind 1) is a single byte used
            # for inter-option padding.
            if frame[offset] == int(TcpOptionType.NOP):
                offset += TCP__OPTION__NOP__LEN
                continue

            # RFC 9293 §3.2 — Case-2 TLV: the Length byte MUST
            # cover both itself and the preceding Kind byte (i.e.
            # >= 2).
            if (value := frame[offset + 1]) < 2:
                raise TcpIntegrityError(
                    f"The TCP option length must be greater than 1. Got: {value!r}.",
                )

            # RFC 9293 §3.2 — no individual option may extend
            # past the TCP header length (Data Offset).
            offset += frame[offset + 1]
            if offset > hlen:
                raise TcpIntegrityError(
                    f"The TCP option length must not extend past the header length. Got: {offset=}, {hlen=}",
                )

    @override
    @classmethod
    def from_buffer(cls, buffer: Buffer, /) -> Self:
        """
        Read the TCP options from buffer.
        """

        offset = 0
        options: list[TcpOption] = []

        while offset < len(buffer):
            match TcpOptionType.from_bytes(buffer[offset : offset + 1]):
                case TcpOptionType.EOL:
                    options.append(TcpOptionEol.from_buffer(buffer[offset:]))
                    break
                case TcpOptionType.NOP:
                    options.append(TcpOptionNop.from_buffer(buffer[offset:]))
                case TcpOptionType.MSS:
                    options.append(TcpOptionMss.from_buffer(buffer[offset:]))
                case TcpOptionType.WSCALE:
                    options.append(TcpOptionWscale.from_buffer(buffer[offset:]))
                case TcpOptionType.SACKPERM:
                    options.append(TcpOptionSackperm.from_buffer(buffer[offset:]))
                case TcpOptionType.SACK:
                    options.append(TcpOptionSack.from_buffer(buffer[offset:]))
                case TcpOptionType.TIMESTAMPS:
                    options.append(TcpOptionTimestamps.from_buffer(buffer[offset:]))
                case TcpOptionType.FASTOPEN:
                    options.append(TcpOptionFastOpen.from_buffer(buffer[offset:]))
                case TcpOptionType.ACCECN0:
                    options.append(TcpOptionAccecn0.from_buffer(buffer[offset:]))
                case TcpOptionType.ACCECN1:
                    options.append(TcpOptionAccecn1.from_buffer(buffer[offset:]))
                case _:
                    options.append(TcpOptionUnknown.from_buffer(buffer[offset:]))

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
        Get the TCP 'mss' option value.

        Returns the TCP__MIN_MSS protocol default when the
        option is absent.
        """

        return TCP__MIN_MSS if self._options.mss is None else self._options.mss

    @property
    def wscale(self) -> int:
        """
        Get the TCP 'wscale' option value.

        Returns 0 (no scaling) when the option is absent.
        """

        return self._options.wscale or 0

    @property
    def sackperm(self) -> bool:
        """
        Get the TCP 'sackperm' option value.

        Returns False when the option is absent.
        """

        return bool(self._options.sackperm)

    @property
    def sack(self) -> list[TcpSackBlock] | None:
        """
        Get the TCP 'sack' option value.
        """

        return self._options.sack

    @property
    def timestamps(self) -> TcpTimestamps | None:
        """
        Get the TCP 'timestamps' option value.
        """

        return self._options.timestamps
