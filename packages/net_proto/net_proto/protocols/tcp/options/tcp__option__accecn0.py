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
This module contains the TCP AccECN0 (kind=172) option support code.

net_proto/protocols/tcp/options/tcp__option__accecn0.py

ver 3.0.10
"""

from dataclasses import dataclass, field
from typing import Self, override

from net_addr import Buffer
from net_proto.lib.int_checks import is_uint24
from net_proto.protocols.tcp.options.tcp__option import (
    TCP__OPTION__LEN,
    TcpOption,
    TcpOptionType,
)
from net_proto.protocols.tcp.tcp__errors import TcpIntegrityError

# The TCP AccECN0 option [RFC 9768 §3.2.3] - kind=172 form carrying all
# three 24-bit byte counters with r.ECT(0) in the first slot. The kind=172
# variant is conventional for classic-ECN-style deployments where ECT(0) is
# the dominant codepoint; the sibling AccECN1 (kind=174) reorders the
# counters to put r.ECT(1) first for L4S deployments. Both kinds encode
# the same conceptual data; only the wire ordering differs.
#
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |   Kind = 172  |   Length = 11 |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                  EE0B (r.ECT(0))              |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                  ECEB (r.CE)                  |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                  EE1B (r.ECT(1))              |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

TCP__OPTION__ACCECN0__LEN = 11


# Per RFC 9768 §3.2.3 Table 5, the AccECN0 option supports four
# wire lengths corresponding to which trailing fields are
# omitted. Senders that have all three byte counters available
# emit the full Length-11 form; senders abbreviating to save
# TCP option space MUST preserve field order and include any
# field that has changed (so dropped fields are always trailing
# unchanged ones).
_TCP__OPTION__ACCECN0__VALID_LENS: frozenset[int] = frozenset({2, 5, 8, 11})


@dataclass(frozen=True, kw_only=True, slots=True)
class TcpOptionAccecn0(TcpOption):
    """
    The TCP AccECN0 option support class (RFC 9768 §3.2.3, AccECN0 form).
    """

    type: TcpOptionType = field(
        repr=False,
        init=False,
        default=TcpOptionType.ACCECN0,
    )
    len: int = field(
        repr=False,
        init=False,
        default=TCP__OPTION__ACCECN0__LEN,
    )

    ee0b: int | None = None
    eceb: int | None = None
    ee1b: int | None = None

    @override
    def __post_init__(self) -> None:
        """
        Ensure integrity of the TCP AccECN0 option fields and
        derive the wire 'len' from which trailing fields are
        present (None means absent on the wire). The Length=11
        form has all three counters; abbreviated forms drop
        from the tail (Length=8 omits ee1b; Length=5 omits
        eceb and ee1b; Length=2 is the empty form).
        """

        # Field-presence ordering invariant: a present field
        # implies all preceding (less-trailing) fields are
        # also present. Equivalently: ee1b cannot be set
        # while eceb is None, and eceb cannot be set while
        # ee0b is None.
        if self.ee1b is not None:
            assert (
                self.eceb is not None and self.ee0b is not None
            ), "AccECN0 Length=11 (ee1b set) requires ee0b and eceb to also be set."
            object.__setattr__(self, "len", 11)
        elif self.eceb is not None:
            assert self.ee0b is not None, "AccECN0 Length=8 (eceb set) requires ee0b to also be set."
            object.__setattr__(self, "len", 8)
        elif self.ee0b is not None:
            object.__setattr__(self, "len", 5)
        else:
            object.__setattr__(self, "len", 2)

        if self.ee0b is not None:
            assert is_uint24(self.ee0b), f"The 'ee0b' field must be a 24-bit unsigned integer. Got: {self.ee0b!r}"
        if self.eceb is not None:
            assert is_uint24(self.eceb), f"The 'eceb' field must be a 24-bit unsigned integer. Got: {self.eceb!r}"
        if self.ee1b is not None:
            assert is_uint24(self.ee1b), f"The 'ee1b' field must be a 24-bit unsigned integer. Got: {self.ee1b!r}"

    @override
    def __str__(self) -> str:
        """
        Get the TCP AccECN0 option log string.
        """

        return f"accecn0 ect0={self.ee0b}/ce={self.eceb}/ect1={self.ee1b}"

    @override
    def __buffer__(self, _: int) -> memoryview:
        """
        Get the TCP AccECN0 option as a memoryview. Emits
        only as many bytes as 'self.len' indicates; absent
        trailing counters are omitted on the wire per the
        §3.2.3 abbreviation rule.
        """

        buffer = bytearray(self.len)
        buffer[0] = int(self.type)
        buffer[1] = self.len
        if self.ee0b is not None:
            buffer[2:5] = self.ee0b.to_bytes(3, "big")
        if self.eceb is not None:
            buffer[5:8] = self.eceb.to_bytes(3, "big")
        if self.ee1b is not None:
            buffer[8:11] = self.ee1b.to_bytes(3, "big")

        return memoryview(buffer)

    @staticmethod
    def _validate_integrity(buffer: Buffer, /) -> None:
        """
        Ensure integrity of the TCP AccECN0 option before parsing it.
        """

        # RFC 9768 §3.2.3 Table 5 — AccECN0 supports four wire
        # lengths corresponding to which trailing counter fields
        # are present (2 = empty, 5 = ee0b only, 8 = ee0b+eceb,
        # 11 = all three). Any other length is malformed.
        if (value := buffer[1]) not in _TCP__OPTION__ACCECN0__VALID_LENS:
            raise TcpIntegrityError(
                "The TCP AccECN0 option length value must be one of "
                f"{sorted(_TCP__OPTION__ACCECN0__VALID_LENS)}. Got: {value!r}"
            )

        # RFC 9293 §3.2 — option length MUST NOT exceed the
        # buffer available.
        if (value := buffer[1]) > len(buffer):
            raise TcpIntegrityError(
                "The TCP AccECN0 option length value must be less than or equal to "
                f"the length of provided bytes ({len(buffer)}). Got: {value!r}"
            )

    @override
    @classmethod
    def from_buffer(cls, buffer: Buffer, /) -> Self:
        """
        Initialize the TCP AccECN0 option from buffer. Length
        2/5/8/11 forms are all accepted; trailing fields
        absent on the wire are returned as None.
        """

        assert (
            value := len(buffer)
        ) >= TCP__OPTION__LEN, (
            f"The minimum length of the TCP AccECN0 option must be {TCP__OPTION__LEN} bytes. Got: {value!r}"
        )

        assert (value := buffer[0]) == int(TcpOptionType.ACCECN0), (
            f"The TCP AccECN0 option type must be {TcpOptionType.ACCECN0!r}. " f"Got: {TcpOptionType.from_int(value)!r}"
        )

        cls._validate_integrity(buffer)

        wire_len = buffer[1]
        ee0b = int.from_bytes(buffer[2:5], "big") if wire_len >= 5 else None
        eceb = int.from_bytes(buffer[5:8], "big") if wire_len >= 8 else None
        ee1b = int.from_bytes(buffer[8:11], "big") if wire_len >= 11 else None

        return cls(
            ee0b=ee0b,
            eceb=eceb,
            ee1b=ee1b,
        )
