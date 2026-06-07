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
This module contains the ICMPv6 packet assembler.

net_proto/protocols/icmp6/icmp6__assembler.py

ver 3.0.8
"""

from typing import cast, override

from net_addr import Buffer
from net_proto.lib.inet_cksum import inet_cksum
from net_proto.lib.proto_assembler import ProtoAssembler
from net_proto.lib.tracker import Tracker
from net_proto.protocols.icmp6.icmp6__base import Icmp6
from net_proto.protocols.icmp6.message.icmp6__message import Icmp6Message
from net_proto.protocols.icmp6.message.icmp6__message__unknown import (
    Icmp6MessageUnknown,
)


class Icmp6Assembler(Icmp6, ProtoAssembler):
    """
    The ICMPv6 packet assembler.
    """

    def __init__(
        self,
        *,
        icmp6__message: Icmp6Message,
        echo_tracker: Tracker | None = None,
    ) -> None:
        """
        Initialize the ICMPv6 packet assembler.
        """

        # RFC 4443 §2.1 / RFC 4861 §4.1-§4.5 / RFC 3810 §5 —
        # every known ICMPv6 message type (6 base + 2 MLD2 +
        # 5 ND) has a closed set of legal code values; the
        # parser's `validate_sanity` rejects RX frames whose
        # code field carries an `UNKNOWN_n` pseudo-member
        # synthesised via `<code-enum>.from_int()`. The TX
        # boundary refuses to construct a frame with an
        # unknown code so PyTCP itself cannot originate one.
        # The dataclass `__post_init__` stays parser-tolerant
        # (the parser's `from_buffer` constructs via
        # `<code-enum>.from_int()` which materialises
        # `UNKNOWN_n` codepoints; the strict closed-set
        # rejection lives at the assembler boundary instead,
        # mirroring the ICMPv4 UNKNOWN-enum asymmetry split,
        # commit `ea58c801`).
        #
        # `Icmp6MessageUnknown` is exempt: it is the
        # parser-side carrier for RFC 4443 §2.1 unknown-type
        # frames whose code field is by definition an
        # `UNKNOWN_n` member of the abstract `Icmp6Code`
        # base. Wrapping such a message in an assembler is a
        # legitimate roundtrip case (security testing /
        # raw-socket replay); the per-code check applies
        # only to the closed-enum subclasses.
        if not isinstance(icmp6__message, Icmp6MessageUnknown):
            assert not icmp6__message.code.is_unknown, (
                f"The 'icmp6__message.code' field must be a known "
                f"{type(icmp6__message.code).__name__} member. "
                f"Got: {icmp6__message.code!r}"
            )

        self._tracker = Tracker(prefix="TX", echo_tracker=echo_tracker)

        self._message = icmp6__message

    @override
    def assemble(self, buffers: list[Buffer], /) -> None:
        """
        Assemble the ICMPv6 packet into list of buffers.
        """

        self._message.assemble(buffers)

        cast(bytearray, buffers[-2])[2:4] = inet_cksum(*buffers[-2:], init=self.pshdr_sum).to_bytes(2)
