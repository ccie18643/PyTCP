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
This module contains the ICMPv4 packet assembler.

net_proto/protocols/icmp4/icmp4__assembler.py

ver 3.0.8
"""

from typing import cast, override

from net_addr import Buffer
from net_proto.lib.inet_cksum import inet_cksum
from net_proto.lib.proto_assembler import ProtoAssembler
from net_proto.lib.tracker import Tracker
from net_proto.protocols.icmp4.icmp4__base import Icmp4
from net_proto.protocols.icmp4.message.icmp4__message import Icmp4Message
from net_proto.protocols.icmp4.message.icmp4__message__unknown import (
    Icmp4MessageUnknown,
)


class Icmp4Assembler(Icmp4, ProtoAssembler):
    """
    The ICMPv4 packet assembler.
    """

    def __init__(
        self,
        *,
        icmp4__message: Icmp4Message,
        echo_tracker: Tracker | None = None,
    ) -> None:
        """
        Initialize the ICMPv4 packet assembler.
        """

        # RFC 792 / RFC 1122 / RFC 1812 — every known ICMPv4 message
        # type has a closed set of legal code values; the parser's
        # `validate_sanity()` rejects wire frames carrying any other
        # code via `code.is_unknown`. The TX boundary refuses to
        # construct a frame with an unknown code so PyTCP itself
        # cannot originate one. The dataclass `__post_init__` stays
        # parser-tolerant (the parser's `from_buffer` constructs via
        # `<code-enum>.from_int()` which materialises `UNKNOWN_n`
        # codepoints; the strict rejection lives at the assembler
        # boundary instead, mirroring the DHCPv4 UNKNOWN-enum
        # asymmetry split).
        #
        # `Icmp4MessageUnknown` is exempt: it is the parser-side
        # carrier for RFC 1122 §3.2.2 unknown-type frames whose code
        # field is necessarily an `UNKNOWN_n` member of the abstract
        # `Icmp4Code` base. Wrapping such a message in an assembler
        # is a legitimate roundtrip case (security testing /
        # raw-socket replay); the per-code check applies only to the
        # closed-enum subclasses.
        if not isinstance(icmp4__message, Icmp4MessageUnknown):
            assert not icmp4__message.code.is_unknown, (
                f"The 'icmp4__message.code' field must be a known "
                f"{type(icmp4__message.code).__name__} member. "
                f"Got: {icmp4__message.code!r}"
            )

        self._tracker = Tracker(prefix="TX", echo_tracker=echo_tracker)

        self._message = icmp4__message

    @override
    def assemble(self, buffers: list[Buffer], /) -> None:
        """
        Assemble the ICMPv4 packet into list of buffers.
        """

        self._message.assemble(buffers)

        cast(bytearray, buffers[-2])[2:4] = inet_cksum(
            *buffers[-2:],
        ).to_bytes(2)
