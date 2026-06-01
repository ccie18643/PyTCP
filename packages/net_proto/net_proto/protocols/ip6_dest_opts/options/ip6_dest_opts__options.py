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
This module contains the IPv6 Destination Options packet options class.

net_proto/protocols/ip6_dest_opts/options/ip6_dest_opts__options.py

ver 3.0.8
"""

from abc import ABC
from typing import Self, override

from net_proto.lib.buffer import Buffer
from net_proto.lib.proto_option import ProtoOptions
from net_proto.protocols.ip6_dest_opts.ip6_dest_opts__errors import (
    Ip6DestOptsIntegrityError,
    Ip6DestOptsSanityError,
)
from net_proto.protocols.ip6_dest_opts.options.ip6_dest_opts__option import (
    IP6_DEST_OPTS__OPTION__LEN,
    Ip6DestOptsOption,
    Ip6DestOptsOptionAction,
    Ip6DestOptsOptionType,
    ip6_dest_opts__option_action,
)
from net_proto.protocols.ip6_dest_opts.options.ip6_dest_opts__option__pad1 import (
    IP6_DEST_OPTS__OPTION__PAD1__LEN,
    Ip6DestOptsOptionPad1,
)
from net_proto.protocols.ip6_dest_opts.options.ip6_dest_opts__option__padn import (
    Ip6DestOptsOptionPadN,
)
from net_proto.protocols.ip6_dest_opts.options.ip6_dest_opts__option__tunnel_encapsulation_limit import (
    Ip6DestOptsOptionTunnelEncapsulationLimit,
)
from net_proto.protocols.ip6_dest_opts.options.ip6_dest_opts__option__unknown import (
    Ip6DestOptsOptionUnknown,
)

# RFC 8200 §4.6 — Hdr Ext Len is an 8-bit unsigned integer giving
# the length of the Destination Options header in 8-octet units NOT
# including the first 8 octets. Maximum total options block (after
# the 2-byte Next-Header / Hdr-Ext-Len prefix) is therefore
# (255 + 1) * 8 - 2 = 2046 bytes.
IP6_DEST_OPTS__OPTIONS__MAX_LEN = 2046


class Ip6DestOptsOptions(ProtoOptions):
    """
    The IPv6 Destination Options packet options.
    """

    @property
    def tunnel_encapsulation_limit(self) -> Ip6DestOptsOptionTunnelEncapsulationLimit | None:
        """
        Get the IPv6 DestOpts 'tunnel_encapsulation_limit' option (RFC 2473 §5.1).
        """

        for option in self._options:
            if isinstance(option, Ip6DestOptsOptionTunnelEncapsulationLimit):
                return option

        return None

    @staticmethod
    def validate_integrity(*, buffer: Buffer) -> None:
        """
        Run the IPv6 Dest Opts options integrity checks before parsing the
        TLV walker. Catches malformed length fields and out-of-bounds
        TLV walks; raises 'Ip6DestOptsIntegrityError' so the caller can
        emit ICMPv6 Parameter Problem code 0 (erroneous header field
        encountered).
        """

        offset = 0

        while offset < len(buffer):
            if buffer[offset] == int(Ip6DestOptsOptionType.PAD1):
                offset += IP6_DEST_OPTS__OPTION__PAD1__LEN
                continue

            if offset + IP6_DEST_OPTS__OPTION__LEN > len(buffer):
                raise Ip6DestOptsIntegrityError(
                    "The IPv6 Dest Opts option must carry a 1-byte Opt Data Len following its "
                    f"Type byte. Got truncated tail at offset {offset} (block length {len(buffer)})."
                )

            opt_data_len = buffer[offset + 1]
            opt_total_len = IP6_DEST_OPTS__OPTION__LEN + opt_data_len

            if offset + opt_total_len > len(buffer):
                raise Ip6DestOptsIntegrityError(
                    "The IPv6 Dest Opts option must not extend past the options block. "
                    f"Got: option at offset {offset} declares total length {opt_total_len}, "
                    f"block length {len(buffer)}."
                )

            offset += opt_total_len

    @staticmethod
    def validate_sanity(*, buffer: Buffer, ip6_dst_is_multicast: bool = False) -> None:
        """
        Apply RFC 8200 §4.2 action-on-unrecognized to every option in
        the (already integrity-checked) options buffer. Raises
        'Ip6DestOptsSanityError' with the offending option's offset as
        'pointer' when the action requires ICMPv6 Parameter Problem
        code 2; with no pointer when the action requires silent
        discard. The 'ip6_dst_is_multicast' flag toggles the §4.2
        action-11 multicast-suppression rule (skip the ICMP when the
        destination is multicast).
        """

        offset = 0

        while offset < len(buffer):
            opt_type = buffer[offset]

            if opt_type in Ip6DestOptsOptionType.get_known_values():
                if opt_type == int(Ip6DestOptsOptionType.PAD1):
                    offset += IP6_DEST_OPTS__OPTION__PAD1__LEN
                else:
                    offset += IP6_DEST_OPTS__OPTION__LEN + buffer[offset + 1]
                continue

            action = ip6_dest_opts__option_action(opt_type)

            match action:
                case Ip6DestOptsOptionAction.SKIP:
                    pass
                case Ip6DestOptsOptionAction.DISCARD:
                    raise Ip6DestOptsSanityError(
                        f"Unrecognized DestOpts option type 0x{opt_type:02x} at offset {offset} "
                        "with action 01 (silent discard).",
                    )
                case Ip6DestOptsOptionAction.DISCARD_PARAM_PROBLEM:
                    raise Ip6DestOptsSanityError(
                        f"Unrecognized DestOpts option type 0x{opt_type:02x} at offset {offset} "
                        "with action 10 (discard + Param Problem code 2).",
                        pointer=offset,
                    )
                case Ip6DestOptsOptionAction.DISCARD_PARAM_PROBLEM_UNICAST:
                    if ip6_dst_is_multicast:
                        raise Ip6DestOptsSanityError(
                            f"Unrecognized DestOpts option type 0x{opt_type:02x} at offset "
                            f"{offset} with action 11 (silent discard on multicast dst).",
                            multicast_only=True,
                        )
                    raise Ip6DestOptsSanityError(
                        f"Unrecognized DestOpts option type 0x{opt_type:02x} at offset {offset} "
                        "with action 11 (discard + Param Problem code 2 on unicast dst).",
                        pointer=offset,
                    )

            offset += IP6_DEST_OPTS__OPTION__LEN + buffer[offset + 1]

    @override
    @classmethod
    def from_buffer(cls, buffer: Buffer, /) -> Self:
        """
        Read the IPv6 Dest Opts options from buffer.

        Caller is responsible for running 'validate_integrity' (and,
        if the chain walker has the destination address handy,
        'validate_sanity') before calling 'from_buffer'.
        """

        offset = 0
        options: list[Ip6DestOptsOption] = []

        while offset < len(buffer):
            match Ip6DestOptsOptionType.from_bytes(buffer[offset : offset + 1]):
                case Ip6DestOptsOptionType.PAD1:
                    options.append(Ip6DestOptsOptionPad1.from_buffer(buffer[offset:]))
                case Ip6DestOptsOptionType.PADN:
                    options.append(Ip6DestOptsOptionPadN.from_buffer(buffer[offset:]))
                case Ip6DestOptsOptionType.TUNNEL_ENCAPSULATION_LIMIT:
                    options.append(Ip6DestOptsOptionTunnelEncapsulationLimit.from_buffer(buffer[offset:]))
                case _:
                    options.append(Ip6DestOptsOptionUnknown.from_buffer(buffer[offset:]))

            offset += options[-1].len

        return cls(*options)


class Ip6DestOptsOptionsProperties(ABC):
    """
    The IPv6 Dest Opts options properties mixin class.
    """

    _options: Ip6DestOptsOptions
