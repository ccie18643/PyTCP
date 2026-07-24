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
This module contains the IPv6 Hop-by-Hop Options packet options class.

net_proto/protocols/ip6_hbh/options/ip6_hbh__options.py

ver 3.0.9
"""

from abc import ABC
from typing import Self, override

from net_addr import Buffer
from net_proto.lib.proto_option import ProtoOptions
from net_proto.protocols.ip6_hbh.ip6_hbh__errors import (
    Ip6HbhIntegrityError,
    Ip6HbhSanityError,
)
from net_proto.protocols.ip6_hbh.options.ip6_hbh__option import (
    IP6_HBH__OPTION__LEN,
    Ip6HbhOption,
    Ip6HbhOptionAction,
    Ip6HbhOptionType,
    ip6_hbh__option_action,
)
from net_proto.protocols.ip6_hbh.options.ip6_hbh__option__calipso import (
    Ip6HbhOptionCalipso,
)
from net_proto.protocols.ip6_hbh.options.ip6_hbh__option__jumbo_payload import (
    Ip6HbhOptionJumboPayload,
)
from net_proto.protocols.ip6_hbh.options.ip6_hbh__option__pad1 import (
    IP6_HBH__OPTION__PAD1__LEN,
    Ip6HbhOptionPad1,
)
from net_proto.protocols.ip6_hbh.options.ip6_hbh__option__padn import (
    Ip6HbhOptionPadN,
)
from net_proto.protocols.ip6_hbh.options.ip6_hbh__option__router_alert import (
    Ip6HbhOptionRouterAlert,
)
from net_proto.protocols.ip6_hbh.options.ip6_hbh__option__unknown import (
    Ip6HbhOptionUnknown,
)

# RFC 8200 §4.3 — Hdr Ext Len is an 8-bit unsigned integer giving
# the length of the Hop-by-Hop Options header in 8-octet units NOT
# including the first 8 octets. Maximum total options block (after
# the 2-byte Next-Header / Hdr-Ext-Len prefix) is therefore
# (255 + 1) * 8 - 2 = 2046 bytes.
IP6_HBH__OPTIONS__MAX_LEN = 2046


class Ip6HbhOptions(ProtoOptions):
    """
    The IPv6 Hop-by-Hop Options packet options.
    """

    @property
    def router_alert(self) -> Ip6HbhOptionRouterAlert | None:
        """
        Get the IPv6 HBH 'router_alert' option (RFC 2711).
        """

        for option in self._options:
            if isinstance(option, Ip6HbhOptionRouterAlert):
                return option

        return None

    @property
    def jumbo_payload(self) -> Ip6HbhOptionJumboPayload | None:
        """
        Get the IPv6 HBH 'jumbo_payload' option (RFC 2675).
        """

        for option in self._options:
            if isinstance(option, Ip6HbhOptionJumboPayload):
                return option

        return None

    @property
    def calipso(self) -> Ip6HbhOptionCalipso | None:
        """
        Get the IPv6 HBH 'calipso' option (RFC 5570).
        """

        for option in self._options:
            if isinstance(option, Ip6HbhOptionCalipso):
                return option

        return None

    @staticmethod
    def validate_integrity(*, buffer: Buffer) -> None:
        """
        Run the IPv6 HBH options integrity checks before parsing the
        TLV walker. Catches malformed length fields and out-of-bounds
        TLV walks; raises 'Ip6HbhIntegrityError' so the caller can
        emit ICMPv6 Parameter Problem code 0 (erroneous header field
        encountered).
        """

        offset = 0

        while offset < len(buffer):
            if buffer[offset] == int(Ip6HbhOptionType.PAD1):
                offset += IP6_HBH__OPTION__PAD1__LEN
                continue

            if offset + IP6_HBH__OPTION__LEN > len(buffer):
                raise Ip6HbhIntegrityError(
                    "The IPv6 HBH option must carry a 1-byte Opt Data Len following its "
                    f"Type byte. Got truncated tail at offset {offset} (block length {len(buffer)})."
                )

            opt_data_len = buffer[offset + 1]
            opt_total_len = IP6_HBH__OPTION__LEN + opt_data_len

            if offset + opt_total_len > len(buffer):
                raise Ip6HbhIntegrityError(
                    "The IPv6 HBH option must not extend past the options block. "
                    f"Got: option at offset {offset} declares total length {opt_total_len}, "
                    f"block length {len(buffer)}."
                )

            offset += opt_total_len

    @staticmethod
    def validate_sanity(*, buffer: Buffer, ip6_dst_is_multicast: bool = False) -> None:
        """
        Apply RFC 8200 §4.2 action-on-unrecognized to every option in
        the (already integrity-checked) options buffer. Raises
        'Ip6HbhSanityError' with the offending option's offset as
        'pointer' when the action requires ICMPv6 Parameter Problem
        code 2; with no pointer when the action requires silent
        discard. The 'ip6_dst_is_multicast' flag toggles the §4.2
        action-11 multicast-suppression rule (skip the ICMP when the
        destination is multicast).
        """

        offset = 0

        while offset < len(buffer):
            opt_type = buffer[offset]

            if opt_type in Ip6HbhOptionType.get_known_values():
                if opt_type == int(Ip6HbhOptionType.PAD1):
                    offset += IP6_HBH__OPTION__PAD1__LEN
                else:
                    offset += IP6_HBH__OPTION__LEN + buffer[offset + 1]
                continue

            action = ip6_hbh__option_action(opt_type)

            match action:
                case Ip6HbhOptionAction.SKIP:
                    pass
                case Ip6HbhOptionAction.DISCARD:
                    raise Ip6HbhSanityError(
                        f"Unrecognized HBH option type 0x{opt_type:02x} at offset {offset} "
                        "with action 01 (silent discard).",
                    )
                case Ip6HbhOptionAction.DISCARD_PARAM_PROBLEM:
                    raise Ip6HbhSanityError(
                        f"Unrecognized HBH option type 0x{opt_type:02x} at offset {offset} "
                        "with action 10 (discard + Param Problem code 2).",
                        pointer=offset,
                    )
                case Ip6HbhOptionAction.DISCARD_PARAM_PROBLEM_UNICAST:
                    if ip6_dst_is_multicast:
                        raise Ip6HbhSanityError(
                            f"Unrecognized HBH option type 0x{opt_type:02x} at offset "
                            f"{offset} with action 11 (silent discard on multicast dst).",
                            multicast_only=True,
                        )
                    raise Ip6HbhSanityError(
                        f"Unrecognized HBH option type 0x{opt_type:02x} at offset {offset} "
                        "with action 11 (discard + Param Problem code 2 on unicast dst).",
                        pointer=offset,
                    )

            offset += IP6_HBH__OPTION__LEN + buffer[offset + 1]

    @override
    @classmethod
    def from_buffer(cls, buffer: Buffer, /) -> Self:
        """
        Read the IPv6 HBH options from buffer.

        Caller is responsible for running 'validate_integrity' (and,
        if the chain walker has the destination address handy,
        'validate_sanity') before calling 'from_buffer'.
        """

        offset = 0
        options: list[Ip6HbhOption] = []

        while offset < len(buffer):
            match Ip6HbhOptionType.from_bytes(buffer[offset : offset + 1]):
                case Ip6HbhOptionType.PAD1:
                    options.append(Ip6HbhOptionPad1.from_buffer(buffer[offset:]))
                case Ip6HbhOptionType.PADN:
                    options.append(Ip6HbhOptionPadN.from_buffer(buffer[offset:]))
                case Ip6HbhOptionType.ROUTER_ALERT:
                    options.append(Ip6HbhOptionRouterAlert.from_buffer(buffer[offset:]))
                case Ip6HbhOptionType.CALIPSO:
                    options.append(Ip6HbhOptionCalipso.from_buffer(buffer[offset:]))
                case Ip6HbhOptionType.JUMBO_PAYLOAD:
                    options.append(Ip6HbhOptionJumboPayload.from_buffer(buffer[offset:]))
                case _:
                    options.append(Ip6HbhOptionUnknown.from_buffer(buffer[offset:]))

            offset += options[-1].len

        return cls(*options)


class Ip6HbhOptionsProperties(ABC):
    """
    The IPv6 HBH options properties mixin class.
    """

    _options: Ip6HbhOptions
