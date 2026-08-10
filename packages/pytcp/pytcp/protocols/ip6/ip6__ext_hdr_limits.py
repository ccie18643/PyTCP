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
This module contains the RFC 8504 §5.3 extension-header
option-cap helper. The IPv6 RX path calls
'check_ext_hdr_option_caps' after a successful HBH /
DestOpts parse to refuse pathological option lists (huge
Pad bursts, excessive unknown options) that could be used
to mount a resource-exhaustion attack on the parser.

pytcp/protocols/ip6/ip6__ext_hdr_limits.py

ver 3.0.9
"""

from collections.abc import Iterable

from net_proto.lib.proto_option import ProtoOption
from net_proto.protocols.ip6_hbh.options.ip6_hbh__option__pad1 import (
    IP6_HBH__OPTION__PAD1__LEN,
    Ip6HbhOptionPad1,
)
from net_proto.protocols.ip6_hbh.options.ip6_hbh__option__padn import (
    Ip6HbhOptionPadN,
)
from net_proto.protocols.ip6_hbh.options.ip6_hbh__option__unknown import (
    Ip6HbhOptionUnknown,
)


class Ip6ExtHdrCapViolation(Exception):
    """
    Raised by 'check_ext_hdr_option_caps' when an RFC 8504
    §5.3 option-cap is exceeded. The RX path catches this
    and silently drops the packet (the §5.3 caps are
    resource-exhaustion defences; the receiver is not
    obliged to emit ICMPv6 Parameter Problem on cap
    violation).
    """


def check_ext_hdr_option_caps(options: Iterable[ProtoOption], /) -> None:
    """
    Walk an HBH / DestOpts options container and raise
    'Ip6ExtHdrCapViolation' if any of the three RFC 8504 §5.3
    resource-exhaustion caps is exceeded:

    - 'ip6.ext_hdr_max_options' — total option count.
    - 'ip6.ext_hdr_max_pad_bytes' — total Pad-byte budget
      (Pad1 contributes 1, PadN of length N contributes
      2 + N).
    - 'ip6.ext_hdr_max_unknown_options' — unknown-option
      count.

    Each cap may be set to 0 to disable the check.

    The 'options' argument is treated as iterable; it
    supports both 'Ip6HbhOptions' (which is the container
    used for both HBH and DestOpts in PyTCP's
    architecture — the codec is shared) and the raw
    'tuple' / 'list' shape that tests may construct.
    """

    # Qualified module access so each invocation re-reads
    # the live sysctl values (the operator may have
    # tuned them at runtime via 'pytcp.stack.sysctl[...]
    # = N').
    from pytcp.protocols.ip6 import ip6__constants

    max_options = ip6__constants.IP6__EXT_HDR_MAX_OPTIONS
    max_pad_bytes = ip6__constants.IP6__EXT_HDR_MAX_PAD_BYTES
    max_unknown = ip6__constants.IP6__EXT_HDR_MAX_UNKNOWN_OPTIONS

    option_count = 0
    pad_bytes = 0
    unknown_count = 0

    for option in options:
        option_count += 1
        if isinstance(option, Ip6HbhOptionPad1):
            pad_bytes += IP6_HBH__OPTION__PAD1__LEN
        elif isinstance(option, Ip6HbhOptionPadN):
            pad_bytes += len(option)
        elif isinstance(option, Ip6HbhOptionUnknown):
            unknown_count += 1

    if max_options and option_count > max_options:
        raise Ip6ExtHdrCapViolation(
            f"RFC 8504 §5.3: option count {option_count} exceeds " f"ip6.ext_hdr_max_options cap {max_options}.",
        )
    if max_pad_bytes and pad_bytes > max_pad_bytes:
        raise Ip6ExtHdrCapViolation(
            f"RFC 8504 §5.3: total Pad bytes {pad_bytes} exceeds " f"ip6.ext_hdr_max_pad_bytes cap {max_pad_bytes}.",
        )
    if max_unknown and unknown_count > max_unknown:
        raise Ip6ExtHdrCapViolation(
            f"RFC 8504 §5.3: unknown-option count {unknown_count} exceeds "
            f"ip6.ext_hdr_max_unknown_options cap {max_unknown}.",
        )
