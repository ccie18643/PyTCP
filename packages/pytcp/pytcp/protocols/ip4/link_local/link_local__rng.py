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
This module contains the RFC 3927 §2.1 MAC-seeded pseudo-
random link-local candidate generator.

The selection algorithm is a small Linear Congruential
Generator seeded from the MAC's 48 bits + an attempt counter
that rolls the sequence on each conflict-driven retry. The
algorithm satisfies the §2.1 SHOULD that different hosts
generate different sequences (different MACs diverge) and the
§2.1 SHOULD that the same host picks the same address across
reboots without persistent storage (deterministic per MAC).

Linux comparison: avahi-autoipd uses a similar manual LCG;
systemd's 'sd_ipv4ll' uses SipHash24-of-MAC instead. The
choice between the two is cosmetic — both satisfy the RFC's
"different hosts diverge" rule. PyTCP follows
avahi-autoipd's choice for clarity (4-line implementation,
no module-level state).

pytcp/protocols/ip4/link_local/link_local__rng.py

ver 3.0.8
"""

import struct

from net_addr import Ip4Address, MacAddress

# RFC 3927 §2.1 link-local candidate range bounds. The first
# 256 (169.254.0.0/24) and last 256 (169.254.255.0/24) of
# 169.254/16 are reserved and MUST NOT be selected; the
# legal range is 169.254.1.0..169.254.254.255 inclusive
# (65024 addresses).
RANGE_FIRST: Ip4Address = Ip4Address("169.254.1.0")
RANGE_LAST: Ip4Address = Ip4Address("169.254.254.255")
_RANGE_FIRST_INT: int = int(RANGE_FIRST)
_RANGE_SIZE: int = int(RANGE_LAST) - _RANGE_FIRST_INT + 1  # 65024

# Numerical Recipes LCG constants. Sufficient mixing for a
# 65024-element address space; the goal is "different MACs
# land on different addresses" not cryptographic
# unpredictability.
_LCG_MULT: int = 1103515245
_LCG_ADD: int = 12345
_LCG_MASK: int = 0x7FFFFFFF


def candidate_from_mac(*, mac: MacAddress, attempt: int = 0) -> Ip4Address:
    """
    Generate a link-local candidate address from 'mac' and the
    'attempt' counter. Deterministic per-(MAC, attempt); two
    calls with the same arguments always return the same
    address. Different MACs always diverge; different attempt
    counters on the same MAC produce different addresses so
    a conflict-driven retry picks a fresh candidate.
    """

    # The MAC is 6 bytes; pad to 8 for struct.unpack and parse
    # as a big-endian 64-bit int.
    seed = struct.unpack("!Q", b"\x00\x00" + bytes(mac))[0]
    value = (seed * _LCG_MULT + _LCG_ADD + attempt) & _LCG_MASK
    return Ip4Address(_RANGE_FIRST_INT + (value % _RANGE_SIZE))
