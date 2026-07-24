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
This module contains the IPv6 Flow Label generator. RFC 6437
§3 requires that nodes set the Flow Label "for all packets
of a given flow to the same value chosen from an
approximation to a discrete uniform distribution". PyTCP's
approach: hash the (src, dst) pair with the stack-wide
'IP6__FLOW_SECRET' to derive a stable 20-bit value per
flow.

The flow definition here is coarser than the 5-tuple Linux
uses (which includes (sport, dport, proto)) because the
IPv6 TX path at '_phtx_ip6' does not have port information
— ICMPv6, MLDv2, NDP, etc. flow through the same dispatch.
A future enhancement can plumb the upper-layer 5-tuple
through and refine the granularity at the socket layer;
the Phase-1 (src, dst) approximation satisfies RFC 6437
§3's per-flow stability requirement and gives uniform
distribution via the secret-keyed hash.

pytcp/protocols/ip6/ip6__flow_label.py

ver 3.0.9
"""

import hashlib

from net_addr import Ip6Address


def compute_ip6_flow_label(*, src: Ip6Address, dst: Ip6Address) -> int:
    """
    Compute a 20-bit IPv6 Flow Label for the (src, dst) pair.

    The hash uses BLAKE2s keyed by the stack's
    'IP6__FLOW_SECRET' (16 random bytes generated at stack
    import). Repeat invocations with the same (src, dst)
    pair return the same label; different pairs return
    different labels with overwhelming probability across
    the 20-bit output space.

    Reference: RFC 6437 §3 (Flow Label generation
    requirements). RFC 8200 §3 (Flow Label is 20 bits).
    """

    # Imported lazily to avoid circular import at stack
    # boot time (pytcp.stack imports many lib modules and
    # this module reads stack-level state).
    from pytcp import stack

    payload = bytes(src) + bytes(dst)
    digest = hashlib.blake2s(payload, key=stack.IP6__FLOW_SECRET, digest_size=4).digest()
    # Fold the 32-bit digest to 20 bits by masking; the
    # output space is uniform across [0, 2^20).
    return int.from_bytes(digest, "big") & 0xFFFFF
