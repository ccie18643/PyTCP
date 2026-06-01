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
This module contains the IPv4 runtime configuration constants
governing host-level outbound TX behaviour — the policy knobs
the stack TX path reads when emitting IPv4 datagrams.

pytcp/protocols/ip4/ip4__constants.py

ver 3.0.8
"""

# RFC 1122 §3.2.1.7 host-default TTL for outbound IPv4 unicast
# datagrams. The RFC requires the per-datagram TTL field to be
# settable by the transport layer (which PyTCP exposes via the
# 'ip4__ttl' kwarg on '_phtx_ip4') and "When a fixed TTL value
# is used, it MUST be configurable." The qualified-module read
# pattern in 'packet_handler__ip4__tx.py' resolves this
# attribute on every emission so the 'ip4.default_ttl' sysctl
# override is observable on the wire without a stack restart.
# Multicast destinations are independently pinned at TTL=1 per
# RFC 1112 §6.1 and do NOT consult this knob.
IP4__DEFAULT_TTL = 64

# RFC 919 §1 / RFC 922 §3 outbound broadcast emission policy.
# Default 0: outbound datagrams to 255.255.255.255 or a
# subnet-directed broadcast address are dropped at TX time
# unless the caller is the RFC 2131 §3.1 DHCP-client path
# (src=0.0.0.0, UDP sport=68/dport=67), which always bypasses
# the gate because a client cannot complete a lease without
# broadcasting DHCPDISCOVER. The Linux equivalent for socket-
# originated broadcast is per-socket 'SO_BROADCAST' (default
# 0); the sysctl gives an operator a single dial that gates
# every broadcast-capable consumer at the IPv4 layer.
#
# Per-interface storage — 'dict[str, int]' keyed by interface
# name with a mandatory '"default"' slot. Operator addresses
# 'ip4.<ifname>.allow_broadcast' or 'ip4.default.allow_broadcast';
# the TX consumer reads through 'sysctl_iface.get_for_iface'
# with the sending interface's name. Plan:
# docs/refactor/sysctl_per_interface.md.
IP4__ALLOW_BROADCAST: dict[str, int] = {"default": 0}


def _is_ip4_default_ttl(value: object) -> None:
    """
    Reject values outside the integer range 1..255. TTL=0 is
    explicitly forbidden by RFC 1122 §3.2.1.7 "A host MUST NOT
    send a datagram with a Time-to-Live (TTL) value of zero,"
    so the operator must not be able to set the default to a
    value that would violate the spec on every emitted packet.
    The 256 ceiling enforces the 8-bit wire field (RFC 791
    §3.1). Booleans are rejected too — 'isinstance(True, int)'
    is True in Python and would silently slip through.
    """

    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 255:
        raise ValueError(
            f"sysctl 'ip4.default_ttl' must be an int in [1, 255]; got {value!r}",
        )


def _is_ip4_allow_broadcast(value: object) -> None:
    """
    Reject values outside the boolean set {0, 1}. Booleans are
    rejected explicitly — 'isinstance(True, int)' is True in
    Python — so the gate state is unambiguous int-valued, not
    Python-truthy. The two values match the Linux
    'net.ipv4.conf.<iface>.bc_forwarding' shape.
    """

    if isinstance(value, bool) or not isinstance(value, int) or value not in (0, 1):
        raise ValueError(
            f"sysctl 'ip4.allow_broadcast' must be 0 or 1; got {value!r}",
        )


# Sysctl registration. The IPv4 policy knobs are tuned by the
# operator via 'stack.init(sysctls={"ip4.X": N})' at boot or
# 'pytcp.stack.sysctl["ip4.X"] = N' at runtime.
from pytcp.stack.sysctl import register  # noqa: E402

register(
    key="ip4.default_ttl",
    module_name=__name__,
    attr="IP4__DEFAULT_TTL",
    default=IP4__DEFAULT_TTL,
    validator=_is_ip4_default_ttl,
    description="RFC 1122 §3.2.1.7 — host-default TTL for outbound IPv4 unicast datagrams (1..255).",
)
register(
    key="ip4.allow_broadcast",
    module_name=__name__,
    attr="IP4__ALLOW_BROADCAST",
    default=IP4__ALLOW_BROADCAST["default"],
    validator=_is_ip4_allow_broadcast,
    description=(
        "Linux 'net.ipv4.conf.<iface>.bc_forwarding' — gate outbound "
        "broadcast emission (0=deny, 1=allow); DHCP-client path bypasses."
    ),
    interface_scope=True,
)
