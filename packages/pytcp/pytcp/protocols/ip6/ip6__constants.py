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
This module contains the IPv6 runtime configuration constants
governing host-level outbound TX behaviour — the policy knobs
the stack TX path reads when emitting IPv6 datagrams.

pytcp/protocols/ip6/ip6__constants.py

ver 3.0.9
"""

# RFC 6437 §3 IPv6 Flow Label auto-generation toggle.
#
# When 1 (default), '_phtx_ip6' computes a 20-bit Flow Label
# per outbound datagram by hashing (src, dst) with the
# stack-wide 'IP6__FLOW_SECRET' — satisfying §3's
# "approximation to discrete uniform distribution" + "same
# value for packets of a given flow" requirements.
#
# When 0, '_phtx_ip6' emits flow=0 (the RFC 8200 §3 "no
# specific flow" form). The integration-test harness sets
# this to 0 so existing golden-byte fixtures continue to
# match; the dedicated RFC-6437-flow-label integration test
# flips it to 1 to exercise the auto-wire.
#
# Linux comparison: 'net.ipv6.flowlabel_state_ranges' /
# '/proc/sys/net/ipv6/flowlabel_consistency'. PyTCP's
# implementation is per-(src, dst), coarser than Linux's
# per-socket but sufficient for §3's per-flow stability
# clause (which explicitly allows coarser flow definitions).
IP6__FLOW_LABEL_GENERATION: int = 1


# RFC 8504 §5.3 extension-header resource-exhaustion limits.
#
# Inbound IPv6 packets with Hop-by-Hop / Destination Options
# extension headers carry a variable-length TLV option list.
# An attacker can craft pathological option lists (thousands
# of Pad1, many unknown options, very long PadN sequences)
# to chew CPU at the receiver. These sysctls cap the
# per-header option count + pad-byte budget so the parser
# refuses anomalous shapes before walking the full option
# stream. Defaults are deliberately permissive (Linux-like)
# so legitimate traffic with reasonable padding is never
# rejected.
#
# Linux comparison: 'net.ipv6.conf.*.parm_validate' and
# the 'hdrincl' option-length checks. PyTCP's three knobs
# carve out the three resource-exhaustion vectors named in
# RFC 8504 §5.3:
#   (a) total option count per header
#   (b) total Pad-byte budget per header
#   (c) unknown-option count per header

# Total option count per HBH / DestOpts header. A normal HBH
# header carries 0-2 options (e.g. Router Alert + PadN). 16
# is well above any legitimate use.
IP6__EXT_HDR_MAX_OPTIONS: int = 16

# Total Pad bytes (Pad1 contributes 1, PadN of length N
# contributes 2 + N) per HBH / DestOpts header. The header
# alignment rule needs at most 7 pad bytes per 8-byte
# boundary; 16 leaves margin for nested-option layouts.
IP6__EXT_HDR_MAX_PAD_BYTES: int = 16

# Unknown options per HBH / DestOpts header. Unknown options
# are normally a transitional / interop artefact; more than
# 2 in a single header is a red flag (RFC 8504 §5.3
# resource-exhaustion mitigation).
IP6__EXT_HDR_MAX_UNKNOWN_OPTIONS: int = 2


# Sysctl registration. The flow-label generation toggle is
# policy — Linux exposes equivalent knobs under
# '/proc/sys/net/ipv6/' — and operators may want to disable
# it on links where downstream forwarding plane treats
# flow=0 as a special-case (older middleboxes, RFC 6437
# §6.1 ECMP/LAG opting-out).
from pytcp.stack.sysctl import is_non_negative_int, register  # noqa: E402

register(
    key="ip6.flow_label_generation",
    module_name=__name__,
    attr="IP6__FLOW_LABEL_GENERATION",
    default=IP6__FLOW_LABEL_GENERATION,
    validator=is_non_negative_int("ip6.flow_label_generation"),
    description="RFC 6437 §3 IPv6 Flow Label auto-generation toggle (0 = emit flow=0; 1 = compute per (src,dst) hash).",
)
register(
    key="ip6.ext_hdr_max_options",
    module_name=__name__,
    attr="IP6__EXT_HDR_MAX_OPTIONS",
    default=IP6__EXT_HDR_MAX_OPTIONS,
    validator=is_non_negative_int("ip6.ext_hdr_max_options"),
    description="RFC 8504 §5.3 max total options per HBH / DestOpts header (0 = unlimited).",
)
register(
    key="ip6.ext_hdr_max_pad_bytes",
    module_name=__name__,
    attr="IP6__EXT_HDR_MAX_PAD_BYTES",
    default=IP6__EXT_HDR_MAX_PAD_BYTES,
    validator=is_non_negative_int("ip6.ext_hdr_max_pad_bytes"),
    description="RFC 8504 §5.3 max total Pad bytes per HBH / DestOpts header (0 = unlimited).",
)
register(
    key="ip6.ext_hdr_max_unknown_options",
    module_name=__name__,
    attr="IP6__EXT_HDR_MAX_UNKNOWN_OPTIONS",
    default=IP6__EXT_HDR_MAX_UNKNOWN_OPTIONS,
    validator=is_non_negative_int("ip6.ext_hdr_max_unknown_options"),
    description="RFC 8504 §5.3 max unknown options per HBH / DestOpts header (0 = unlimited).",
)
