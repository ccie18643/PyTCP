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
This module contains the IGMP runtime configuration constants — the
RFC 3376 §8 host timing / robustness defaults, exposed as policy
sysctls.

pytcp/protocols/igmp/igmp__constants.py

ver 3.0.9
"""

# RFC 3376 §8.1 Robustness Variable. The number of times a host
# transmits an unsolicited state-change Report (RV total, i.e. the
# initial Report plus RV-1 retransmits) so the membership change
# survives the loss of up to RV-1 packets. Linux exposes no per-host
# RV knob (it is fixed at 2); PyTCP makes it tunable.
IGMP__ROBUSTNESS_VARIABLE = 2

# RFC 3376 §8.11 Unsolicited Report Interval, in milliseconds (the RFC
# default is 1 second). Each state-change-Report retransmit is spaced
# by a value drawn uniformly at random from (0, this interval].
IGMP__UNSOLICITED_REPORT_INTERVAL__MS = 1000

# Linux 'net.ipv4.igmp_max_memberships' — the maximum number of
# multicast groups a host may join through the membership API
# (the all-systems group 224.0.0.1, joined implicitly at interface
# bring-up, does not count against this limit). Linux defaults to 20.
IGMP__MAX_MEMBERSHIPS = 20

# RFC 3376 §7 forced Host Compatibility Mode (Linux
# 'net.ipv4.conf.*.force_igmp_version'): 0 = automatic version fallback
# (track the querier per §7.2.1), 1/2/3 = pin the host to IGMPv1 /
# IGMPv2 / IGMPv3 regardless of the queriers heard.
IGMP__FORCE_VERSION = 0

# RFC 3376 §8.2 Query Interval default (125 s), in milliseconds. A
# v1/v2 Query carries no QQIC, so this default is the [Query Interval]
# term of the §8.12 Older Version Querier Present Timeout the host arms
# when it hears such a Query. On the querier side (Phase-2 M5b) it is
# also the spacing between steady-state General Queries the querier
# emits and the QQIC it advertises.
IGMP__QUERY_INTERVAL__MS = 125_000

# --- Querier-side timing (Phase-2 M5b router role) -------------------

# RFC 3376 §8.3 Query Response Interval, in milliseconds — the maximum
# response window the querier advertises in the Max Resp Code of a
# General Query (RFC default 10 s). Phase 2: per-interface.
IGMP__QUERY_RESPONSE_INTERVAL__MS = 10_000

# RFC 3376 §8.6 Startup Query Interval, in milliseconds — the spacing
# between the General Queries a newly-elected querier sends at startup
# (RFC default [Query Interval] / 4). Phase 2: per-interface.
IGMP__STARTUP_QUERY_INTERVAL__MS = 31_250

# RFC 3376 §8.7 Startup Query Count — the number of General Queries a
# newly-elected querier sends at startup, spaced by the Startup Query
# Interval (RFC default [Robustness Variable]). Phase 2: per-interface.
IGMP__STARTUP_QUERY_COUNT = 2

# RFC 3376 §8.8 Last Member Query Interval, in milliseconds — the Max
# Resp Time the querier advertises in the Group-Specific Queries it
# sends on a leave, and their spacing (RFC default 1 s). Phase 2:
# per-interface.
IGMP__LAST_MEMBER_QUERY_INTERVAL__MS = 1000

# RFC 3376 §8.9 Last Member Query Count — the number of Group-Specific
# Queries the querier sends on a leave before pruning the group (RFC
# default [Robustness Variable]). Phase 2: per-interface.
IGMP__LAST_MEMBER_QUERY_COUNT = 2

# Linux 'net.ipv4.conf.<iface>.mc_forwarding' — per-interface multicast
# router switch. When set, the interface takes the IGMP querier role
# (election, General Queries, downstream group-membership state). A
# 'dict[str, bool]' keyed by interface name with a mandatory
# '"default"' slot. Default off keeps exact host behaviour — a host is
# not a querier.
IGMP__MC_FORWARDING: dict[str, bool] = {"default": False}

# Sysctl registration. Every constant above is a policy knob,
# operator-tunable at boot via 'stack.init(sysctls={...})' or at
# runtime via 'pytcp.stack.sysctl["igmp...."] = N'.
from pytcp.stack.sysctl import (  # noqa: E402
    is_bool,
    is_int_in_range,
    is_positive_int,
    register,
)

register(
    key="igmp.robustness",
    module_name=__name__,
    attr="IGMP__ROBUSTNESS_VARIABLE",
    default=IGMP__ROBUSTNESS_VARIABLE,
    validator=is_positive_int("igmp.robustness"),
    description="RFC 3376 §8.1 Robustness Variable — unsolicited state-change Report transmission count.",
)
register(
    key="igmp.unsolicited_report_interval",
    module_name=__name__,
    attr="IGMP__UNSOLICITED_REPORT_INTERVAL__MS",
    default=IGMP__UNSOLICITED_REPORT_INTERVAL__MS,
    validator=is_positive_int("igmp.unsolicited_report_interval"),
    description="RFC 3376 §8.11 Unsolicited Report Interval — state-change Report retransmit spacing, ms.",
)
register(
    key="igmp.max_memberships",
    module_name=__name__,
    attr="IGMP__MAX_MEMBERSHIPS",
    default=IGMP__MAX_MEMBERSHIPS,
    validator=is_positive_int("igmp.max_memberships"),
    description="Linux 'net.ipv4.igmp_max_memberships' — max multicast groups joinable via the membership API.",
)
register(
    key="igmp.version",
    module_name=__name__,
    attr="IGMP__FORCE_VERSION",
    default=IGMP__FORCE_VERSION,
    validator=is_int_in_range("igmp.version", low=0, high=3),
    description="RFC 3376 §7 forced Host Compatibility Mode — 0 = auto fallback, 1/2/3 = pin IGMPv1/v2/v3.",
)
register(
    key="igmp.query_interval",
    module_name=__name__,
    attr="IGMP__QUERY_INTERVAL__MS",
    default=IGMP__QUERY_INTERVAL__MS,
    validator=is_positive_int("igmp.query_interval"),
    description="RFC 3376 §8.2 Query Interval (ms) — default term of the §8.12 Older Version Querier Present Timeout.",
)
register(
    key="igmp.query_response_interval",
    module_name=__name__,
    attr="IGMP__QUERY_RESPONSE_INTERVAL__MS",
    default=IGMP__QUERY_RESPONSE_INTERVAL__MS,
    validator=is_positive_int("igmp.query_response_interval"),
    description="RFC 3376 §8.3 Query Response Interval (ms) — querier Max Resp Code window in a General Query.",
)
register(
    key="igmp.startup_query_interval",
    module_name=__name__,
    attr="IGMP__STARTUP_QUERY_INTERVAL__MS",
    default=IGMP__STARTUP_QUERY_INTERVAL__MS,
    validator=is_positive_int("igmp.startup_query_interval"),
    description="RFC 3376 §8.6 Startup Query Interval (ms) — spacing of the querier's startup General Queries.",
)
register(
    key="igmp.startup_query_count",
    module_name=__name__,
    attr="IGMP__STARTUP_QUERY_COUNT",
    default=IGMP__STARTUP_QUERY_COUNT,
    validator=is_positive_int("igmp.startup_query_count"),
    description="RFC 3376 §8.7 Startup Query Count — number of startup General Queries a new querier sends.",
)
register(
    key="igmp.last_member_query_interval",
    module_name=__name__,
    attr="IGMP__LAST_MEMBER_QUERY_INTERVAL__MS",
    default=IGMP__LAST_MEMBER_QUERY_INTERVAL__MS,
    validator=is_positive_int("igmp.last_member_query_interval"),
    description="RFC 3376 §8.8 Last Member Query Interval (ms) — Group-Specific Query max-resp + spacing on leave.",
)
register(
    key="igmp.last_member_query_count",
    module_name=__name__,
    attr="IGMP__LAST_MEMBER_QUERY_COUNT",
    default=IGMP__LAST_MEMBER_QUERY_COUNT,
    validator=is_positive_int("igmp.last_member_query_count"),
    description="RFC 3376 §8.9 Last Member Query Count — Group-Specific Queries sent on leave before pruning.",
)
register(
    key="igmp.mc_forwarding",
    module_name=__name__,
    attr="IGMP__MC_FORWARDING",
    default=IGMP__MC_FORWARDING["default"],
    validator=is_bool("igmp.mc_forwarding"),
    interface_scope=True,
    description="Linux 'net.ipv4.conf.<iface>.mc_forwarding' — per-interface IGMP querier / multicast-router switch.",
)
