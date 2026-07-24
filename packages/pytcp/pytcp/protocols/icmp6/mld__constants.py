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
This module contains the MLD runtime configuration constants — the
RFC 3810 §8 host compatibility defaults, exposed as policy sysctls.

pytcp/protocols/icmp6/mld__constants.py

ver 3.0.9
"""

# RFC 3810 §8 forced MLD Host Compatibility Mode (the IPv6 analogue of
# Linux 'net.ipv4.conf.*.force_igmp_version', which has no shipped IPv6
# counterpart — this is a PyTCP parity extension): 0 = automatic version
# fallback (track the querier per §8.2.1), 1/2 = pin the host to MLDv1 /
# MLDv2 regardless of the queriers heard.
MLD__FORCE_VERSION = 0

# RFC 3810 §9.1 Robustness Variable (default 2). A host transmits an
# unsolicited state-change Report RV total times (the initial Report plus
# RV-1 retransmits) so the membership change survives the loss of up to
# RV-1 packets. The IPv6 analogue of 'IGMP__ROBUSTNESS_VARIABLE'.
MLD__ROBUSTNESS_VARIABLE = 2

# RFC 3810 §9.11 Unsolicited Report Interval, in milliseconds (the RFC
# default is 1 second). Each state-change-Report retransmit is spaced by
# a value drawn uniformly at random from (0, this interval]. The IPv6
# analogue of 'IGMP__UNSOLICITED_REPORT_INTERVAL__MS'.
MLD__UNSOLICITED_REPORT_INTERVAL__MS = 1000

# RFC 3810 §9.2 Query Interval default (125 s), in milliseconds. An MLDv1
# Query carries no QQIC, so this default is the [Query Interval] term of
# the §9.12 Older Version Querier Present Timeout the host arms when it
# hears such a Query. The IPv6 analogue of 'IGMP__QUERY_INTERVAL__MS'.
MLD__QUERY_INTERVAL__MS = 125_000

# Sysctl registration. Every constant above is a policy knob,
# operator-tunable at boot via 'stack.init(sysctls={...})' or at
# runtime via 'pytcp.stack.sysctl["mld...."] = N'.
from pytcp.stack.sysctl import (  # noqa: E402
    is_int_in_range,
    is_positive_int,
    register,
)

register(
    key="mld.version",
    module_name=__name__,
    attr="MLD__FORCE_VERSION",
    default=MLD__FORCE_VERSION,
    validator=is_int_in_range("mld.version", low=0, high=2),
    description="RFC 3810 §8 forced MLD Host Compatibility Mode — 0 = auto fallback, 1/2 = pin MLDv1/MLDv2.",
)
register(
    key="mld.robustness",
    module_name=__name__,
    attr="MLD__ROBUSTNESS_VARIABLE",
    default=MLD__ROBUSTNESS_VARIABLE,
    validator=is_positive_int("mld.robustness"),
    description="RFC 3810 §9.1 Robustness Variable — unsolicited state-change Report transmission count.",
)
register(
    key="mld.unsolicited_report_interval",
    module_name=__name__,
    attr="MLD__UNSOLICITED_REPORT_INTERVAL__MS",
    default=MLD__UNSOLICITED_REPORT_INTERVAL__MS,
    validator=is_positive_int("mld.unsolicited_report_interval"),
    description="RFC 3810 §9.11 Unsolicited Report Interval — state-change Report retransmit spacing, ms.",
)
register(
    key="mld.query_interval",
    module_name=__name__,
    attr="MLD__QUERY_INTERVAL__MS",
    default=MLD__QUERY_INTERVAL__MS,
    validator=is_positive_int("mld.query_interval"),
    description="RFC 3810 §9.2 Query Interval — [Query Interval] term of the MLDv1 querier-present timeout, ms.",
)
