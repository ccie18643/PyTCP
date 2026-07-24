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
This module contains the RFC 3927 IPv4 Link-Local autoconfig
runtime configuration constants — RFC 3927 §9 retry-loop
timing knobs registered as 'pytcp.stack.sysctl' sysctls so the
operator can tune them at boot or runtime.

Phase 4 (DHCP coordination) will add
'ip4_link_local.dhcp_fallback_timeout_ms'; Phase 6 (optional
persistence) will add 'ip4_link_local.cache_path'.

pytcp/protocols/ip4/link_local/link_local__constants.py

ver 3.0.8
"""

# RFC 3927 §9 MAX_CONFLICTS — the number of consecutive probe
# conflicts the autoconfig client will tolerate before
# entering the RATE_LIMIT_INTERVAL cool-down. The default of
# 10 matches the RFC; operators of constrained embedded
# targets may tighten / loosen this via the sysctl.
IP4_LINK_LOCAL__MAX_CONFLICTS: int = 10

# RFC 3927 §9 RATE_LIMIT_INTERVAL — the cool-down (in seconds)
# the autoconfig client sleeps after MAX_CONFLICTS conflicts
# before resetting the counter and retrying. The default of
# 60 seconds matches the RFC.
IP4_LINK_LOCAL__RATE_LIMIT_INTERVAL: int = 60

# RFC 3927 §1.9 / §2.11 DHCP-fallback window — the number of
# milliseconds the autoconfig client waits after DHCP fails to
# acquire a lease before claiming a link-local address. The
# default of 0 means "feature off — link-local runs eagerly,
# independent of DHCP state". Setting to a positive value
# enables the §1.9 fallback model: while DHCP is bound, the
# link-local address is released; on continuous DHCP-failure
# for this many milliseconds, link-local activates.
#
# Linux comparison: dhcpcd's 'ipv4ll' fires after the
# DISCOVER 'timeout' (default 30 s); systemd-networkd's
# 'LinkLocalAddressing=fallback' has its own internal timer.
IP4_LINK_LOCAL__DHCP_FALLBACK_TIMEOUT_MS: int = 0


# Sysctl registration. Both knobs are policy (Linux exposes
# the equivalent under '/proc/sys/net' in autoipd-style
# userspace daemons), tunable at boot via
# 'stack.init(sysctls={"ip4_link_local.X": N})' or at runtime
# via 'pytcp.stack.sysctl["ip4_link_local.X"] = N'.
from pytcp.stack.sysctl import is_non_negative_int, is_positive_int, register  # noqa: E402

register(
    key="ip4_link_local.max_conflicts",
    module_name=__name__,
    attr="IP4_LINK_LOCAL__MAX_CONFLICTS",
    default=IP4_LINK_LOCAL__MAX_CONFLICTS,
    validator=is_positive_int("ip4_link_local.max_conflicts"),
    description="RFC 3927 §9 MAX_CONFLICTS — consecutive probe conflicts before rate-limit cool-down.",
)
register(
    key="ip4_link_local.rate_limit_interval_s",
    module_name=__name__,
    attr="IP4_LINK_LOCAL__RATE_LIMIT_INTERVAL",
    default=IP4_LINK_LOCAL__RATE_LIMIT_INTERVAL,
    validator=is_positive_int("ip4_link_local.rate_limit_interval_s"),
    description="RFC 3927 §9 RATE_LIMIT_INTERVAL — cool-down between conflict bursts (seconds).",
)
register(
    key="ip4_link_local.dhcp_fallback_timeout_ms",
    module_name=__name__,
    attr="IP4_LINK_LOCAL__DHCP_FALLBACK_TIMEOUT_MS",
    default=IP4_LINK_LOCAL__DHCP_FALLBACK_TIMEOUT_MS,
    validator=is_non_negative_int("ip4_link_local.dhcp_fallback_timeout_ms"),
    description="RFC 3927 §1.9 / §2.11 DHCP-fallback window (ms); 0 = feature off / eager link-local.",
)
