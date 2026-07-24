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
This module contains the ICMPv4 runtime configuration constants exposed
as policy sysctls.

pytcp/protocols/icmp4/icmp4__constants.py

ver 3.0.9
"""

# Linux 'net.ipv4.icmp_echo_ignore_broadcasts' — when set (1, the
# default), the host does NOT answer an ICMPv4 Echo Request whose IPv4
# destination is a broadcast or multicast address (the Smurf-attack
# mitigation, RFC 1122 §3.2.2.6). Set to 0 to make the host answer such
# requests (sourcing the reply from a unicast address).
ICMP4__ECHO_IGNORE_BROADCASTS = 1

# Sysctl registration. The constant above is a policy knob,
# operator-tunable at boot via 'stack.init(sysctls={...})' or at runtime
# via 'pytcp.stack.sysctl["icmp4.echo_ignore_broadcasts"] = N'.
from pytcp.stack.sysctl import (  # noqa: E402
    is_int_in_range,
    register,
)

register(
    key="icmp4.echo_ignore_broadcasts",
    module_name=__name__,
    attr="ICMP4__ECHO_IGNORE_BROADCASTS",
    default=ICMP4__ECHO_IGNORE_BROADCASTS,
    validator=is_int_in_range("icmp4.echo_ignore_broadcasts", low=0, high=1),
    description=(
        "Linux 'net.ipv4.icmp_echo_ignore_broadcasts' — 1 (default) ignores broadcast/multicast "
        "Echo Requests (Smurf mitigation), 0 answers them from a unicast source."
    ),
)
