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

ver 3.0.8
"""

# RFC 3810 §8 forced MLD Host Compatibility Mode (the IPv6 analogue of
# Linux 'net.ipv4.conf.*.force_igmp_version', which has no shipped IPv6
# counterpart — this is a PyTCP parity extension): 0 = automatic version
# fallback (track the querier per §8.2.1), 1/2 = pin the host to MLDv1 /
# MLDv2 regardless of the queriers heard.
MLD__FORCE_VERSION = 0

# Sysctl registration. The constant above is a policy knob,
# operator-tunable at boot via 'stack.init(sysctls={...})' or at
# runtime via 'pytcp.stack.sysctl["mld.version"] = N'.
from pytcp.stack.sysctl import (  # noqa: E402
    is_int_in_range,
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
