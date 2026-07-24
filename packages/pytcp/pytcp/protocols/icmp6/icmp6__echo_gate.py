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
This module contains the ICMPv6 Echo Reply emission gate. ICMPv6
deliberately diverges from the ICMPv4 Smurf-mitigation rule: replies
to multicast Echo Requests are explicitly permitted by the spec,
with appropriate src-address selection performed by the TX path.
This module is the canonical home for any future ICMPv6-specific
Echo emission policy (e.g. rate limiting on Echo Reply, src-address
selection rules).

pytcp/protocols/icmp6/icmp6__echo_gate.py

ver 3.0.8
"""


def should_emit_echo_reply() -> bool:
    """
    Return True if an ICMPv6 Echo Reply may be sent. Currently
    unconditional: replies to multicast Echo Requests are permitted.

    Reference: RFC 4443 §4.2 (ICMPv6 Echo Reply emission).
    """

    return True
