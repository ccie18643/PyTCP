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
This module contains the ICMP runtime support constants shared between
v4 and v6 — the outbound-error rate-limiter sysctl knobs that drive
RFC 1812 §4.3.2.8 / RFC 4443 §2.4(f) compliance. Both knobs are
operator-tunable at boot via 'stack.init(sysctls={...})' or at runtime
via 'pytcp.stack.sysctl["icmp.error...."] = N'. Runtime callers MUST
read the values via qualified module access (e.g.
'icmp__constants.ICMP__ERROR__RATE_PPS') so each read re-resolves
through the backing module attribute the registry writes.

pytcp/protocols/icmp/icmp__constants.py

ver 3.0.9
"""

# Maximum sustained rate at which the stack will originate ICMP error
# messages, in packets per second. RFC 1812 §4.3.2.8 / RFC 4443 §2.4(f)
# require some form of rate limit; PyTCP picks a token-bucket. Linux
# exposes a comparable knob as 'net.ipv4.icmp_ratelimit' (in ms per
# token; PyTCP uses pps for directness — divide 1000 by the PyTCP
# value to get the Linux-equivalent period).
ICMP__ERROR__RATE_PPS = 100

# Maximum burst size for the ICMP error rate limiter, in tokens. A
# burst of this many error generations is permitted at a cold start
# or after an idle period; sustained rate is capped at the rate-pps
# knob above. Linux exposes 'net.ipv4.icmp_msgs_burst' (5.x kernels).
ICMP__ERROR__BURST = 50


# Sysctl registration. Both constants are policy knobs, operator-
# tunable at boot via 'stack.init(sysctls={"icmp.error.X": ...})' or
# at runtime via 'pytcp.stack.sysctl["icmp.error.X"] = N'.
from pytcp.stack.sysctl import is_positive_int, register  # noqa: E402

register(
    key="icmp.error.rate_pps",
    module_name=__name__,
    attr="ICMP__ERROR__RATE_PPS",
    default=ICMP__ERROR__RATE_PPS,
    validator=is_positive_int("icmp.error.rate_pps"),
    description=(
        "RFC 1812 §4.3.2.8 / RFC 4443 §2.4(f) outbound ICMP-error token-bucket"
        " sustained rate, in packets per second (Linux 'net.ipv4.icmp_ratelimit'"
        " analogue; period_ms = 1000 / value)."
    ),
)
register(
    key="icmp.error.burst",
    module_name=__name__,
    attr="ICMP__ERROR__BURST",
    default=ICMP__ERROR__BURST,
    validator=is_positive_int("icmp.error.burst"),
    description=(
        "RFC 1812 §4.3.2.8 / RFC 4443 §2.4(f) outbound ICMP-error token-bucket"
        " burst capacity, in tokens (Linux 'net.ipv4.icmp_msgs_burst')."
    ),
)
