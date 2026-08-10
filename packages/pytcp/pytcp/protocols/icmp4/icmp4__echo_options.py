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
This module contains the IPv4 Echo Reply options-echo helper.

RFC 1122 §3.2.2.6 mandates that an ICMPv4 Echo Reply MUST echo
all options received in the Echo Request, with one transformation:
the IP source-route options (LSRR / SSRR, RFC 791 §3.1) MUST be
reversed before being used to send the response. All other
options (NOP, EOL, Record Route, Timestamp, Security, ...) are
echoed verbatim — Echo Reply is not a forwarded packet, so
record-route slots and timestamp entries are preserved as-is.

pytcp/protocols/icmp4/icmp4__echo_options.py

ver 3.0.10
"""

from typing import cast

from net_proto import (
    IP4__OPTION__LSRR__POINTER_BASE,
    IP4__OPTION__SSRR__POINTER_BASE,
    Ip4Option,
    Ip4OptionLsrr,
    Ip4Options,
    Ip4OptionSsrr,
)


def echo_reply_options(inbound: Ip4Options, /) -> Ip4Options:
    """
    Build the IPv4 options for an Echo Reply from the inbound Echo
    Request's options. Source-route options (LSRR / SSRR) are
    reversed; everything else is echoed verbatim.

    Reference: RFC 1122 §3.2.2.6 (Echo Reply MUST echo all options;
    LSRR/SSRR MUST be reversed).
    Reference: RFC 791 §3.1 (Source Routing wire format).
    """

    reply_options: list[Ip4Option] = []

    for option in inbound:
        match option:
            case Ip4OptionLsrr():
                reply_options.append(
                    Ip4OptionLsrr(
                        pointer=IP4__OPTION__LSRR__POINTER_BASE,
                        route=list(reversed(option.route)),
                    )
                )
            case Ip4OptionSsrr():
                reply_options.append(
                    Ip4OptionSsrr(
                        pointer=IP4__OPTION__SSRR__POINTER_BASE,
                        route=list(reversed(option.route)),
                    )
                )
            case _:
                reply_options.append(cast(Ip4Option, option))

    return Ip4Options(*reply_options)
