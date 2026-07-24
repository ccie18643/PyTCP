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
This module contains the per-session handshake-advertise +
post-handshake-active flag container. The 'advertise_*' flags
gate which TCP options the active-open SYN / passive-open
SYN+ACK carries; the post-handshake 'send_sack' flag is the
result of bilateral SACK-Permitted negotiation (its TSopt and
ECE counterparts live on TimestampsState and ClassicEcnState
respectively).

pytcp/protocols/tcp/state/tcp__state__advertise.py

ver 3.0.9
"""

from dataclasses import dataclass


@dataclass(slots=True)
class AdvertiseState:
    """
    Per-session option-advertisement state. Owned by 'TcpSession';
    'advertise_*' flags are set by the application or socket
    layer before CONNECT / LISTEN; 'send_sack' is set by the
    handshake on bilateral negotiation success.
    """

    # RFC 7323 §2.2 outbound SYN / SYN+ACK Timestamps option
    # advertisement gate. Defaults True (modern, throughput-
    # friendly behaviour).
    ts: bool = True

    # RFC 7323 §2.2 outbound SYN / SYN+ACK WSCALE option
    # advertisement gate. Defaults True; allows up to 8 MB
    # advertised window with the canonical Linux default.
    wscale: bool = True

    # RFC 2018 §2 outbound SYN / SYN+ACK SACK-Permitted option
    # advertisement gate. Defaults True.
    sack: bool = True

    # RFC 3168 §6.1.1 ECN-setup SYN / SYN+ACK advertisement
    # gate. Defaults True (RFC 3168 RECOMMENDED).
    ecn: bool = True

    # RFC 9768 §3.1.1 AccECN-setup SYN / SYN+ACK advertisement
    # gate. Defaults True; an AccECN-advertising client falls
    # back to RFC 3168 ECN if peer responds with the ECE-only
    # form.
    accecn: bool = True

    # RFC 7413 §3.1 Fast Open client-side advertisement gate.
    # Defaults True so active-open SYNs carry the TFO option
    # in the cookie-request form.
    fastopen: bool = True

    # RFC 2018 §2 post-handshake bilateral-success flag for
    # SACK. False until the handshake succeeds with both sides
    # advertising SACK-Permitted. Distinct from 'sack' (the
    # "do we offer it on outbound SYN") — this is the "did the
    # negotiation succeed" mirror.
    send_sack: bool = False
