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
This module contains the RFC 6582 NewReno fast-recovery cwnd
deflation helper.

RFC 6582 §3 step 3b specifies the response to a partial
cumulative ACK during fast recovery:

    "Deflate the congestion window by the amount of new data
     acknowledged by the cumulative acknowledgment field. If
     the partial ACK acknowledges at least one SMSS of new
     data, then add back SMSS bytes to the congestion
     window."

The 'add back' compensates for the SMSS-sized retransmit the
sender will fire next: cwnd accounting represents 'segments
in flight that the network has not yet consumed', so when
the receiver acknowledges a chunk of bytes the sender's view
of in-flight bytes drops by that amount. Adding back SMSS
preserves room for the next-gap retransmit per §3 step 3b
clause 1.

The helper exposes the formula as a pure function on
'(cwnd, bytes_acked, smss)'. The TcpSession integration
(in '_process_ack_packet') consumes it inside the
SND.UNA-advancement gate when the session is in fast
recovery and the cumulative ACK has not yet reached the
RecoveryPoint marker.

pytcp/protocols/tcp/tcp__newreno.py

ver 3.0.10
"""


def partial_cum_ack_deflate(cwnd: int, bytes_acked: int, smss: int) -> int:
    """
    Compute the post-deflation cwnd value for an in-recovery
    partial cumulative ACK per RFC 6582 §3 step 3b.

    Algorithm:
        new_cwnd = max(smss, cwnd - bytes_acked)
        if bytes_acked >= smss:
            new_cwnd += smss

    The 'max(smss, ...)' floor prevents the deflation from
    collapsing cwnd below 1 SMSS (the canonical RFC 5681 LW
    floor used during RTO recovery). Without the floor, a
    very large 'bytes_acked' could drive cwnd to zero or
    negative, freezing the session.

    Parameters:
        cwnd:         current cwnd value (bytes; pre-deflation)
        bytes_acked:  amount of new data acknowledged by the
                      partial cumulative ACK (bytes)
        smss:         sender's MSS (SMSS) - both the deflation
                      floor and the add-back amount

    Returns: post-deflation cwnd value (bytes).
    """

    assert cwnd >= 0, f"'cwnd' must be non-negative; got {cwnd!r}"
    assert bytes_acked >= 0, f"'bytes_acked' must be non-negative; got {bytes_acked!r}"
    assert smss > 0, f"'smss' must be positive; got {smss!r}"

    new_cwnd = max(smss, cwnd - bytes_acked)
    if bytes_acked >= smss:
        new_cwnd += smss
    return new_cwnd
