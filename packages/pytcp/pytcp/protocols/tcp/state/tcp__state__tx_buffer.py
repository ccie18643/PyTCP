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
This module contains the per-session TX-buffer state container,
covering the application-write byte buffer, the seq-anchor used
to map buffer indexes to TCP sequence numbers, and the
fast-retransmit dup-ACK request counter.

pytcp/protocols/tcp/state/tcp__state__tx_buffer.py

ver 3.0.8
"""

from dataclasses import dataclass, field

from pytcp.protocols.tcp.tcp__seq import Seq32, add32


@dataclass(slots=True)
class TxBufferState:
    """
    Per-session TX-buffer state. Owned by 'TcpSession'; mutated
    by the application 'send' syscall (extends 'buffer'), by the
    TX dispatch path ('seq_mod' bumps for SYN/FIN), and by the
    cum-ACK drain hook ('drain' both shrinks the buffer and
    advances the anchor).

    Note: the 'tx_buffer_una' / 'tx_buffer_nxt' indexes derived
    from this state stay as properties on TcpSession because
    they bridge SendSeqState's una/nxt with this dataclass's
    seq_mod anchor.
    """

    # Application-write byte buffer. Bytes accumulate via the
    # SEND syscall and drain via the cum-ACK path once peer
    # has acknowledged them.
    buffer: bytearray = field(default_factory=bytearray)

    # Seq-anchor for buffer-index ↔ sequence-number mapping.
    # 'tx_buffer_una = (snd_una - seq_mod) & 0xFFFFFFFF' is the
    # leftmost still-unacked byte's buffer index. Advances by
    # the drained byte count on every cum-ACK and by
    # 'flag_syn + flag_fin' on every SYN / FIN emission so the
    # seq-space consumed by control flags doesn't shift the
    # buffer-index baseline.
    seq_mod: Seq32 = 0

    # RFC 5681 §3.2 fast-retransmit dup-ACK counter. Maps
    # outbound seq -> dup-ACK count for that seq; when count
    # reaches DUP_ACK_THRESHOLD, fast-retransmit fires for the
    # corresponding segment. Pruned on cum-ACK that covers the
    # tracked seq.
    retransmit_request_counter: dict[int, int] = field(default_factory=dict)

    def drain(self, *, bytes_count: int) -> None:
        """
        Remove 'bytes_count' bytes from the front of the buffer
        and advance 'seq_mod' modularly by the same amount so
        the buffer-index ↔ seq-number mapping stays coherent.

        Reference: RFC 9293 §3.4 (modular seq anchor).
        """

        del self.buffer[:bytes_count]
        self.seq_mod = add32(self.seq_mod, bytes_count)

    def bump_seq_mod_for_flags(self, *, flag_syn: bool, flag_fin: bool) -> None:
        """
        Advance 'seq_mod' modularly past the seq consumed by an
        outbound SYN and/or FIN. Each flag consumes exactly one
        seq; raw '+=' would let seq_mod escape the 32-bit range
        past the wrap.

        Reference: RFC 9293 §3.4 (modular wrap).
        """

        self.seq_mod = add32(self.seq_mod, flag_syn, flag_fin)
