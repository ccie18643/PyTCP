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
This module contains the shared IPv4/IPv6 fragment-reassembly flow table.

pytcp/protocols/ip/ip_frag_table.py

ver 3.0.10
"""

import struct
from dataclasses import dataclass
from enum import Enum
from time import time

from net_addr import Buffer
from pytcp.protocols.ip.ip_frag import IpFragData, IpFragFlowId, aggregate_ecn


class IpFragAddOutcome(Enum):
    """
    Tag for the outcome of an 'IpFragTable.add_fragment' call.
    """

    PENDING = "pending"
    COMPLETE = "complete"
    OVERLAP = "overlap"
    DISCARDED = "discarded"
    ECN_MIXED__DROP = "ecn_mixed_drop"


@dataclass(frozen=True, kw_only=True, slots=True)
class IpFragAddResult:
    """
    Tagged result of an 'IpFragTable.add_fragment' call.

    'header' / 'payload' carry the joined datagram bytes when
    'outcome is IpFragAddOutcome.COMPLETE'. Otherwise both are
    empty 'bytes()' sentinels and callers must not consume them.

    'ecn' carries the RFC 3168 §5.3 aggregated ECN codepoint of
    the reassembled datagram when 'outcome is COMPLETE'. On any
    other outcome it is 0 and callers MUST NOT consume it.
    """

    outcome: IpFragAddOutcome
    header: bytes = b""
    payload: bytes = b""
    ecn: int = 0


class IpFragTable:
    """
    Shared IPv4/IPv6 fragment-reassembly flow table.

    Mirrors the Linux 'net/ipv4/inet_fragment.c' shape: a flow
    table keyed by the family-specific 'IpFragFlowId' carrying a
    per-offset fragment store, with a lazy expiry sweep on every
    admission. Family differences (key shape, header rewrite,
    atomic-fragment fast-path) live in the calling handler — this
    table only owns the common machinery.
    """

    _flows: dict[IpFragFlowId, IpFragData]
    _timeout: float

    def __init__(self, *, timeout: float) -> None:
        """
        Initialize the flow table with the given expiry timeout.
        """

        self._flows = {}
        self._timeout = timeout

    @property
    def flows(self) -> dict[IpFragFlowId, IpFragData]:
        """
        Get a live view of the flow store. Mutation by callers is
        permitted and used by tests that backdate a flow's
        timestamp to drive the expiry path.
        """

        return self._flows

    def add_fragment(
        self,
        *,
        flow_id: IpFragFlowId,
        offset: int,
        payload: Buffer,
        flag_mf: bool,
        header: Buffer,
        ecn: int = 0,
    ) -> IpFragAddResult:
        """
        Admit one fragment into the flow store.

        Returns an 'IpFragAddResult' tagged by 'IpFragAddOutcome':

          - PENDING:          the fragment is stored and more are
                              expected (or the offset chain is not
                              yet contiguous).
          - COMPLETE:         the fragment that just arrived
                              completes the datagram; 'header' /
                              'payload' / 'ecn' carry the joined
                              bytes and the aggregated ECN value.
          - OVERLAP:          the fragment overlaps a previously-
                              stored fragment in the same flow; the
                              flow is marked discarded and its
                              payload cleared (RFC 5722 §3 silent-
                              discard).
          - DISCARDED:        the fragment arrived for a flow that
                              was previously marked discarded; it
                              is silently dropped without
                              admission.
          - ECN_MIXED__DROP:  the reassembled datagram's ECN bits
                              cannot be reconciled per RFC 3168
                              §5.3 (Not-ECT mixed with any other
                              codepoint); the flow is removed and
                              callers MUST drop the packet.

        Atomic fragments (offset=0, M=0) bypass the flow store
        entirely and yield COMPLETE on the spot, in isolation
        from any other fragment with the same 'flow_id' (RFC
        8200 §4.5 / RFC 6946 §4). The 'ecn' input is returned
        verbatim on the atomic-fragment path.

        The 'ecn' kwarg carries the ECN codepoint observed on
        this fragment's outer IP header. The table aggregates
        per-fragment values via 'aggregate_ecn' (RFC 3168 §5.3)
        and returns the aggregated codepoint on the COMPLETE
        result.

        The expiry sweep ('time() - timestamp >= timeout' purges
        the flow) runs at the head of every admission, matching
        Linux's lazy-reap model.
        """

        # RFC 8200 §4.5 / RFC 6946 §4 atomic-fragment fast-path.
        # An atomic fragment is the entire datagram; it must
        # never touch the flow store and must process in
        # isolation from any concurrent non-atomic reassembly
        # that happens to share the same source/destination/ID.
        if offset == 0 and not flag_mf:
            return IpFragAddResult(
                outcome=IpFragAddOutcome.COMPLETE,
                header=bytes(header),
                payload=bytes(payload),
                ecn=ecn,
            )

        # Lazy expiry sweep.
        now = time()
        self._flows = {
            flow: self._flows[flow] for flow in self._flows if now - self._flows[flow].timestamp < self._timeout
        }

        # RFC 5722 §3: a fragment arriving for an already-
        # discarded flow is silently dropped.
        if flow_id in self._flows and self._flows[flow_id].discarded:
            return IpFragAddResult(outcome=IpFragAddOutcome.DISCARDED)

        # RFC 5722 §3: detect overlap with any previously-stored
        # fragment in the same flow. Strict reading — exact-
        # duplicate offsets are also overlapping.
        if flow_id in self._flows:
            new_end = offset + len(payload)
            for stored_offset, stored_chunk in self._flows[flow_id].payload.items():
                stored_end = stored_offset + len(stored_chunk)
                if offset < stored_end and stored_offset < new_end:
                    self._flows[flow_id].mark_discarded()
                    return IpFragAddResult(outcome=IpFragAddOutcome.OVERLAP)

        # Insert / update per-offset entry.
        if flow_id in self._flows:
            self._flows[flow_id].payload[offset] = payload
            self._flows[flow_id].ecn[offset] = ecn
        else:
            self._flows[flow_id] = IpFragData(
                header=header,
                payload={offset: payload},
                ecn={offset: ecn},
            )
        if not flag_mf:
            self._flows[flow_id].received_last_frag()

        # Completeness check: last-fragment seen + every byte
        # covered by a contiguous offset chain starting at zero.
        if not self._flows[flow_id].last:
            return IpFragAddResult(outcome=IpFragAddOutcome.PENDING)
        payload_len = 0
        for entry_offset in sorted(self._flows[flow_id].payload):
            if entry_offset > payload_len:
                return IpFragAddResult(outcome=IpFragAddOutcome.PENDING)
            payload_len = entry_offset + len(self._flows[flow_id].payload[entry_offset])

        # RFC 3168 §5.3 ECN aggregation across the per-fragment
        # ECN values observed at admission time. A 'None' return
        # signals "MUST drop" per §5.3's Not-ECT-mixed-with-other
        # rule; the flow is removed from the store before
        # returning so a retransmit can start fresh.
        aggregated_ecn = aggregate_ecn(self._flows[flow_id].ecn.values())
        if aggregated_ecn is None:
            del self._flows[flow_id]
            return IpFragAddResult(outcome=IpFragAddOutcome.ECN_MIXED__DROP)

        # Build the joined payload buffer in offset order.
        joined = bytearray(payload_len)
        for entry_offset in sorted(self._flows[flow_id].payload):
            chunk = self._flows[flow_id].payload[entry_offset]
            struct.pack_into(f"{len(chunk)}s", joined, entry_offset, bytes(chunk))

        header_bytes = bytes(self._flows[flow_id].header)
        del self._flows[flow_id]

        return IpFragAddResult(
            outcome=IpFragAddOutcome.COMPLETE,
            header=header_bytes,
            payload=bytes(joined),
            ecn=aggregated_ecn,
        )
