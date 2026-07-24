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


# pylint: disable=protected-access
# pyright: reportPrivateUsage=false


"""
Integration tests for the RFC 1191 §6.5 retransmit walkback on PMTU
shrink — when an inbound Frag-Needed shrinks snd_mss while data is
in flight at the old (larger) MSS, the in-flight oversized segments
are marked lost and snd_nxt is rewound to snd_una so the next timer
tick re-emits at the new (smaller) MSS rather than waiting for RTO
to recover.

pytcp/tests/integration/protocols/tcp/test__tcp__session__pmtu_walkback.py

ver 3.0.8
"""

from net_addr import Ip4Address
from net_proto import (
    Icmp4Assembler,
    Icmp4DestinationUnreachableCode,
    Icmp4MessageDestinationUnreachable,
    Ip4Assembler,
    TcpAssembler,
)
from pytcp.protocols.tcp.session import TcpSession
from pytcp.tests.lib.network_testcase import (
    HOST_A__IP4_ADDRESS,
    STACK__IP4_HOST,
)
from pytcp.tests.lib.tcp_testcase import TcpTestCase

STACK__IP: Ip4Address = STACK__IP4_HOST.address
PEER__IP: Ip4Address = HOST_A__IP4_ADDRESS
LOCAL__ISS: int = 0x0000_1000
PEER__ISS: int = 0x9000_0000

# Wire MSS — peer's offer in the SYN-ACK seeds the local snd_mss.
INITIAL_PEER_MSS: int = 1460
# Frag-Needed advertises a tight path MTU; new snd_mss = MTU - 40.
NEW_PATH_MTU: int = 600
NEW_SND_MSS: int = NEW_PATH_MTU - 40  # IPv4(20) + TCP(20)


def _build_frag_needed_for_session(*, mtu: int, embedded_seq: int, sport: int, dport: int) -> bytes:
    """
    Build an Ethernet/IPv4/ICMPv4 Frag-Needed frame whose embedded
    data is an IPv4+TCP header for the (STACK -> PEER : sport->dport)
    flow at the given seq, so the RFC 5927 §4 sequence-in-window
    guard accepts it.
    """

    embedded_tcp = bytes(
        Ip4Assembler(
            ip4__src=STACK__IP,
            ip4__dst=PEER__IP,
            ip4__payload=TcpAssembler(
                tcp__sport=sport,
                tcp__dport=dport,
                tcp__seq=embedded_seq,
                tcp__flag_syn=True,
            ),
        )
    )
    icmp = Icmp4Assembler(
        icmp4__message=Icmp4MessageDestinationUnreachable(
            code=Icmp4DestinationUnreachableCode.FRAGMENTATION_NEEDED,
            mtu=mtu,
            data=embedded_tcp,
        ),
    )
    ip4 = bytes(
        Ip4Assembler(
            ip4__src=PEER__IP,
            ip4__dst=STACK__IP,
            ip4__payload=icmp,
        )
    )
    return b"\x02\x00\x00\x00\x00\x07\x02\x00\x00\x00\x00\x91\x08\x00" + ip4


class TestTcpPmtuWalkback(TcpTestCase):
    """
    The RFC 1191 §6.5 PMTU retransmit-walkback tests.
    """

    def _make_established_with_data_in_flight(self, *, payload_size: int) -> TcpSession:
        """
        Drive a session to ESTABLISHED with peer_mss=INITIAL_PEER_MSS,
        queue 'payload_size' bytes for transmission, advance one timer
        tick so the data hits the wire as segments at the initial MSS.
        Returns the post-send session.
        """

        session = self._drive_handshake_to_established(
            iss=LOCAL__ISS,
            peer_iss=PEER__ISS,
            peer_mss=INITIAL_PEER_MSS,
        )
        session.send(data=b"X" * payload_size)
        self._advance(ms=1)
        return session

    def test__tcp__pmtu_walkback__rewinds_snd_nxt_to_snd_una(self) -> None:
        """
        Ensure an inbound Frag-Needed that shrinks snd_mss while
        oversize segments are in flight rewinds snd_nxt back to
        snd_una, so the next timer tick re-emits from snd_una at the
        new MSS rather than waiting for RTO.

        Reference: RFC 1191 §6.5 (active retransmit at new MSS on
        PMTU shrink, optional optimisation over passive RTO recovery).
        """

        session = self._make_established_with_data_in_flight(payload_size=4000)

        snd_una_before = session._snd_seq.una
        snd_nxt_before = session._snd_seq.nxt
        self.assertGreater(
            (snd_nxt_before - snd_una_before) & 0xFFFF_FFFF,
            NEW_SND_MSS,
            msg="Setup: in-flight bytes must exceed the new MSS to trigger walkback.",
        )

        self._drive_rx(
            frame=_build_frag_needed_for_session(
                mtu=NEW_PATH_MTU,
                embedded_seq=snd_una_before,
                sport=session._local_port,
                dport=session._remote_port,
            ),
        )

        self.assertEqual(
            session._snd_seq.nxt,
            snd_una_before,
            msg="snd_nxt must be rewound to snd_una after the PMTU shrink.",
        )

    def test__tcp__pmtu_walkback__shrinks_snd_mss(self) -> None:
        """
        Ensure the walkback path still performs the basic snd_mss
        shrink. This is a regression guard: the walkback's rewind
        and the existing snd_mss update must both fire.

        Reference: RFC 9293 §3.7.5 (MSS option update on path-MTU change).
        """

        session = self._make_established_with_data_in_flight(payload_size=4000)

        self._drive_rx(
            frame=_build_frag_needed_for_session(
                mtu=NEW_PATH_MTU,
                embedded_seq=session._snd_seq.una,
                sport=session._local_port,
                dport=session._remote_port,
            ),
        )

        self.assertEqual(
            session._win.snd_mss,
            NEW_SND_MSS,
            msg="snd_mss must shrink to next_hop_mtu - 40 (IPv4 + TCP overhead).",
        )

    def test__tcp__pmtu_walkback__does_not_halve_cwnd(self) -> None:
        """
        Ensure the walkback path does NOT collapse cwnd to 1 SMSS or
        halve ssthresh. Unlike RTO, a PMTU shrink is not a congestion
        signal — the path narrowed but didn't drop packets due to
        congestion. cwnd and ssthresh stay put.

        Reference: RFC 1191 §6.5 (PMTU shrink is not a congestion event).
        """

        session = self._make_established_with_data_in_flight(payload_size=4000)
        cwnd_before = session._cc.cwnd
        ssthresh_before = session._cc.ssthresh

        self._drive_rx(
            frame=_build_frag_needed_for_session(
                mtu=NEW_PATH_MTU,
                embedded_seq=session._snd_seq.una,
                sport=session._local_port,
                dport=session._remote_port,
            ),
        )

        self.assertEqual(
            session._cc.cwnd,
            cwnd_before,
            msg="PMTU walkback must NOT change cwnd (not a congestion event).",
        )
        self.assertEqual(
            session._cc.ssthresh,
            ssthresh_before,
            msg="PMTU walkback must NOT change ssthresh (not a congestion event).",
        )

    def test__tcp__pmtu_walkback__does_not_bump_retransmit_count(self) -> None:
        """
        Ensure the walkback path does NOT advance the
        '_retransmit_count' that gates the R2 connection-abort
        timeout. A PMTU walkback is not a "no progress" event; the
        path just narrowed.

        Reference: RFC 1122 §4.2.3.5 (R2 retransmit-abort floor).
        """

        session = self._make_established_with_data_in_flight(payload_size=4000)
        retransmit_count_before = session._retransmit_count

        self._drive_rx(
            frame=_build_frag_needed_for_session(
                mtu=NEW_PATH_MTU,
                embedded_seq=session._snd_seq.una,
                sport=session._local_port,
                dport=session._remote_port,
            ),
        )

        self.assertEqual(
            session._retransmit_count,
            retransmit_count_before,
            msg="PMTU walkback must NOT bump '_retransmit_count'.",
        )

    def test__tcp__pmtu_walkback__no_inflight__no_rewind(self) -> None:
        """
        Ensure a Frag-Needed received on a quiescent session (no data
        in flight) does NOT rewind snd_nxt — the rewind is a no-op
        when there's nothing to retransmit.

        Reference: RFC 1191 §6.5 (walkback only applies when in-flight
        segments exceed the new MSS).
        """

        session = self._drive_handshake_to_established(
            iss=LOCAL__ISS,
            peer_iss=PEER__ISS,
            peer_mss=INITIAL_PEER_MSS,
        )
        # No send() call — TX buffer is empty, snd_nxt == snd_una.
        snd_nxt_before = session._snd_seq.nxt
        self.assertEqual(
            session._snd_seq.una,
            session._snd_seq.nxt,
            msg="Setup: quiescent session must have snd_una == snd_nxt.",
        )

        self._drive_rx(
            frame=_build_frag_needed_for_session(
                mtu=NEW_PATH_MTU,
                embedded_seq=session._snd_seq.una,
                sport=session._local_port,
                dport=session._remote_port,
            ),
        )

        self.assertEqual(
            session._snd_seq.nxt,
            snd_nxt_before,
            msg="Quiescent session must not have snd_nxt rewound by Frag-Needed.",
        )

    def test__tcp__pmtu_walkback__inflight_already_fits__no_rewind(self) -> None:
        """
        Ensure a Frag-Needed that shrinks snd_mss but does NOT make
        in-flight segments oversize (because the in-flight segments
        are already smaller than the new MSS) is a no-op for the
        rewind path. The shrink still applies; the walkback doesn't
        fire because there's nothing to walk back.

        Reference: RFC 1191 §6.5 (walkback only applies when in-flight
        segments exceed the new MSS).
        """

        # Use a tight initial MSS so the in-flight segments are
        # smaller than NEW_SND_MSS already. Send 100 bytes (< new MSS
        # = 560) so even at the original MSS the single segment fits
        # within the new MSS.
        session = self._drive_handshake_to_established(
            iss=LOCAL__ISS,
            peer_iss=PEER__ISS,
            peer_mss=INITIAL_PEER_MSS,
        )
        session.send(data=b"X" * 100)
        self._advance(ms=1)

        snd_nxt_before = session._snd_seq.nxt
        in_flight = (snd_nxt_before - session._snd_seq.una) & 0xFFFF_FFFF
        self.assertLessEqual(
            in_flight,
            NEW_SND_MSS,
            msg="Setup: in-flight bytes must already fit within the new MSS.",
        )

        self._drive_rx(
            frame=_build_frag_needed_for_session(
                mtu=NEW_PATH_MTU,
                embedded_seq=session._snd_seq.una,
                sport=session._local_port,
                dport=session._remote_port,
            ),
        )

        self.assertEqual(
            session._snd_seq.nxt,
            snd_nxt_before,
            msg=("snd_nxt must NOT be rewound when in-flight segments " "already fit within the new MSS."),
        )
