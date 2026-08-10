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
This module contains integration tests for the TCP options handling
in the 'TcpSession' state machine: MSS clamping (above and below
the legal range), unknown options, and SACK-permitted handling per
RFC 9293 §3.7.1 / RFC 6691 / RFC 2018.

The WSCALE-when-not-advertised rule is covered by
'data_transfer__window.py' scenario #2.

Reference RFCs:
    RFC 9293 §3.7.1     Maximum Segment Size Option
    RFC 6691            TCP Options and Maximum Segment Size
    RFC 879             The TCP Maximum Segment Size and Related
                        Topics (TCP__MIN_MSS = 536)
    RFC 2018            TCP Selective Acknowledgment Options

pytcp/tests/integration/protocols/tcp/test__tcp__session__options.py

ver 3.0.9
"""

from net_addr import Ip4Address
from net_proto.protocols.tcp.tcp__header import TCP__MIN_MSS
from pytcp.protocols.tcp.tcp__enums import FsmState, SysCall
from pytcp.tests.lib.network_testcase import (
    HOST_A__IP4_ADDRESS,
    STACK__IP4_HOST,
)
from pytcp.tests.lib.tcp_segment_factory import build_tcp4
from pytcp.tests.lib.tcp_testcase import TcpTestCase

# Deterministic addressing.
STACK__IP: Ip4Address = STACK__IP4_HOST.address
STACK__PORT: int = 12345
PEER__IP: Ip4Address = HOST_A__IP4_ADDRESS
PEER__PORT: int = 80

# Initial sequence numbers chosen well clear of the 32-bit wrap.
LOCAL__ISS: int = 0x0000_1000
PEER__ISS: int = 0x0000_2000

# Peer's advertised receive window on its SYN+ACK reply.
PEER__WIN: int = 64240


class TestTcpSession__Options(TcpTestCase):
    """
    Integration tests for TCP options handling: MSS clamping,
    unknown options, SACK-permitted, etc.
    """

    def test__options__peer_mss_zero_clamped_to_tcp_min_mss(self) -> None:
        """
        Ensure that a peer SYN+ACK carrying MSS=0 results in
        '_snd_mss' being clamped to 'TCP__MIN_MSS' (536), not
        accepted as zero.

        Reference: RFC 6691 §2 (default 536-byte SMSS floor).
        Reference: RFC 9293 §3.7.1 (MSS option semantics).
        """

        session = self._make_active_session(iss=LOCAL__ISS)
        session.tcp_fsm(syscall=SysCall.CONNECT)
        self._advance(ms=1)

        peer_syn_ack_mss_zero = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS,
            ack=LOCAL__ISS + 1,
            flags=("SYN", "ACK"),
            win=PEER__WIN,
            mss=0,
        )
        self._drive_rx(frame=peer_syn_ack_mss_zero)

        self.assertIs(
            session.state,
            FsmState.ESTABLISHED,
            msg="Setup precondition: handshake must complete to ESTABLISHED.",
        )
        self.assertEqual(
            session._win.snd_mss,
            TCP__MIN_MSS,
            msg=(
                f"Peer's MSS=0 must be clamped to TCP__MIN_MSS "
                f"({TCP__MIN_MSS}), not accepted verbatim. RFC 6691 "
                "§2 mandates 536 as the SMSS floor; MSS=0 is "
                "nonsensical and must be treated as 'option absent' "
                "for the floor purposes. Without the clamp, "
                "'_transmit_data's 'min(self._win.snd_mss, ...)' produces "
                "'transmit_data_len=0' and the session can never send "
                "any application data."
            ),
        )

    def test__options__peer_mss_above_local_mtu_clamped_to_mtu_minus_40(self) -> None:
        """
        Ensure that a peer SYN+ACK carrying an MSS larger
        than our local interface MTU minus the IPv4+TCP
        header overhead (40 bytes) results in '_snd_mss'
        being clamped to the local ceiling, preserving the
        invariant that no segment we transmit will ever
        exceed our path MTU.

        Reference: RFC 6691 §2 (MSS calculation from MTU).
        """

        session = self._make_active_session(iss=LOCAL__ISS)
        session.tcp_fsm(syscall=SysCall.CONNECT)
        self._advance(ms=1)

        peer_jumbo_mss = 9000
        peer_syn_ack_jumbo = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS,
            ack=LOCAL__ISS + 1,
            flags=("SYN", "ACK"),
            win=PEER__WIN,
            mss=peer_jumbo_mss,
        )
        self._drive_rx(frame=peer_syn_ack_jumbo)

        self.assertIs(
            session.state,
            FsmState.ESTABLISHED,
            msg="Setup precondition: handshake must complete to ESTABLISHED.",
        )

        # 'stack.interface_mtu' is 1500 in the harness (set by
        # 'TcpTestCase.setUp'). The IPv4+TCP header overhead
        # is 40 bytes, so the effective MSS ceiling is 1460.
        expected_snd_mss = 1500 - 40
        self.assertEqual(
            session._win.snd_mss,
            expected_snd_mss,
            msg=(
                f"Peer's MSS={peer_jumbo_mss} must be clamped down "
                f"to 'mtu - 40' = {expected_snd_mss} so we never emit "
                "segments larger than our local link can carry "
                "without fragmentation. RFC 6691 §3 / RFC 9293 "
                "§3.7.1."
            ),
        )

    def test__options__peer_sack_permitted_on_inbound_syn_silently_ignored(self) -> None:
        """
        Ensure that a peer SYN+ACK carrying the
        SACK-Permitted option is processed normally without
        enabling SACK on our side when we did not advertise
        SACK-Permitted on our outbound SYN; the bilateral
        negotiation does not complete and peer's offer is
        silently ignored.

        Reference: RFC 2018 §2 (SACK-Permitted bilateral negotiation).
        """

        session = self._make_active_session(iss=LOCAL__ISS)
        # Mirror the WSCALE asymmetric-guard pattern: the modern
        # default flips '_advertise_sack' to True, but this scenario
        # specifically tests "we did not advertise SACK-Permitted -
        # peer's offer is silently ignored", so opt out before
        # CONNECT.
        session._advertise.sack = False
        session.tcp_fsm(syscall=SysCall.CONNECT)

        # Inspect our outbound SYN.
        syn_tx = self._advance(ms=1)
        self.assertEqual(
            len(syn_tx),
            1,
            msg="Setup precondition: outbound SYN must fire on the first tick.",
        )
        syn_probe = self._parse_tx(syn_tx[0])
        self._assert_segment(
            syn_probe,
            flags=frozenset({"SYN"}),
            sackperm=False,
        )

        # Peer SYN+ACK with SACK-Permitted option.
        peer_syn_ack_with_sack = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS,
            ack=LOCAL__ISS + 1,
            flags=("SYN", "ACK"),
            win=PEER__WIN,
            mss=1460,
            sackperm=True,
        )
        self._drive_rx(frame=peer_syn_ack_with_sack)

        self.assertIs(
            session.state,
            FsmState.ESTABLISHED,
            msg=(
                "Handshake must complete normally despite peer's "
                "SACK-Permitted offer - the option is silently "
                "ignored, not rejected."
            ),
        )

        # Application sends data so we emit a post-handshake segment.
        session._cc.snd_ewn = PEER__WIN
        session.send(data=b"X")
        data_tx = self._advance(ms=1)
        self.assertEqual(
            len(data_tx),
            1,
            msg="Application data must produce exactly one outbound segment.",
        )

        # Outbound data segment must NOT carry SACK-Permitted.
        data_probe = self._parse_tx(data_tx[0])
        self._assert_segment(
            data_probe,
            sackperm=False,
        )
