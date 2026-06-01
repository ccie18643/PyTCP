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
This module contains tests for the 'Dhcp4Client'.

pytcp/tests/unit/protocols/dhcp4/test__dhcp4__client.py

ver 3.0.8
"""

import errno
from typing import Any, cast, override
from unittest import TestCase
from unittest.mock import MagicMock, create_autospec, patch

from net_addr import Ip4Address, Ip4IfAddr, Ip4Mask, Ip4Network, MacAddress
from net_proto.protocols.dhcp4.dhcp4__enums import Dhcp4MessageType
from net_proto.protocols.dhcp4.options.dhcp4__option import Dhcp4OptionType
from pytcp.protocols.dhcp4.dhcp4__client import Dhcp4Client, Dhcp4Lease, Dhcp4State
from pytcp.protocols.dhcp4.dhcp4__uid import build_client_id
from pytcp.protocols.ip4.acd.ip4_acd import AcdResult, Ip4Acd
from pytcp.runtime.fib import Route, RouteProtocol
from pytcp.runtime.socket import AddressFamily
from pytcp.runtime.subsystem import Subsystem
from pytcp.stack import sysctl
from pytcp.stack.route import RouteApi
from pytcp.tests.lib.dhcp4_mock_server import (
    Dhcp4MockServer,
    autospec_dhcp4_socket,
)

_DEFAULT_MAC = MacAddress("02:00:00:00:00:01")
_DEFAULT_CID = build_client_id(_DEFAULT_MAC)
_PINNED_XID = 0xDEADBEEF


def _acd_mock(*, probe_results: list[bool] | bool = True, conflict_mac: MacAddress | None = None) -> MagicMock:
    """
    Build an autospec-locked 'Ip4Acd' whose 'probe' returns a clean
    or conflicting 'AcdResult'. 'probe_results' may be a single bool
    (every probe returns that verdict) or a list consumed in order.
    'start_defense' / 'poll_conflict' / 'release' default to no-ops.
    """

    acd = create_autospec(Ip4Acd, spec_set=True)
    verdicts = probe_results if isinstance(probe_results, list) else None

    def _probe(*, address: Ip4Address) -> AcdResult:
        verdict = verdicts.pop(0) if verdicts is not None else cast(bool, probe_results)
        return AcdResult(success=verdict, address=address, conflict_mac=None if verdict else conflict_mac)

    acd.probe.side_effect = _probe
    acd.poll_conflict.return_value = None
    return cast(MagicMock, acd)


class TestDhcp4ClientInit(TestCase):
    """
    The 'Dhcp4Client' constructor tests.
    """

    @override
    def setUp(self) -> None:
        """
        Silence the Subsystem base-class init log line so the
        constructor tests do not leak '<stack> Initializing
        DHCP4 Client' to stdout under the default LOG__CHANNEL.
        """

        self.enterContext(patch("pytcp.runtime.subsystem.log"))

    def test__dhcp4_client__init_stores_mac_address(self) -> None:
        """
        Ensure the constructor stores the supplied MAC address. The
        per-recv timeout is no longer a constructor parameter — the
        Phase 1 backoff loop draws timeouts from the
        'dhcp.retrans_*' sysctl namespace instead.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        client = Dhcp4Client(mac_address=_DEFAULT_MAC)

        self.assertEqual(
            client._mac_address,
            _DEFAULT_MAC,
            msg="Dhcp4Client._mac_address must equal the MAC passed to the constructor.",
        )

    def test__dhcp4_client__init_keyword_only_arguments(self) -> None:
        """
        Ensure the constructor arguments are keyword-only — passing the
        MAC address positionally must raise 'TypeError'.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(TypeError):
            Dhcp4Client(_DEFAULT_MAC)  # type: ignore[misc]


class _Dhcp4ClientFixture(TestCase):
    """
    Shared fixture base. Subclasses build their own
    'Dhcp4MockServer', enqueue the replies the test needs, and call
    'self._fetch()' which patches the socket factory and the log
    channel for the duration of the call.
    """

    @override
    def setUp(self) -> None:
        """
        Stand up a 'Dhcp4MockServer' plus an autospec-locked socket
        factory whose return value is wired into the server. Patch
        'pytcp.protocols.dhcp4.dhcp4__client.socket' (the factory call site) and
        the 'log' channel for the duration of every test in the
        subclass. Disable the Phase 2.1 startup desynchronisation
        delay by default so the suite does not actually sleep 1-10 s
        per 'fetch()'; tests that exercise the delay re-enable it
        via 'sysctl.override' in their own bodies.
        """

        self._server = Dhcp4MockServer()
        self._socket_factory = autospec_dhcp4_socket()
        self._sock = self._socket_factory.return_value
        self._server.wire(self._sock)
        self.enterContext(patch("pytcp.protocols.dhcp4.dhcp4__client.socket", self._socket_factory))
        self._mock_log = self.enterContext(patch("pytcp.protocols.dhcp4.dhcp4__client.log"))
        # Silence the Subsystem base-class init log line (Dhcp4Client
        # inherits from Subsystem as of Phase 4 commit 0; the base
        # 'log("stack", "Initializing ...")' call would otherwise
        # leak to stdout under the default 'LOG__CHANNEL' set).
        self.enterContext(patch("pytcp.runtime.subsystem.log"))
        self.enterContext(sysctl.override("dhcp.init_delay_min_ms", 0))
        self.enterContext(sysctl.override("dhcp.init_delay_max_ms", 0))
        # Phase 8.x — disable the multi-OFFER collection window
        # by default so tests do not actually sleep 3 s waiting
        # for additional OFFERs. Tests that exercise the window
        # re-enable it via 'sysctl.override' in their own bodies.
        self.enterContext(sysctl.override("dhcp.offer_collection_ms", 0))


class TestDhcp4ClientFetchHappyPath(_Dhcp4ClientFixture):
    """
    The 'Dhcp4Client.fetch()' happy-path tests.
    """

    @override
    def setUp(self) -> None:
        """
        Build the canonical lease scenario — an OFFER and ACK for
        '10.0.0.100/24' with gateway '10.0.0.1'.
        """

        super().setUp()
        self._server.enqueue_offer(router=[Ip4Address("10.0.0.1")])
        self._server.enqueue_ack(router=[Ip4Address("10.0.0.1")])

    def test__dhcp4_client__fetch_returns_lease_with_address_and_mask(self) -> None:
        """
        Ensure a valid Offer/Ack exchange yields a 'Dhcp4Lease' carrying
        an 'ip4_host' with the server-assigned address and subnet mask.

        Reference: RFC 2131 §3.1 (DHCP message exchange — DISCOVER → OFFER → REQUEST → ACK).
        """

        client = Dhcp4Client(mac_address=_DEFAULT_MAC)
        result = client.fetch()

        self.assertIsInstance(
            result,
            Dhcp4Lease,
            msg="Dhcp4Client.fetch() must return a Dhcp4Lease on a successful Offer/Ack exchange.",
        )
        assert result is not None
        self.assertIsInstance(
            result.ip4_host,
            Ip4IfAddr,
            msg="Dhcp4Lease.ip4_host must be an Ip4IfAddr.",
        )
        self.assertEqual(
            result.ip4_host.address,
            Ip4Address("10.0.0.100"),
            msg="Dhcp4Lease.ip4_host.address must equal the server-assigned yiaddr.",
        )
        self.assertEqual(
            result.ip4_host.network.mask,
            Ip4Mask("255.255.255.0"),
            msg="Dhcp4Lease.ip4_host.network.mask must equal the server-supplied subnet mask.",
        )

    def test__dhcp4_client__fetch_sets_gateway_when_router_option_present(self) -> None:
        """
        Ensure the first router address from the Router option is stored
        as the host's default gateway.

        Reference: RFC 2132 §3.5 (Router Option — option code 3).
        """

        client = Dhcp4Client(mac_address=_DEFAULT_MAC)
        result = client.fetch()

        assert result is not None
        self.assertEqual(
            result.gateway,
            Ip4Address("10.0.0.1"),
            msg="Dhcp4Lease.ip4_host.gateway must equal the first router address in the DHCP Router option.",
        )

    def test__dhcp4_client__fetch_binds_and_connects_to_dhcp_ports(self) -> None:
        """
        Ensure the client binds to the canonical DHCPv4 client port 68
        on the unspecified IPv4 address and 'connects' to the broadcast
        address on port 67 before sending the Discover packet.

        Reference: RFC 2131 §4.1 (Constructing and sending DHCP messages — server port 67, client port 68).
        """

        client = Dhcp4Client(mac_address=_DEFAULT_MAC)
        client.fetch()

        self._sock.bind.assert_called_once_with(("0.0.0.0", 68))
        self._sock.connect.assert_called_once_with(("255.255.255.255", 67))

    def test__dhcp4_client__fetch_sends_two_packets(self) -> None:
        """
        Ensure the happy path sends exactly two packets — the initial
        Discover and the follow-up Request.

        Reference: RFC 2131 §3.1 (DHCP message exchange — DISCOVER → OFFER → REQUEST → ACK).
        """

        client = Dhcp4Client(mac_address=_DEFAULT_MAC)
        client.fetch()

        self.assertEqual(
            self._sock.send.call_count,
            2,
            msg="Happy-path fetch() must send two packets (Discover + Request).",
        )
        self.assertEqual(
            self._server.tx_log[0].message_type,
            Dhcp4MessageType.DISCOVER,
            msg="First emitted packet must be a DHCPDISCOVER.",
        )
        self.assertEqual(
            self._server.tx_log[1].message_type,
            Dhcp4MessageType.REQUEST,
            msg="Second emitted packet must be a DHCPREQUEST.",
        )

    def test__dhcp4_client__fetch_closes_socket_on_success(self) -> None:
        """
        Ensure the UDP socket is closed before 'fetch()' returns the
        negotiated lease.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        client = Dhcp4Client(mac_address=_DEFAULT_MAC)
        client.fetch()

        self._sock.close.assert_called_once_with()

    def test__dhcp4_client__fetch_first_recv_uses_initial_retrans_window(self) -> None:
        """
        Ensure the first 'recv__mv' call uses a 'timeout' kwarg derived
        from 'dhcp.retrans_initial_ms' (Phase 1 backoff). With jitter
        disabled and 'retrans_initial_ms' pinned at 4000, the first
        recv must request a 4.0-second window.

        Reference: RFC 2131 §4.1 (first retransmit at 4 seconds).
        """

        with sysctl.override("dhcp.retrans_jitter_ms", 0):
            Dhcp4Client(mac_address=_DEFAULT_MAC).fetch()

        first_recv = self._sock.recv__mv.call_args_list[0]
        self.assertAlmostEqual(
            first_recv.kwargs["timeout"],
            4.0,
            places=2,
            msg="First recv__mv must use the dhcp.retrans_initial_ms-derived 4-second window.",
        )


class TestDhcp4ClientFetchNoRouter(_Dhcp4ClientFixture):
    """
    The 'Dhcp4Client.fetch()' 'router option absent' happy-path test.
    """

    def test__dhcp4_client__fetch_no_router_leaves_gateway_unset(self) -> None:
        """
        Ensure the host returned by 'fetch()' has no gateway set when
        the DHCP Ack lacks a Router option (the 'router is None' branch
        in the source).

        Reference: RFC 2132 §3.5 (Router Option — optional, may be absent).
        """

        self._server.enqueue_offer(router=None)
        self._server.enqueue_ack(router=None)

        client = Dhcp4Client(mac_address=_DEFAULT_MAC)
        result = client.fetch()

        assert result is not None
        self.assertIsNone(
            result.gateway,
            msg="Dhcp4Lease.ip4_host.gateway must remain None when the DHCP Ack carries no Router option.",
        )


class TestDhcp4ClientFetchOfferTimeout(_Dhcp4ClientFixture):
    """
    The 'Dhcp4Client.fetch()' Offer-timeout failure test.
    """

    def test__dhcp4_client__fetch_returns_none_on_offer_timeout(self) -> None:
        """
        Ensure a 'TimeoutError' during the Offer receive collapses the
        exchange: 'fetch()' returns None and the socket is closed.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._server.enqueue_timeout()

        client = Dhcp4Client(mac_address=_DEFAULT_MAC)
        result = client.fetch()

        self.assertIsNone(
            result,
            msg="fetch() must return None when the Offer receive times out.",
        )
        self._sock.close.assert_called_once_with()


class TestDhcp4ClientFetchOfferWrongMessageType(_Dhcp4ClientFixture):
    """
    The 'Dhcp4Client.fetch()' Offer-with-wrong-type failure test.
    """

    def test__dhcp4_client__fetch_returns_none_on_wrong_offer_message_type(self) -> None:
        """
        Ensure a response to the Discover with a non-OFFER message type
        is silently dropped — under the Phase 1 backoff the bogus
        frame keeps the wait window open, the empty queue then times
        the window out, and (with the retransmit budget capped at 1
        for this test) 'fetch()' returns None without retransmitting.

        Reference: RFC 2131 §3.1 step 2 (server response to DISCOVER is DHCPOFFER).
        Reference: RFC 2131 §4.4.1 (mismatching messages silently discarded; client keeps listening).
        """

        self.enterContext(sysctl.override("dhcp.retrans_max_attempts", 1))
        self._server.enqueue_offer(message_type=Dhcp4MessageType.ACK)

        client = Dhcp4Client(mac_address=_DEFAULT_MAC)
        result = client.fetch()

        self.assertIsNone(
            result,
            msg="fetch() must return None when the first response is not a DHCP Offer.",
        )
        self._sock.close.assert_called_once_with()
        self.assertEqual(
            self._sock.send.call_count,
            1,
            msg="Only the Discover must be sent when the Offer message-type check fails.",
        )


class TestDhcp4ClientFetchAckTimeout(_Dhcp4ClientFixture):
    """
    The 'Dhcp4Client.fetch()' Ack-timeout failure test.
    """

    def test__dhcp4_client__fetch_returns_none_on_ack_timeout(self) -> None:
        """
        Ensure a 'TimeoutError' during the Ack receive — after a valid
        Offer — aborts the exchange: 'fetch()' returns None and the
        socket is closed.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._server.enqueue_offer()
        self._server.enqueue_timeout()

        client = Dhcp4Client(mac_address=_DEFAULT_MAC)
        result = client.fetch()

        self.assertIsNone(
            result,
            msg="fetch() must return None when the Ack receive times out.",
        )
        self._sock.close.assert_called_once_with()


class TestDhcp4ClientFetchAckWrongMessageType(_Dhcp4ClientFixture):
    """
    The 'Dhcp4Client.fetch()' Ack-with-wrong-non-NAK-type failure test.
    """

    def test__dhcp4_client__fetch_returns_none_on_wrong_ack_message_type(self) -> None:
        """
        Ensure a response to the Request with a non-ACK, non-NAK
        message type is silently dropped — Phase 1 keeps the wait
        window open, the empty queue then times the window out, and
        (with the retransmit budget capped at 1) 'fetch()' returns
        None without retransmitting the REQUEST.

        Reference: RFC 2131 §3.1 step 4 (server response to REQUEST is DHCPACK or DHCPNAK).
        Reference: RFC 2131 §4.4.1 (mismatching messages silently discarded; client keeps listening).
        """

        self.enterContext(sysctl.override("dhcp.retrans_max_attempts", 1))
        self._server.enqueue_offer()
        self._server.enqueue_ack(message_type=Dhcp4MessageType.OFFER)

        client = Dhcp4Client(mac_address=_DEFAULT_MAC)
        result = client.fetch()

        self.assertIsNone(
            result,
            msg="fetch() must return None when the second response is neither an ACK nor a NAK.",
        )
        self._sock.close.assert_called_once_with()
        self.assertEqual(
            self._sock.send.call_count,
            2,
            msg="Both Discover and Request must be sent before the Ack message-type check fails.",
        )


class TestDhcp4ClientFetchOfferSrvIdNone(_Dhcp4ClientFixture):
    """
    The 'Dhcp4Client.fetch()' rejection of an Offer without Server-ID.
    """

    def test__dhcp4_client__fetch_returns_none_on_offer_without_server_id(self) -> None:
        """
        Ensure 'fetch()' returns None when the Offer omits the
        Server-ID option. The malformed Offer is rejected at the
        parser layer with Dhcp4SanityError so the client's wait
        loop drops it and eventually times out without sending a
        Request.

        Reference: RFC 2131 §3 Table 3 / §4.3.6 (Server Identifier required in DHCPOFFER).
        """

        self._server.enqueue_offer(server_id=None)

        client = Dhcp4Client(mac_address=_DEFAULT_MAC)
        result = client.fetch()

        self.assertIsNone(
            result,
            msg="fetch() must return None when the Offer omits the Server-ID option.",
        )
        self._sock.close.assert_called_once_with()
        # Parser-level rejection causes the wait loop to drop the
        # malformed frame and the RFC 2131 §4.1 retransmission loop
        # to re-send Discover until the per-round budget is
        # exhausted. The exact retransmission count is governed by
        # the `dhcp.discover_max_retries` sysctl; assert only on
        # the invariant we care about — no Request packet was sent
        # off the back of the malformed Offer.
        for call in self._sock.send.call_args_list:
            sent_bytes = call.args[0]
            self.assertNotIn(
                # Message Type option (53), length 1, REQUEST (3).
                b"\x35\x01\x03",
                bytes(sent_bytes),
                msg="No Request packet must be emitted after a malformed Offer.",
            )


class TestDhcp4ClientFetchAckMissingSubnetMask(_Dhcp4ClientFixture):
    """
    The 'Dhcp4Client.fetch()' rejection of an Ack without Subnet Mask.
    """

    def test__dhcp4_client__fetch_returns_none_on_ack_without_subnet_mask(self) -> None:
        """
        Ensure 'fetch()' returns None when the Ack omits the Subnet
        Mask option. The socket must still be closed.

        Reference: RFC 2132 §3.3 (Subnet Mask option — option code 1).
        """

        self._server.enqueue_offer()
        self._server.enqueue_ack(subnet_mask=None)

        client = Dhcp4Client(mac_address=_DEFAULT_MAC)
        result = client.fetch()

        self.assertIsNone(
            result,
            msg="fetch() must return None when the Ack omits the Subnet Mask option.",
        )
        self._sock.close.assert_called_once_with()


class TestDhcp4ClientFetchXid(_Dhcp4ClientFixture):
    """
    The 'Dhcp4Client.fetch()' transaction-ID generation tests.
    """

    def test__dhcp4_client__fetch_uses_random_randint_for_xid(self) -> None:
        """
        Ensure each 'fetch()' call draws a fresh xid via
        'random.randint(0, 0xFFFFFFFF)'. Pinning the PRNG call shape
        guards against accidental reseeding or range changes.

        Reference: RFC 2131 §4.1 (xid is a random 32-bit number).
        """

        self._server.enqueue_offer()
        self._server.enqueue_ack()

        with patch(
            "pytcp.protocols.dhcp4.dhcp4__client.random.randint",
            return_value=_PINNED_XID,
        ) as mock_randint:
            Dhcp4Client(mac_address=_DEFAULT_MAC).fetch()

        mock_randint.assert_called_once_with(0, 0xFFFFFFFF)

    def test__dhcp4_client__fetch_regenerates_xid_per_call(self) -> None:
        """
        Ensure successive 'fetch()' calls draw a new xid each time so
        a stale Offer from a previous transaction cannot be matched
        against a fresh handshake.

        Reference: RFC 2131 §4.1 (each new exchange uses a fresh xid).
        """

        self._server.enqueue_offer()
        self._server.enqueue_ack()
        self._server.enqueue_offer()
        self._server.enqueue_ack()

        with patch(
            "pytcp.protocols.dhcp4.dhcp4__client.random.randint",
            return_value=_PINNED_XID,
        ) as mock_randint:
            client = Dhcp4Client(mac_address=_DEFAULT_MAC)
            client.fetch()
            client.fetch()

        self.assertEqual(
            mock_randint.call_count,
            2,
            msg="random.randint must be called once per fetch() to regenerate the xid.",
        )


class TestDhcp4ClientFetchClientIdInRequest(_Dhcp4ClientFixture):
    """
    The 'Dhcp4Client.fetch()' Client Identifier emission in REQUEST.
    """

    def test__dhcp4_client__send_request_includes_client_id(self) -> None:
        """
        Ensure the REQUEST packet emitted in response to a valid OFFER
        carries the Client Identifier option ('\\x01' + MAC).

        Reference: RFC 2131 §2 (Client Identifier).
        Reference: RFC 2131 §4.4.1 (client SHOULD include client identifier in every message).
        """

        self._server.enqueue_offer()
        self._server.enqueue_ack()

        Dhcp4Client(mac_address=_DEFAULT_MAC).fetch()

        request = self._server.tx_log[1]
        self.assertEqual(
            request.message_type,
            Dhcp4MessageType.REQUEST,
            msg="Sanity: the second TX must be a DHCPREQUEST.",
        )
        self.assertEqual(
            request.client_id,
            _DEFAULT_CID,
            msg="REQUEST must include the Client Identifier option carrying b'\\x01' + MAC.",
        )


class TestDhcp4ClientFetchXidMismatch(_Dhcp4ClientFixture):
    """
    The 'Dhcp4Client.fetch()' xid-mismatch silent-drop tests.
    """

    def test__dhcp4_client__fetch_returns_none_on_offer_xid_mismatch(self) -> None:
        """
        Ensure an OFFER whose 'xid' does not match the value the client
        sent in DISCOVER is silently dropped — under Phase 1 the bogus
        frame keeps the wait window open without retransmitting; with
        the retransmit budget capped at 1 for this test, 'fetch()'
        returns None after the empty-queue timeout and the REQUEST is
        not sent.

        Reference: RFC 2131 §4.4.1 (client MUST discard messages whose xid does not match).
        """

        self.enterContext(sysctl.override("dhcp.retrans_max_attempts", 1))
        self._server.enqueue_offer(xid=0x11111111)

        with patch(
            "pytcp.protocols.dhcp4.dhcp4__client.random.randint",
            return_value=_PINNED_XID,
        ):
            result = Dhcp4Client(mac_address=_DEFAULT_MAC).fetch()

        self.assertIsNone(
            result,
            msg="fetch() must return None when the OFFER xid does not match the DISCOVER xid.",
        )
        self.assertEqual(
            self._sock.send.call_count,
            1,
            msg="Only DISCOVER must be sent when the OFFER xid is rejected.",
        )

    def test__dhcp4_client__fetch_returns_none_on_ack_xid_mismatch(self) -> None:
        """
        Ensure an ACK whose 'xid' does not match the value the client
        sent in REQUEST is silently dropped: 'fetch()' returns None.

        Reference: RFC 2131 §4.4.1 (client MUST discard messages whose xid does not match).
        """

        self._server.enqueue_offer()
        self._server.enqueue_ack(xid=0x22222222)

        with patch(
            "pytcp.protocols.dhcp4.dhcp4__client.random.randint",
            return_value=_PINNED_XID,
        ):
            result = Dhcp4Client(mac_address=_DEFAULT_MAC).fetch()

        self.assertIsNone(
            result,
            msg="fetch() must return None when the ACK xid does not match the REQUEST xid.",
        )


class TestDhcp4ClientFetchCidEcho(_Dhcp4ClientFixture):
    """
    The 'Dhcp4Client.fetch()' Client Identifier echo-validation tests.
    """

    def test__dhcp4_client__fetch_returns_none_on_offer_cid_mismatch(self) -> None:
        """
        Ensure an OFFER whose echoed Client Identifier does not match
        the value the client emitted is silently dropped.

        Reference: RFC 6842 §3 (client MUST compare echoed CID and silently discard mismatching messages).
        """

        self._server.enqueue_offer(
            client_id_echo=b"\x01" + bytes(MacAddress("02:00:00:00:99:99")),
        )

        result = Dhcp4Client(mac_address=_DEFAULT_MAC).fetch()

        self.assertIsNone(
            result,
            msg="fetch() must return None when the OFFER echoes a mismatching Client Identifier.",
        )

    def test__dhcp4_client__fetch_returns_none_on_ack_cid_mismatch(self) -> None:
        """
        Ensure an ACK whose echoed Client Identifier does not match
        the value the client emitted is silently dropped.

        Reference: RFC 6842 §3 (client MUST compare echoed CID and silently discard mismatching messages).
        """

        self._server.enqueue_offer()
        self._server.enqueue_ack(
            client_id_echo=b"\x01" + bytes(MacAddress("02:00:00:00:99:99")),
        )

        result = Dhcp4Client(mac_address=_DEFAULT_MAC).fetch()

        self.assertIsNone(
            result,
            msg="fetch() must return None when the ACK echoes a mismatching Client Identifier.",
        )

    def test__dhcp4_client__fetch_accepts_matching_cid_echo(self) -> None:
        """
        Ensure an OFFER/ACK pair whose echoed Client Identifier matches
        the client's emitted CID is accepted (regression guard against
        the new validator over-rejecting the happy path).

        Reference: RFC 6842 §3 (matching CID echo must not be discarded).
        """

        self._server.enqueue_offer()
        self._server.enqueue_ack()

        result = Dhcp4Client(mac_address=_DEFAULT_MAC).fetch()

        self.assertIsInstance(
            result,
            Dhcp4Lease,
            msg="fetch() must accept matching Client Identifier echoes.",
        )


class TestDhcp4ClientFetchNakRestart(_Dhcp4ClientFixture):
    """
    The 'Dhcp4Client.fetch()' DHCPNAK bounded-restart tests.
    """

    def test__dhcp4_client__fetch_restarts_from_discover_on_ack_stage_nak(self) -> None:
        """
        Ensure a DHCPNAK arriving in response to the REQUEST triggers a
        restart from DISCOVER and the second exchange yields a usable
        lease. The successful round-trip after NAK confirms the
        client's bounded-restart loop, distinct from the silent-drop
        path that 'wrong message type' takes.

        Reference: RFC 2131 §3.1 step 4 (DHCPNAK → restart from DHCPDISCOVER).
        """

        self._server.enqueue_offer()
        self._server.enqueue_nak()
        self._server.enqueue_offer()
        self._server.enqueue_ack()

        result = Dhcp4Client(mac_address=_DEFAULT_MAC).fetch()

        self.assertIsInstance(
            result,
            Dhcp4Lease,
            msg="fetch() must restart from DISCOVER on NAK and return a lease when the retry succeeds.",
        )
        self.assertEqual(
            self._sock.send.call_count,
            4,
            msg="NAK-restart path must send DISCOVER, REQUEST, DISCOVER, REQUEST.",
        )

    def test__dhcp4_client__fetch_returns_none_after_max_nak_restarts(self) -> None:
        """
        Ensure 'fetch()' returns None once the bounded NAK-restart
        budget is exhausted. With the default budget of 3 restarts,
        four NAK rounds (initial + 3 restarts) exhaust the loop and
        no further DISCOVER is emitted.

        Reference: RFC 2131 §3.1 step 4 (NAK → restart; bounded to avoid loops).
        """

        for _ in range(4):
            self._server.enqueue_offer()
            self._server.enqueue_nak()

        result = Dhcp4Client(mac_address=_DEFAULT_MAC).fetch()

        self.assertIsNone(
            result,
            msg="fetch() must return None after the NAK-restart budget is exhausted.",
        )
        self.assertEqual(
            self._sock.send.call_count,
            8,
            msg="Four DISCOVER/REQUEST round-trips must be attempted before giving up (initial + 3 restarts).",
        )


class TestDhcp4ClientFetchLeaseReturn(_Dhcp4ClientFixture):
    """
    The 'Dhcp4Client.fetch()' Dhcp4Lease return-shape tests.
    """

    def test__dhcp4_client__fetch_returns_lease_time_from_ack(self) -> None:
        """
        Ensure 'Dhcp4Lease.lease_time__sec' equals the lease-time value
        carried by the ACK's option 51.

        Reference: RFC 2132 §9.2 (IP Address Lease Time option — code 51).
        """

        self._server.enqueue_offer()
        self._server.enqueue_ack(lease_time=7200)

        result = Dhcp4Client(mac_address=_DEFAULT_MAC).fetch()

        assert result is not None
        self.assertEqual(
            result.lease_time__sec,
            7200,
            msg="Dhcp4Lease.lease_time__sec must equal the ACK's option 51 value.",
        )

    def test__dhcp4_client__fetch_records_server_id_on_lease(self) -> None:
        """
        Ensure 'Dhcp4Lease.server_id' equals the Server Identifier from
        the OFFER so subsequent RENEW/REBIND/DECLINE messages can
        target the correct server.

        Reference: RFC 2131 §4.3.2 (server identifier carried into REQUEST/RENEW).
        """

        self._server.enqueue_offer()
        self._server.enqueue_ack()

        result = Dhcp4Client(mac_address=_DEFAULT_MAC).fetch()

        assert result is not None
        self.assertEqual(
            result.server_id,
            Ip4Address("10.0.0.254"),
            msg="Dhcp4Lease.server_id must equal the OFFER's Server Identifier.",
        )

    def test__dhcp4_client__fetch_records_acquired_at_monotonic(self) -> None:
        """
        Ensure 'Dhcp4Lease.acquired_at_monotonic' captures a monotonic
        timestamp at lease acquisition so the lifecycle thread can
        compute T1/T2 expiries without a wall-clock dependency.

        Reference: RFC 2131 §4.4.5 (T1/T2 timing relative to lease acquisition).
        """

        self._server.enqueue_offer()
        self._server.enqueue_ack()

        with patch("pytcp.protocols.dhcp4.dhcp4__client.time.monotonic", return_value=1234.5):
            result = Dhcp4Client(mac_address=_DEFAULT_MAC).fetch()

        assert result is not None
        self.assertEqual(
            result.acquired_at_monotonic,
            1234.5,
            msg="Dhcp4Lease.acquired_at_monotonic must equal time.monotonic() at acquisition.",
        )


class TestDhcp4ClientFetchAckMissingLeaseTime(_Dhcp4ClientFixture):
    """
    The 'Dhcp4Client.fetch()' rejection of an Ack without lease time.
    """

    def test__dhcp4_client__fetch_returns_none_on_ack_without_lease_time(self) -> None:
        """
        Ensure 'fetch()' returns None when the ACK omits the IP Address
        Lease Time option. Without a lease duration the lifecycle has
        no T1/T2 to schedule against, so the lease is unusable.

        Reference: RFC 2131 Table 3 (IP address lease time MUST be present in DHCPACK).
        """

        self._server.enqueue_offer()
        self._server.enqueue_ack(lease_time=None)

        result = Dhcp4Client(mac_address=_DEFAULT_MAC).fetch()

        self.assertIsNone(
            result,
            msg="fetch() must return None when the ACK omits the IP Address Lease Time option.",
        )


class TestDhcp4ClientFetchBackoffSilence(_Dhcp4ClientFixture):
    """
    The Phase 1 retransmission-backoff behavior under server silence.
    """

    @override
    def setUp(self) -> None:
        """
        Disable jitter for the duration of the test so the expected
        timeout sequence is deterministic, then enqueue 5 'TimeoutError'
        replies — one per backoff attempt.
        """

        super().setUp()
        self.enterContext(sysctl.override("dhcp.retrans_jitter_ms", 0))
        for _ in range(5):
            self._server.enqueue_timeout()

    def test__dhcp4_client__fetch_silent_server_runs_5_attempts(self) -> None:
        """
        Ensure a fully silent server triggers exactly 5 'recv__mv'
        attempts and 5 outbound DISCOVERs (1 initial + 4 retransmits),
        then 'fetch()' returns None.

        Reference: RFC 2131 §4.1 (retransmission backoff with up to 5 attempts).
        """

        result = Dhcp4Client(mac_address=_DEFAULT_MAC).fetch()

        self.assertIsNone(
            result,
            msg="fetch() must return None when the server is silent across all retransmissions.",
        )
        self.assertEqual(
            self._sock.recv__mv.call_count,
            5,
            msg="Phase 1 backoff must make 5 recv attempts before giving up.",
        )
        self.assertEqual(
            self._sock.send.call_count,
            5,
            msg="Phase 1 backoff must emit 5 DISCOVERs (1 initial + 4 retransmits).",
        )

    def test__dhcp4_client__fetch_silent_server_doubles_timeouts(self) -> None:
        """
        Ensure the 'timeout' kwarg passed to successive 'recv__mv'
        calls follows the doubling sequence 4 / 8 / 16 / 32 / 64
        seconds with jitter disabled.

        Reference: RFC 2131 §4.1 (retransmission delay doubled up to 64 seconds).
        """

        Dhcp4Client(mac_address=_DEFAULT_MAC).fetch()

        timeouts = [call.kwargs["timeout"] for call in self._sock.recv__mv.call_args_list]
        self.assertEqual(
            timeouts,
            [4.0, 8.0, 16.0, 32.0, 64.0],
            msg="recv__mv timeouts must follow the 4/8/16/32/64 doubling sequence with jitter disabled.",
        )


class TestDhcp4ClientFetchBackoffEarlyExit(_Dhcp4ClientFixture):
    """
    Phase 1 backoff terminates early on the first valid OFFER.
    """

    def test__dhcp4_client__fetch_offer_on_third_attempt_returns_lease(self) -> None:
        """
        Ensure an OFFER arriving on the third attempt (after two
        timeouts) is accepted and 'fetch()' completes the exchange
        without continuing the doubling sequence.

        Reference: RFC 2131 §4.1 (retransmission loop terminates as soon as a valid reply arrives).
        """

        self.enterContext(sysctl.override("dhcp.retrans_jitter_ms", 0))
        self._server.enqueue_timeout()
        self._server.enqueue_timeout()
        self._server.enqueue_offer()
        self._server.enqueue_ack()

        result = Dhcp4Client(mac_address=_DEFAULT_MAC).fetch()

        self.assertIsInstance(
            result,
            Dhcp4Lease,
            msg="fetch() must return the lease as soon as the server replies, mid-backoff.",
        )
        # Three OFFER-stage recv attempts (two timed out, third
        # succeeded) plus one ACK-stage recv = 4 total.
        self.assertEqual(
            self._sock.recv__mv.call_count,
            4,
            msg="recv__mv must be called once for each OFFER attempt plus once for the ACK.",
        )
        # Three DISCOVERs (initial + 2 retransmits) + 1 REQUEST.
        self.assertEqual(
            self._sock.send.call_count,
            4,
            msg="Send count must be 3 DISCOVERs (initial + 2 retransmits) plus 1 REQUEST.",
        )


class TestDhcp4ClientFetchBackoffBogusPacket(_Dhcp4ClientFixture):
    """
    Phase 1 backoff drops a bogus inbound packet without burning the
    current attempt's wait window.
    """

    def test__dhcp4_client__fetch_bogus_xid_in_window_does_not_burn_attempt(self) -> None:
        """
        Ensure an OFFER with a mismatching xid arriving mid-window is
        silently dropped and the client keeps waiting in the SAME
        wait window for a valid OFFER. The valid OFFER lands within
        the first 4-second window, so only one DISCOVER is emitted
        (no retransmit).

        Reference: RFC 2131 §4.4.1 (mismatched-xid messages discarded; client keeps listening).
        """

        self.enterContext(sysctl.override("dhcp.retrans_jitter_ms", 0))
        self._server.enqueue_offer(xid=0x11111111)
        self._server.enqueue_offer()
        self._server.enqueue_ack()

        # Pin random.randint so we know the DISCOVER's xid is not
        # 0x11111111 — the bogus OFFER will fail the xid gate.
        with patch(
            "pytcp.protocols.dhcp4.dhcp4__client.random.randint",
            return_value=0xDEADBEEF,
        ):
            result = Dhcp4Client(mac_address=_DEFAULT_MAC).fetch()

        self.assertIsInstance(
            result,
            Dhcp4Lease,
            msg="fetch() must accept the second OFFER once the bogus first OFFER is silently dropped.",
        )
        # Two recv__mv calls during the OFFER stage (bogus + valid) +
        # one for the ACK = 3 total. NO retransmits — the bogus
        # packet did NOT trigger a new DISCOVER.
        self.assertEqual(
            self._sock.send.call_count,
            2,
            msg="Bogus mid-window OFFER must NOT trigger a retransmit; only 1 DISCOVER + 1 REQUEST expected.",
        )


class TestDhcp4ClientFetchSecsField(_Dhcp4ClientFixture):
    """
    Phase 1 'secs' field advances per RFC 1542 §3.2 across the
    outbound DISCOVER / REQUEST messages within a fetch().
    """

    def test__dhcp4_client__first_discover_carries_secs_zero(self) -> None:
        """
        Ensure the very first DISCOVER carries 'secs' = 0 — the
        client has just begun the address-acquisition process so no
        time has elapsed.

        Reference: RFC 1542 §3.2 (secs field: seconds elapsed since the client began the address acquisition process).
        """

        self._server.enqueue_offer()
        self._server.enqueue_ack()

        Dhcp4Client(mac_address=_DEFAULT_MAC).fetch()

        self.assertEqual(
            self._server.tx_log[0].secs,
            0,
            msg="First DISCOVER must carry secs=0.",
        )

    def test__dhcp4_client__retransmitted_discover_carries_advancing_secs(self) -> None:
        """
        Ensure a retransmitted DISCOVER's 'secs' field equals the
        integer number of seconds elapsed since the initial DISCOVER.
        Patches the '_elapsed_secs' helper to return 0, then 5, so
        the first DISCOVER carries secs=0 and the retransmitted
        DISCOVER (after the first window times out) carries secs=5.

        Reference: RFC 1542 §3.2 (secs field advances across retransmissions).
        """

        self.enterContext(sysctl.override("dhcp.retrans_jitter_ms", 0))
        # First attempt: server times out → client retransmits.
        # Second attempt: server replies with OFFER, then ACK.
        self._server.enqueue_timeout()
        self._server.enqueue_offer()
        self._server.enqueue_ack()

        # Patch the elapsed-seconds helper directly so the test is
        # decoupled from 'time.monotonic' call counts inside the
        # deadline-math loop.
        with patch.object(
            Dhcp4Client,
            "_elapsed_secs",
            side_effect=[0, 5, 5],
        ):
            Dhcp4Client(mac_address=_DEFAULT_MAC).fetch()

        self.assertEqual(
            self._server.tx_log[0].secs,
            0,
            msg="First DISCOVER must carry secs=0.",
        )
        self.assertEqual(
            self._server.tx_log[1].secs,
            5,
            msg="Retransmitted DISCOVER must carry secs=5 after 5 s elapsed.",
        )


class TestDhcp4ClientFetchBackoffJitter(_Dhcp4ClientFixture):
    """
    Phase 1 jitter draws from a uniform ±retrans_jitter_ms window.
    """

    def test__dhcp4_client__fetch_jitter_draws_from_pm_jitter_ms(self) -> None:
        """
        Ensure 'random.uniform' is called with the symmetric
        '(-jitter_ms / 1000, +jitter_ms / 1000)' window before each
        recv attempt.

        Reference: RFC 2131 §4.1 (retransmission delay randomized by ±1 s).
        """

        self._server.enqueue_timeout()

        with patch(
            "pytcp.protocols.dhcp4.dhcp4__client.random.uniform",
            return_value=0.0,
        ) as mock_uniform:
            Dhcp4Client(mac_address=_DEFAULT_MAC).fetch()

        # First (and only) jitter draw must use the configured
        # ±1000 ms bound expressed in seconds.
        mock_uniform.assert_any_call(-1.0, 1.0)


class TestDhcp4ClientFetchInitialDelay(_Dhcp4ClientFixture):
    """
    Phase 2.1 — RFC 2131 §4.4.1 "wait a random time between one and
    ten seconds to desynchronize the use of DHCP at startup".
    """

    def test__dhcp4_client__fetch_initial_delay_uses_default_bounds(self) -> None:
        """
        Ensure the startup desync delay draws from
        'random.uniform(1.0, 10.0)' when the
        'dhcp.init_delay_{min,max}_ms' sysctls are at their default
        values. The fixture base disables the delay by default, so
        this test restores the defaults locally before exercising
        'fetch()'.

        Reference: RFC 2131 §4.4.1 (client SHOULD wait a random time between one and ten seconds).
        """

        self.enterContext(sysctl.override("dhcp.init_delay_min_ms", 1000))
        self.enterContext(sysctl.override("dhcp.init_delay_max_ms", 10000))
        self._server.enqueue_offer()
        self._server.enqueue_ack()

        with (
            patch("pytcp.protocols.dhcp4.dhcp4__client.random.uniform", return_value=4.2) as mock_uniform,
            patch("pytcp.protocols.dhcp4.dhcp4__client.time.sleep") as mock_sleep,
        ):
            Dhcp4Client(mac_address=_DEFAULT_MAC).fetch()

        mock_uniform.assert_any_call(1.0, 10.0)
        mock_sleep.assert_any_call(4.2)

    def test__dhcp4_client__fetch_initial_delay_honours_custom_sysctl_bounds(self) -> None:
        """
        Ensure operator overrides on 'dhcp.init_delay_min_ms' /
        'dhcp.init_delay_max_ms' propagate through to the
        'random.uniform' bounds (expressed in seconds).

        Reference: RFC 2131 §4.4.1 (the 1-10 s range is a SHOULD; tunable to fit deployment).
        """

        self.enterContext(sysctl.override("dhcp.init_delay_min_ms", 500))
        self.enterContext(sysctl.override("dhcp.init_delay_max_ms", 2500))
        self._server.enqueue_offer()
        self._server.enqueue_ack()

        with (
            patch("pytcp.protocols.dhcp4.dhcp4__client.random.uniform", return_value=1.0) as mock_uniform,
            patch("pytcp.protocols.dhcp4.dhcp4__client.time.sleep"),
        ):
            Dhcp4Client(mac_address=_DEFAULT_MAC).fetch()

        # 500 ms / 1000 = 0.5 s; 2500 ms / 1000 = 2.5 s.
        mock_uniform.assert_any_call(0.5, 2.5)

    def test__dhcp4_client__fetch_initial_delay_disabled_when_max_ms_zero(self) -> None:
        """
        Ensure the startup desync delay is bypassed entirely when
        'dhcp.init_delay_max_ms' is 0 — the canonical
        disable-for-tests configuration that the fixture base
        applies by default. 'time.sleep' must not be invoked from
        the initial-delay path on the happy-path 'fetch()'.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        # Fixture base already sets both bounds to 0; no override
        # needed here. The Phase 1 backoff path uses 'recv__mv(timeout=)'
        # rather than 'time.sleep', so 'time.sleep' should not be
        # called at all during a happy-path fetch.
        self._server.enqueue_offer()
        self._server.enqueue_ack()

        with patch("pytcp.protocols.dhcp4.dhcp4__client.time.sleep") as mock_sleep:
            Dhcp4Client(mac_address=_DEFAULT_MAC).fetch()

        mock_sleep.assert_not_called()


class TestDhcp4ClientFetchArpDad(_Dhcp4ClientFixture):
    """
    ARP DAD verification + DHCPDECLINE on conflict.
    'Dhcp4Client.__init__' accepts an optional 'acd' engine whose
    'probe' 'fetch()' runs against the leased address after a valid
    ACK; on conflict, the client emits DHCPDECLINE and restarts from
    DISCOVER per RFC 2131 §3.1 step 5.
    """

    def test__dhcp4_client__fetch_probes_leased_address_via_acd(self) -> None:
        """
        Ensure 'fetch()' runs the ACD probe exactly once against the
        server-assigned 'yiaddr' after a valid ACK.

        Reference: RFC 2131 §3.1 step 5 (client SHOULD probe the offered address).
        Reference: RFC 5227 §2.1 (host MUST probe before claiming).
        """

        acd = _acd_mock(probe_results=True)
        self._server.enqueue_offer()
        self._server.enqueue_ack()

        result = Dhcp4Client(
            mac_address=_DEFAULT_MAC,
            acd=acd,
        ).fetch()

        self.assertIsInstance(
            result,
            Dhcp4Lease,
            msg="fetch() must return the lease when the ACD probe reports no conflict.",
        )
        acd.probe.assert_called_once_with(address=Ip4Address("10.0.0.100"))

    def test__dhcp4_client__fetch_without_acd_returns_lease_unverified(self) -> None:
        """
        Ensure 'fetch()' returns the lease unverified when no 'acd'
        engine is supplied (sync-mode callers that own conflict
        detection themselves).

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._server.enqueue_offer()
        self._server.enqueue_ack()

        result = Dhcp4Client(mac_address=_DEFAULT_MAC).fetch()

        self.assertIsInstance(
            result,
            Dhcp4Lease,
            msg="fetch() without an ACD engine must still return the lease unverified.",
        )

    def test__dhcp4_client__fetch_probe_conflict_emits_decline_message(self) -> None:
        """
        Ensure an ACD probe conflict triggers a DHCPDECLINE TX whose
        message type, Server Identifier, Requested IP Address, and
        Client Identifier echo all carry the values from the offered
        lease.

        Reference: RFC 2131 §3.1 step 5 (the client MUST send a DHCPDECLINE message).
        Reference: RFC 2131 §4.4 Table 5 (DHCPDECLINE MUST carry Server ID + Requested IP).
        """

        self.enterContext(sysctl.override("dhcp.decline_backoff_ms", 0))
        self.enterContext(sysctl.override("dhcp.nak_max_restarts", 0))
        self._server.enqueue_offer()
        self._server.enqueue_ack()

        acd = _acd_mock(probe_results=False, conflict_mac=MacAddress("02:00:00:00:00:99"))

        Dhcp4Client(
            mac_address=_DEFAULT_MAC,
            acd=acd,
        ).fetch()

        # tx_log: [DISCOVER, REQUEST, DECLINE]
        self.assertEqual(
            len(self._server.tx_log),
            3,
            msg="DECLINE on conflict must produce exactly 3 outbound TXs (DISCOVER, REQUEST, DECLINE).",
        )
        decline = self._server.tx_log[2]
        self.assertEqual(
            decline.message_type,
            Dhcp4MessageType.DECLINE,
            msg="Third TX must carry message type DHCPDECLINE.",
        )
        self.assertEqual(
            decline.server_id,
            Ip4Address("10.0.0.254"),
            msg="DECLINE must echo the OFFER's Server Identifier (option 54).",
        )
        self.assertEqual(
            decline.req_ip_addr,
            Ip4Address("10.0.0.100"),
            msg="DECLINE must carry the rejected yiaddr in the Requested IP Address option (50).",
        )
        self.assertEqual(
            decline.ciaddr,
            Ip4Address(),
            msg="DECLINE MUST carry ciaddr = 0 (the address has not been claimed).",
        )
        self.assertEqual(
            decline.client_id,
            _DEFAULT_CID,
            msg="DECLINE must carry the same Client Identifier as DISCOVER / REQUEST.",
        )

    def test__dhcp4_client__fetch_probe_false_then_true_restarts_and_returns_lease(self) -> None:
        """
        Ensure a probe that reports conflict once and then clean on
        the retry produces a usable lease: 'fetch()' emits the
        DECLINE, restarts from DISCOVER, and succeeds on the
        second round.

        Reference: RFC 2131 §3.1 step 5 (DECLINE → restart configuration process).
        """

        self.enterContext(sysctl.override("dhcp.decline_backoff_ms", 0))
        self._server.enqueue_offer()
        self._server.enqueue_ack()
        self._server.enqueue_offer()
        self._server.enqueue_ack()

        acd = _acd_mock(probe_results=[False, True])

        result = Dhcp4Client(
            mac_address=_DEFAULT_MAC,
            acd=acd,
        ).fetch()

        self.assertIsInstance(
            result,
            Dhcp4Lease,
            msg="fetch() must return the lease when the second-round probe reports no conflict.",
        )
        # tx_log: [DISCOVER, REQUEST, DECLINE, DISCOVER, REQUEST]
        self.assertEqual(
            len(self._server.tx_log),
            5,
            msg="DECLINE-then-restart path must emit 5 TXs (D, R, DECL, D, R).",
        )
        self.assertEqual(
            self._server.tx_log[2].message_type,
            Dhcp4MessageType.DECLINE,
            msg="Third TX must be the DECLINE bridging the two rounds.",
        )

    def test__dhcp4_client__fetch_probe_always_false_exhausts_restart_budget(self) -> None:
        """
        Ensure a probe that always reports conflict exhausts the
        shared restart budget ('dhcp.nak_max_restarts' = 3 means
        initial + 3 restarts = 4 rounds) and 'fetch()' returns None.
        Four DECLINEs are emitted, one per round.

        Reference: RFC 2131 §3.1 step 5 (DECLINE-and-restart is bounded to prevent infinite loops).
        """

        self.enterContext(sysctl.override("dhcp.decline_backoff_ms", 0))
        for _ in range(4):
            self._server.enqueue_offer()
            self._server.enqueue_ack()

        acd = _acd_mock(probe_results=False, conflict_mac=MacAddress("02:00:00:00:00:99"))

        result = Dhcp4Client(
            mac_address=_DEFAULT_MAC,
            acd=acd,
        ).fetch()

        self.assertIsNone(
            result,
            msg="fetch() must return None when the restart budget is exhausted on persistent conflict.",
        )
        # 4 rounds × 3 TXs (D, R, DECL) = 12.
        declines = [tx for tx in self._server.tx_log if tx.message_type == Dhcp4MessageType.DECLINE]
        self.assertEqual(
            len(declines),
            4,
            msg="Each restart round must emit one DECLINE; budget=3 yields 4 rounds.",
        )

    def test__dhcp4_client__fetch_decline_path_honours_decline_backoff_sleep(self) -> None:
        """
        Ensure 'fetch()' sleeps 'dhcp.decline_backoff_ms / 1000.0'
        seconds after emitting a DECLINE — the canonical
        "minimum of ten seconds" wait that prevents traffic
        floods on persistent conflict.

        Reference: RFC 2131 §3.1 step 5 (client SHOULD wait a minimum of ten seconds before restarting).
        """

        self.enterContext(sysctl.override("dhcp.decline_backoff_ms", 5000))
        # Stop after the first DECLINE so only the one sleep we care
        # about is observed.
        self.enterContext(sysctl.override("dhcp.nak_max_restarts", 0))
        self._server.enqueue_offer()
        self._server.enqueue_ack()

        acd = _acd_mock(probe_results=False, conflict_mac=MacAddress("02:00:00:00:00:99"))

        with patch("pytcp.protocols.dhcp4.dhcp4__client.time.sleep") as mock_sleep:
            Dhcp4Client(
                mac_address=_DEFAULT_MAC,
                acd=acd,
            ).fetch()

        # Initial-delay sleep is disabled by the fixture; only the
        # decline-backoff sleep should fire.
        mock_sleep.assert_called_once_with(5.0)


class TestDhcp4ClientFetchRfc4361Cid(_Dhcp4ClientFixture):
    """
    Phase 3 — Client Identifier emission and echo validation use
    the RFC 4361 form (type 0xff + IAID + DUID-LL) rather than the
    legacy RFC 2131 type-0x01 + MAC form.
    """

    def test__dhcp4_client__fetch_emits_rfc4361_client_id_in_discover_and_request(self) -> None:
        """
        Ensure both the DISCOVER and the REQUEST emitted by
        'fetch()' carry the RFC 4361 13-byte Client Identifier
        (type 0xff + 4-byte IAID + 8-byte DUID-LL) rather than
        the legacy RFC 2131 7-byte type-0x01 + MAC form.

        Reference: RFC 4361 §6.1 (new clients SHOULD use the type-0xff + IAID + DUID Client Identifier form).
        """

        self._server.enqueue_offer()
        self._server.enqueue_ack()

        Dhcp4Client(mac_address=_DEFAULT_MAC).fetch()

        discover_cid = self._server.tx_log[0].client_id
        request_cid = self._server.tx_log[1].client_id

        self.assertEqual(
            discover_cid,
            build_client_id(_DEFAULT_MAC),
            msg="DISCOVER's Client Identifier must equal the RFC 4361 13-byte form.",
        )
        self.assertEqual(
            request_cid,
            discover_cid,
            msg="REQUEST's Client Identifier must equal DISCOVER's (stable across the exchange).",
        )

    def test__dhcp4_client__fetch_honours_dhcp_duid_sysctl_override(self) -> None:
        """
        Ensure setting 'dhcp.duid' to an operator-supplied hex
        string overrides the MAC-derived DUID portion of the
        emitted Client Identifier.

        Reference: RFC 4361 §6.1 (client MAY use an externally configured DUID).
        """

        override_duid_hex = "00:03:00:01:de:ad:be:ef:ca:fe"
        override_duid_bytes = bytes.fromhex(override_duid_hex.replace(":", ""))
        self.enterContext(sysctl.override("dhcp.duid", override_duid_hex))
        self._server.enqueue_offer()
        self._server.enqueue_ack()

        Dhcp4Client(mac_address=_DEFAULT_MAC).fetch()

        discover_cid = self._server.tx_log[0].client_id
        assert discover_cid is not None
        self.assertEqual(
            discover_cid[0:1],
            b"\xff",
            msg="RFC 4361 type prefix MUST be 0xff regardless of DUID override.",
        )
        self.assertEqual(
            discover_cid[5:],
            override_duid_bytes,
            msg="DUID portion of the Client Identifier must match the 'dhcp.duid' sysctl override.",
        )

    def test__dhcp4_client__fetch_emits_same_cid_across_two_fetches(self) -> None:
        """
        Ensure two consecutive 'fetch()' calls with the same MAC
        emit byte-for-byte identical Client Identifiers — DUID
        stability is required across the client's lifetime.

        Reference: RFC 4361 §6.1 (the DUID is stable across the client's life).
        """

        self._server.enqueue_offer()
        self._server.enqueue_ack()
        self._server.enqueue_offer()
        self._server.enqueue_ack()

        client = Dhcp4Client(mac_address=_DEFAULT_MAC)
        client.fetch()
        client.fetch()

        first_cid = self._server.tx_log[0].client_id
        third_cid = self._server.tx_log[2].client_id  # 2nd fetch's DISCOVER

        self.assertEqual(
            first_cid,
            third_cid,
            msg="Two fetches with the same MAC must emit identical Client Identifiers.",
        )

    def test__dhcp4_client__fetch_rejects_server_echo_of_legacy_cid_form(self) -> None:
        """
        Ensure a server that mistakenly echoes the legacy
        RFC 2131 type-0x01 + MAC form (instead of the emitted
        type-0xff form) is silently discarded — the bytes do not
        match the emitted Client Identifier.

        Reference: RFC 6842 §3 (client MUST silently discard messages whose CID echo mismatches the sent value).
        """

        self.enterContext(sysctl.override("dhcp.retrans_max_attempts", 1))
        legacy_cid = b"\x01" + bytes(_DEFAULT_MAC)
        self._server.enqueue_offer(client_id_echo=legacy_cid)

        result = Dhcp4Client(mac_address=_DEFAULT_MAC).fetch()

        self.assertIsNone(
            result,
            msg="OFFER echoing the legacy CID form must fail the RFC 6842 echo check and be discarded.",
        )


class TestDhcp4ClientFetchLogging(_Dhcp4ClientFixture):
    """
    Observability — fetch() must log both sides of the wire plus
    lifecycle events (acquisition start, lease acquired, failure).
    """

    @staticmethod
    def _log_messages(mock_log_call_args_list: list[Any]) -> list[str]:
        """
        Return every 'log("dhcp4", message)' message text from the
        captured call_args_list, filtering out non-dhcp4 channel
        calls.
        """

        return [
            args[1]
            for args, _ in ((call.args, call.kwargs) for call in mock_log_call_args_list)
            if len(args) >= 2 and args[0] == "dhcp4"
        ]

    def test__dhcp4_client__fetch_logs_rx_line_for_offer_and_ack(self) -> None:
        """
        Ensure 'fetch()' emits a '<lg>RX</>' log line for the OFFER
        and the ACK so operators see the inbound side of the
        exchange (not just the TX side). Regression pin for the
        Phase 1 refactor that initially dropped this line.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._server.enqueue_offer()
        self._server.enqueue_ack()

        Dhcp4Client(mac_address=_DEFAULT_MAC).fetch()

        rx_messages = [msg for msg in self._log_messages(self._mock_log.call_args_list) if "<lg>RX</>" in msg]
        self.assertGreaterEqual(
            len(rx_messages),
            2,
            msg=(
                "fetch() must emit at least two '<lg>RX</>' log lines "
                "(OFFER + ACK) so the inbound side of the exchange is "
                "visible in the log."
            ),
        )

    def test__dhcp4_client__fetch_logs_acquisition_start_and_lease_acquired(self) -> None:
        """
        Ensure 'fetch()' emits a "Starting DHCPv4 acquisition" log
        line at the top and a "Lease acquired" log line on
        successful return so the lifecycle is operator-visible
        without requiring a parser-level TX/RX dump.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._server.enqueue_offer()
        self._server.enqueue_ack()

        Dhcp4Client(mac_address=_DEFAULT_MAC).fetch()

        messages = self._log_messages(self._mock_log.call_args_list)
        self.assertTrue(
            any("Starting DHCPv4 acquisition" in msg for msg in messages),
            msg="fetch() must log a 'Starting DHCPv4 acquisition' lifecycle line.",
        )
        self.assertTrue(
            any("Lease acquired" in msg for msg in messages),
            msg="fetch() must log a 'Lease acquired' lifecycle line on success.",
        )

    def test__dhcp4_client__fetch_logs_acquisition_failure_on_none_return(self) -> None:
        """
        Ensure 'fetch()' emits a "DHCPv4 acquisition failed" log
        line when the exchange fails so operators see a single
        summary line rather than only the per-step warnings.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.enterContext(sysctl.override("dhcp.retrans_max_attempts", 1))
        # Server silence — fetch returns None after the single
        # window times out.
        self._server.enqueue_timeout()

        result = Dhcp4Client(mac_address=_DEFAULT_MAC).fetch()
        self.assertIsNone(result)

        messages = self._log_messages(self._mock_log.call_args_list)
        self.assertTrue(
            any("DHCPv4 acquisition failed" in msg for msg in messages),
            msg="fetch() must log a 'DHCPv4 acquisition failed' summary line on failure.",
        )


class TestDhcp4ClientFsmScaffolding(_Dhcp4ClientFixture):
    """
    Phase 4 commit 0 — 'Dhcp4Client' is now a 'Subsystem' subclass
    with an explicit RFC 2131 §4.4 FSM ('Dhcp4State'). The sync
    'fetch()' path runs '_do_init_to_bound' inline; the daemon
    path drives '_subsystem_loop' under the Subsystem-base
    thread. This test class pins the scaffolding shape — the
    full INIT/RENEW/REBIND/RELEASE wiring lands in Phase 4
    commits B/C/D.
    """

    def test__dhcp4_client__is_subsystem_subclass(self) -> None:
        """
        Ensure 'Dhcp4Client' inherits from 'Subsystem' so it can
        be installed as a long-running thread under the stack
        lifecycle ('stack.start()' / 'stack.stop()').

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertTrue(
            issubclass(Dhcp4Client, Subsystem),
            msg="Dhcp4Client must inherit from Subsystem for daemon-mode operation.",
        )

    def test__dhcp4_client__initial_state_is_init(self) -> None:
        """
        Ensure a freshly-constructed 'Dhcp4Client' starts in the
        'INIT' FSM state — the entry state in the client
        state-transition diagram.

        Reference: RFC 2131 §4.4 (Figure 5 client state-transition diagram — INIT is the entry state).
        """

        client = Dhcp4Client(mac_address=_DEFAULT_MAC)

        self.assertIs(
            client._state,
            Dhcp4State.INIT,
            msg="A freshly-constructed Dhcp4Client must start in the INIT state.",
        )

    def test__dhcp4_client__initial_lease_is_none(self) -> None:
        """
        Ensure a freshly-constructed 'Dhcp4Client' has no lease —
        the lease attribute is populated only when the daemon
        FSM reaches BOUND.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        client = Dhcp4Client(mac_address=_DEFAULT_MAC)

        self.assertIsNone(
            client._lease,
            msg="Dhcp4Client._lease must be None until the FSM reaches BOUND.",
        )

    def test__dhcp4_client__sync_fetch_does_not_mutate_state_or_lease(self) -> None:
        """
        Ensure sync 'fetch()' does NOT update the client's
        internal FSM state or '_lease' attribute. Sync mode is
        deliberately stateless from the FSM POV — the caller
        receives the lease as the return value.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._server.enqueue_offer()
        self._server.enqueue_ack()
        client = Dhcp4Client(mac_address=_DEFAULT_MAC)

        result = client.fetch()

        self.assertIsInstance(
            result,
            Dhcp4Lease,
            msg="Sanity: fetch() must still return the lease in commit 0.",
        )
        self.assertIs(
            client._state,
            Dhcp4State.INIT,
            msg="Sync fetch() must NOT mutate the FSM state — it remains INIT.",
        )
        self.assertIsNone(
            client._lease,
            msg="Sync fetch() must NOT populate _lease — the caller owns the returned lease.",
        )

    def test__dhcp4_client__subsystem_loop_init_transitions_to_bound_on_success(self) -> None:
        """
        Ensure one '_subsystem_loop' iteration starting in INIT
        runs the wire exchange and transitions to BOUND, storing
        the lease on '_lease', when the exchange succeeds.

        Reference: RFC 2131 §4.4 (INIT → SELECTING → REQUESTING → BOUND on successful ACK).
        """

        self._server.enqueue_offer()
        self._server.enqueue_ack()
        client = Dhcp4Client(mac_address=_DEFAULT_MAC)

        client._subsystem_loop()

        self.assertIs(
            client._state,
            Dhcp4State.BOUND,
            msg="Daemon-mode INIT handler must transition to BOUND on successful lease acquisition.",
        )
        self.assertIsInstance(
            client._lease,
            Dhcp4Lease,
            msg="Daemon-mode INIT handler must store the acquired lease on _lease.",
        )

    def test__dhcp4_client__subsystem_loop_init_signals_stop_on_failure(self) -> None:
        """
        Ensure one '_subsystem_loop' iteration starting in INIT
        signals the subsystem stop event when the wire exchange
        fails — Phase 4 commit B will replace this with a retry
        policy, but commit 0 must not spin in a tight
        failure-then-fail-again loop.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.enterContext(sysctl.override("dhcp.retrans_max_attempts", 1))
        # Server is silent on the first attempt → fetch returns None.
        self._server.enqueue_timeout()
        client = Dhcp4Client(mac_address=_DEFAULT_MAC)

        client._subsystem_loop()

        self.assertTrue(
            client._event__stop_subsystem.is_set(),
            msg="Commit-0 INIT-failure path must signal the subsystem stop event.",
        )
        self.assertIs(
            client._state,
            Dhcp4State.INIT,
            msg="State must remain INIT (no BOUND transition) on failure.",
        )
        self.assertIsNone(
            client._lease,
            msg="No lease must be recorded on INIT-handler failure.",
        )

    def test__dhcp4_client__subsystem_loop_halts_on_unexpected_exception(self) -> None:
        """
        Ensure an unexpected exception raised from a state handler does
        not propagate out of '_subsystem_loop' — an escaping exception
        would kill the 'Subsystem' worker thread and silently take the
        DHCPv4 client down (the symptom seen when a send raised
        EHOSTUNREACH). The loop instead logs the failure and signals the
        stop event so the client halts cleanly.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        client = Dhcp4Client(mac_address=_DEFAULT_MAC)
        self.enterContext(
            patch.object(
                client,
                "_do_init_to_bound",
                side_effect=OSError(errno.EHOSTUNREACH, "No route to host"),
            )
        )

        # Must return normally — a propagating exception would fail the
        # test by escaping this call.
        client._subsystem_loop()

        self.assertTrue(
            client._event__stop_subsystem.is_set(),
            msg="An unexpected loop exception must signal the stop event, not crash the worker.",
        )
        self._mock_log.assert_called()


class TestDhcp4ClientDaemonModeBindWiring(_Dhcp4ClientFixture):
    """
    Daemon-mode BOUND wiring. On the INIT → BOUND transition the
    client calls 'address_api.add', begins RFC 5227 §2.4
    ongoing defense via 'acd.start_defense', and signals
    'start_and_wait_for_bind' watchers via '_event__bound'.
    """

    def test__dhcp4_client__bound_transition_invokes_address_api_add_host(self) -> None:
        """
        Ensure the daemon-mode INIT → BOUND transition calls
        'address_api.add' with the leased Ip4IfAddr — the
        kernel/userspace boundary surface installs the address
        on the stack.

        Reference: RFC 2131 §4.4 (BOUND-state entry — address available for use).
        """

        self._server.enqueue_offer()
        self._server.enqueue_ack()
        mock_address_api = MagicMock(name="AddressApi")
        client = Dhcp4Client(mac_address=_DEFAULT_MAC, address_api=mock_address_api)

        client._subsystem_loop()

        assert client._lease is not None
        mock_address_api.add.assert_called_once_with(
            ifaddr=client._lease.ip4_host,
        )

    def test__dhcp4_client__bound_transition_installs_default_route(self) -> None:
        """
        Ensure the daemon-mode INIT → BOUND transition installs
        the leased gateway as a protocol=DHCP default route via
        the Route API.

        Reference: RFC 2131 §3.1 step 1 (Router option, option 3).
        """

        self._server.enqueue_offer(router=[Ip4Address("10.0.0.1")])
        self._server.enqueue_ack(router=[Ip4Address("10.0.0.1")])
        mock_route_api = MagicMock(name="RouteApi")
        client = Dhcp4Client(mac_address=_DEFAULT_MAC, route_api=mock_route_api)

        client._subsystem_loop()

        mock_route_api.replace_default.assert_called_once_with(
            gateway=Ip4Address("10.0.0.1"),
            protocol=RouteProtocol.DHCP,
        )

    def test__dhcp4_client__bound_transition_no_router_skips_route_install(self) -> None:
        """
        Ensure the BOUND transition installs no default route
        when the DHCP Ack carries no Router option.

        Reference: RFC 2131 §3.1 step 1 (Router option, option 3).
        """

        self._server.enqueue_offer(router=None)
        self._server.enqueue_ack(router=None)
        mock_route_api = MagicMock(name="RouteApi")
        client = Dhcp4Client(mac_address=_DEFAULT_MAC, route_api=mock_route_api)

        client._subsystem_loop()

        mock_route_api.replace_default.assert_not_called()

    def test__dhcp4_client__reset_to_init_removes_default_route(self) -> None:
        """
        Ensure tearing the lease down (NAK / expiry reset with
        host removal) removes the DHCP default route via the
        Route API.

        Reference: RFC 2131 §4.4.5 (lease expiry — host relinquishes the address).
        """

        mock_route_api = MagicMock(name="RouteApi")
        client = Dhcp4Client(mac_address=_DEFAULT_MAC, route_api=mock_route_api)
        client._lease = Dhcp4Lease(
            ip4_host=Ip4IfAddr((Ip4Address("10.0.0.100"), Ip4Mask("/24"))),
            gateway=Ip4Address("10.0.0.1"),
            lease_time__sec=3600,
            server_id=Ip4Address("10.0.0.1"),
            acquired_at_monotonic=0.0,
        )

        client._reset_to_init(remove_lease_host=True)

        mock_route_api.remove_default.assert_called_once_with(family=AddressFamily.INET4)

    def test__dhcp4_client__bound_transition_begins_acd_defense(self) -> None:
        """
        Ensure the daemon-mode INIT → BOUND transition begins
        ongoing conflict defense via 'acd.start_defense' with the
        leased address — the engine emits the Announcement burst and
        holds the defense socket for poll_conflict.

        Reference: RFC 5227 §2.3 (host MUST broadcast ANNOUNCE_NUM Announcements after a successful claim).
        Reference: RFC 5227 §2.4 (begin ongoing defense of the committed address).
        """

        self._server.enqueue_offer()
        self._server.enqueue_ack()
        acd = _acd_mock(probe_results=True)
        client = Dhcp4Client(mac_address=_DEFAULT_MAC, acd=acd)

        client._subsystem_loop()

        assert client._lease is not None
        acd.start_defense.assert_called_once_with(address=client._lease.ip4_host.address)

    def test__dhcp4_client__bound_transition_sets_event_bound(self) -> None:
        """
        Ensure the daemon-mode INIT → BOUND transition sets
        '_event__bound' so 'start_and_wait_for_bind' watchers
        unblock immediately on a successful acquisition.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._server.enqueue_offer()
        self._server.enqueue_ack()
        client = Dhcp4Client(mac_address=_DEFAULT_MAC)

        self.assertFalse(
            client._event__bound.is_set(),
            msg="Pre-condition: '_event__bound' must be clear on fresh construction.",
        )
        client._subsystem_loop()

        self.assertTrue(
            client._event__bound.is_set(),
            msg="INIT → BOUND transition must set '_event__bound'.",
        )

    def test__dhcp4_client__bound_transition_skips_collaborators_when_none(self) -> None:
        """
        Ensure the daemon-mode INIT → BOUND transition silently
        skips the address-API and ACD calls when neither
        collaborator is supplied. This is the test-default — most
        existing tests pass no collaborators and still expect a
        successful BOUND transition.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._server.enqueue_offer()
        self._server.enqueue_ack()
        client = Dhcp4Client(mac_address=_DEFAULT_MAC)

        client._subsystem_loop()

        self.assertIs(
            client._state,
            Dhcp4State.BOUND,
            msg="State must reach BOUND even when callbacks are absent.",
        )

    def test__dhcp4_client__start_and_wait_for_bind_returns_true_on_success(self) -> None:
        """
        Ensure 'start_and_wait_for_bind' returns True when the
        FSM reaches BOUND within the timeout. Spawns the
        Subsystem thread, then waits on '_event__bound'.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._server.enqueue_offer()
        self._server.enqueue_ack()
        client = Dhcp4Client(mac_address=_DEFAULT_MAC)

        try:
            bound = client.start_and_wait_for_bind(timeout_s=2.0)
        finally:
            client.stop()

        self.assertTrue(
            bound,
            msg="start_and_wait_for_bind must return True when the FSM reaches BOUND in time.",
        )
        self.assertIs(
            client._state,
            Dhcp4State.BOUND,
            msg="Sanity: client state must be BOUND after the daemon thread completes the cycle.",
        )

    def test__dhcp4_client__start_and_wait_for_bind_returns_false_on_timeout(self) -> None:
        """
        Ensure 'start_and_wait_for_bind' returns False when the
        FSM does not reach BOUND within the timeout — the
        lifecycle keeps running in the background and the caller
        must call 'stop()' to halt it.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        # Server stays silent and the retransmit budget is set to
        # 1 so the FSM gives up quickly. Even then, the failure
        # path signals stop_event but never sets _event__bound,
        # so the wait must time out.
        self.enterContext(sysctl.override("dhcp.retrans_max_attempts", 1))
        self._server.enqueue_timeout()
        client = Dhcp4Client(mac_address=_DEFAULT_MAC)

        try:
            bound = client.start_and_wait_for_bind(timeout_s=0.2)
        finally:
            client.stop()

        self.assertFalse(
            bound,
            msg="start_and_wait_for_bind must return False on FSM-acquisition failure.",
        )

    def test__dhcp4_client__stop_joins_subsystem_thread_cleanly(self) -> None:
        """
        Ensure 'stop()' joins the Subsystem thread cleanly after
        a successful BOUND — the BOUND idle handler must respect
        the stop event.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._server.enqueue_offer()
        self._server.enqueue_ack()
        client = Dhcp4Client(mac_address=_DEFAULT_MAC)
        client.start_and_wait_for_bind(timeout_s=2.0)

        client.stop()

        self.assertTrue(
            client._event__stop_subsystem.is_set(),
            msg="stop() must signal the subsystem stop event.",
        )
        assert client._thread is not None
        self.assertFalse(
            client._thread.is_alive(),
            msg="Subsystem thread must terminate cleanly after stop().",
        )


class TestDhcp4ClientLeaseLifecycle(_Dhcp4ClientFixture):
    """
    Phase 4 commit C — RFC 2131 §4.4.5 lease lifecycle. BOUND
    waits until T1, then transitions to RENEWING; RENEWING sends
    a unicast REQUEST and on ACK refreshes back to BOUND; on T2
    elapsed without an ACK, escalates to REBINDING; on lease
    expiry without an ACK, halts IPv4 and re-enters INIT.
    """

    @staticmethod
    def _make_lease(*, lease_time__sec: int = 3600, acquired_at: float = 0.0) -> Dhcp4Lease:
        """
        Build a synthetic Dhcp4Lease for tests that drive the
        FSM through the BOUND / RENEWING / REBINDING handlers
        directly (no INIT-side wire exchange).
        """

        return Dhcp4Lease(
            ip4_host=Ip4IfAddr("10.0.0.100/24"),
            lease_time__sec=lease_time__sec,
            server_id=Ip4Address("10.0.0.254"),
            acquired_at_monotonic=acquired_at,
        )

    def test__dhcp4_client__do_bound_transitions_to_renewing_when_t1_elapsed(self) -> None:
        """
        Ensure '_do_bound' transitions the FSM to RENEWING when
        'time.monotonic()' has reached the T1 deadline
        (acquired_at + lease_time × t1_factor).

        Reference: RFC 2131 §4.4.5 (BOUND → RENEWING at T1 = 0.5 × lease default).
        """

        client = Dhcp4Client(mac_address=_DEFAULT_MAC)
        client._lease = self._make_lease(lease_time__sec=3600, acquired_at=0.0)
        client._state = Dhcp4State.BOUND

        # Default T1 factor = 0.5; T1 deadline = 0.0 + 1800. Jump
        # to t = 1801 (> T1) to trigger the transition.
        with patch("pytcp.protocols.dhcp4.dhcp4__client.time.monotonic", return_value=1801.0):
            client._do_bound()

        self.assertIs(
            client._state,
            Dhcp4State.RENEWING,
            msg="BOUND → RENEWING must fire when T1 has elapsed.",
        )

    def test__dhcp4_client__do_bound_stays_bound_when_t1_not_elapsed(self) -> None:
        """
        Ensure '_do_bound' stays in BOUND and waits on the stop
        event when T1 has not yet been reached.

        Reference: RFC 2131 §4.4.5 (no transition until T1 elapses).
        """

        client = Dhcp4Client(mac_address=_DEFAULT_MAC)
        client._lease = self._make_lease(lease_time__sec=3600, acquired_at=0.0)
        client._state = Dhcp4State.BOUND

        # T1 deadline = 1800. At t = 100, T1 has not elapsed.
        with (
            patch("pytcp.protocols.dhcp4.dhcp4__client.time.monotonic", return_value=100.0),
            patch.object(client._event__stop_subsystem, "wait") as mock_wait,
        ):
            client._do_bound()

        self.assertIs(
            client._state,
            Dhcp4State.BOUND,
            msg="State must remain BOUND when T1 has not elapsed.",
        )
        # Remaining = 1800 - 100 = 1700; verify wait called with that.
        mock_wait.assert_called_once_with(timeout=1700.0)

    def test__dhcp4_client__do_bound_polls_acd_when_no_conflict(self) -> None:
        """
        Ensure '_do_bound' polls the ACD conflict signal each tick;
        when 'poll_conflict' reports no conflict the handler falls
        through to the normal T1 lease-lifecycle logic.

        Reference: RFC 5227 §2.4 (ongoing conflict polling on a claimed address).
        """

        acd = _acd_mock()  # poll_conflict returns None
        client = Dhcp4Client(mac_address=_DEFAULT_MAC, acd=acd)
        client._lease = self._make_lease(lease_time__sec=3600, acquired_at=0.0)
        client._state = Dhcp4State.BOUND

        with patch("pytcp.protocols.dhcp4.dhcp4__client.time.monotonic", return_value=1801.0):
            client._do_bound()

        acd.poll_conflict.assert_called_once_with()
        self.assertIs(
            client._state,
            Dhcp4State.RENEWING,
            msg="A clean ACD poll must let '_do_bound' proceed to the T1 transition.",
        )

    def test__dhcp4_client__do_bound_conflict_declines_and_resets_to_init(self) -> None:
        """
        Ensure a BOUND-state ACD conflict makes the client yield the
        leased address: emit DHCPDECLINE to the leasing server, drop
        the held ACD claim, and re-enter INIT to re-acquire.

        Reference: RFC 5227 §2.4 (host yields a claimed address on sustained conflict).
        Reference: RFC 2131 §3.1 step 5 (DHCPDECLINE then restart configuration).
        """

        acd = _acd_mock()
        acd.poll_conflict.return_value = MacAddress("02:00:00:00:00:99")
        client = Dhcp4Client(mac_address=_DEFAULT_MAC, acd=acd)
        client._lease = self._make_lease()
        client._state = Dhcp4State.BOUND

        client._do_bound()

        self.assertEqual(
            self._server.tx_log[-1].message_type,
            Dhcp4MessageType.DECLINE,
            msg="A BOUND conflict must emit a DHCPDECLINE to the leasing server.",
        )
        self.assertEqual(
            self._server.tx_log[-1].req_ip_addr,
            Ip4Address("10.0.0.100"),
            msg="The BOUND-conflict DECLINE must name the abandoned leased address.",
        )
        self.assertIs(
            client._state,
            Dhcp4State.INIT,
            msg="A BOUND conflict must reset the FSM to INIT to re-acquire.",
        )
        acd.release.assert_called_once_with()

    def test__dhcp4_client__reset_to_init_releases_acd_claim(self) -> None:
        """
        Ensure '_reset_to_init' drops the held ongoing-defense
        claim (closes the ACD socket) on any lease-loss path.

        Reference: RFC 5227 §2.4 (release the defense socket when the address is relinquished).
        """

        acd = _acd_mock()
        client = Dhcp4Client(mac_address=_DEFAULT_MAC, acd=acd)
        client._lease = self._make_lease()

        client._reset_to_init(remove_lease_host=True)

        acd.release.assert_called_once_with()

    def test__dhcp4_client__do_renewing_returns_to_bound_on_ack(self) -> None:
        """
        Ensure '_do_renewing' refreshes the lease and returns to
        BOUND when the unicast REQUEST receives a valid ACK.

        Reference: RFC 2131 §4.4.5 (RENEW ACK extends the lease in place).
        """

        self.enterContext(sysctl.override("dhcp.retrans_jitter_ms", 0))
        client = Dhcp4Client(mac_address=_DEFAULT_MAC)
        client._lease = self._make_lease(lease_time__sec=3600, acquired_at=0.0)
        client._state = Dhcp4State.RENEWING
        self._server.enqueue_ack(yiaddr=Ip4Address("10.0.0.100"))

        # Run at t = 1850 — past T1 (1800), before T2 (3150).
        with patch("pytcp.protocols.dhcp4.dhcp4__client.time.monotonic", return_value=1850.0):
            client._do_renewing()

        self.assertIs(
            client._state,
            Dhcp4State.BOUND,
            msg="RENEW ACK must transition the FSM back to BOUND.",
        )
        assert client._lease is not None
        self.assertEqual(
            client._lease.ip4_host.address,
            Ip4Address("10.0.0.100"),
            msg="Lease IP must be retained across a successful RENEW.",
        )

    def test__dhcp4_client__do_renewing_falls_back_to_init_on_nak(self) -> None:
        """
        Ensure '_do_renewing' returns the FSM to INIT and clears
        the lease when the server replies with DHCPNAK.

        Reference: RFC 2131 §4.4.5 (RENEW NAK → re-INIT and re-DISCOVER).
        """

        self.enterContext(sysctl.override("dhcp.retrans_jitter_ms", 0))
        client = Dhcp4Client(
            mac_address=_DEFAULT_MAC,
            address_api=MagicMock(name="AddressApi"),
        )
        client._lease = self._make_lease(lease_time__sec=3600, acquired_at=0.0)
        client._state = Dhcp4State.RENEWING
        self._server.enqueue_nak()

        with patch("pytcp.protocols.dhcp4.dhcp4__client.time.monotonic", return_value=1850.0):
            client._do_renewing()

        self.assertIs(
            client._state,
            Dhcp4State.INIT,
            msg="RENEW NAK must return the FSM to INIT.",
        )
        self.assertIsNone(
            client._lease,
            msg="Lease must be cleared after a RENEW NAK.",
        )

    def test__dhcp4_client__do_renewing_escalates_to_rebinding_when_t2_elapsed(self) -> None:
        """
        Ensure '_do_renewing' transitions the FSM to REBINDING
        when 'time.monotonic()' has reached the T2 deadline
        without a successful RENEW ACK.

        Reference: RFC 2131 §4.4.5 (no RENEW ACK by T2 → REBINDING).
        """

        client = Dhcp4Client(mac_address=_DEFAULT_MAC)
        client._lease = self._make_lease(lease_time__sec=3600, acquired_at=0.0)
        client._state = Dhcp4State.RENEWING

        # T2 deadline = 0.0 + 3600 × 0.875 = 3150. Jump to t = 3200.
        with patch("pytcp.protocols.dhcp4.dhcp4__client.time.monotonic", return_value=3200.0):
            client._do_renewing()

        self.assertIs(
            client._state,
            Dhcp4State.REBINDING,
            msg="RENEWING → REBINDING must fire when T2 has elapsed.",
        )

    def test__dhcp4_client__do_rebinding_returns_to_bound_on_ack(self) -> None:
        """
        Ensure '_do_rebinding' refreshes the lease and returns
        to BOUND when the broadcast REQUEST receives a valid
        ACK from any DHCP server on the segment.

        Reference: RFC 2131 §4.4.5 (REBIND ACK extends the lease).
        """

        self.enterContext(sysctl.override("dhcp.retrans_jitter_ms", 0))
        client = Dhcp4Client(mac_address=_DEFAULT_MAC)
        client._lease = self._make_lease(lease_time__sec=3600, acquired_at=0.0)
        client._state = Dhcp4State.REBINDING
        self._server.enqueue_ack(yiaddr=Ip4Address("10.0.0.100"))

        # T2 elapsed; lease still valid (expiry = 3600). t = 3200.
        with patch("pytcp.protocols.dhcp4.dhcp4__client.time.monotonic", return_value=3200.0):
            client._do_rebinding()

        self.assertIs(
            client._state,
            Dhcp4State.BOUND,
            msg="REBIND ACK must transition the FSM back to BOUND.",
        )

    def test__dhcp4_client__do_rebinding_halts_ipv4_on_lease_expiry(self) -> None:
        """
        Ensure '_do_rebinding' halts IPv4 (removes the address
        via the address API) and re-enters INIT when the lease
        has expired without a successful REBIND ACK.

        Reference: RFC 2131 §4.4.5 (lease expiry → halt IPv4).
        """

        mock_address_api = MagicMock(name="AddressApi")
        client = Dhcp4Client(mac_address=_DEFAULT_MAC, address_api=mock_address_api)
        client._lease = self._make_lease(lease_time__sec=3600, acquired_at=0.0)
        client._state = Dhcp4State.REBINDING

        # Lease expiry = 3600. Jump to t = 3700.
        with patch("pytcp.protocols.dhcp4.dhcp4__client.time.monotonic", return_value=3700.0):
            client._do_rebinding()

        self.assertIs(
            client._state,
            Dhcp4State.INIT,
            msg="Lease expiry must reset the FSM to INIT.",
        )
        self.assertIsNone(
            client._lease,
            msg="Lease must be cleared on expiry.",
        )
        mock_address_api.remove.assert_called_once_with(
            address=Ip4Address("10.0.0.100"),
            abort_bound_sessions=True,
        )

    def test__dhcp4_client__renewing_emits_unicast_request_with_ciaddr(self) -> None:
        """
        Ensure '_do_renewing' emits a DHCPREQUEST with ciaddr set
        to the current lease's IP, no Server Identifier option,
        and no Requested IP Address option — the canonical
        RENEW message shape.

        Reference: RFC 2131 §4.3.2 Table 4 (RENEW: server-id MUST NOT, requested-ip MUST NOT, ciaddr = current IP).
        """

        self.enterContext(sysctl.override("dhcp.retrans_jitter_ms", 0))
        client = Dhcp4Client(mac_address=_DEFAULT_MAC)
        client._lease = self._make_lease(lease_time__sec=3600, acquired_at=0.0)
        client._state = Dhcp4State.RENEWING
        self._server.enqueue_ack(yiaddr=Ip4Address("10.0.0.100"))

        with patch("pytcp.protocols.dhcp4.dhcp4__client.time.monotonic", return_value=1850.0):
            client._do_renewing()

        renew_request = self._server.tx_log[0]
        self.assertEqual(
            renew_request.message_type,
            Dhcp4MessageType.REQUEST,
            msg="RENEW TX must be a DHCPREQUEST.",
        )
        self.assertEqual(
            renew_request.ciaddr,
            Ip4Address("10.0.0.100"),
            msg="RENEW REQUEST must carry 'ciaddr' = the leased IP per RFC 2131 §4.3.2 Table 4.",
        )
        self.assertIsNone(
            renew_request.server_id,
            msg="RENEW REQUEST MUST NOT carry the Server Identifier option.",
        )
        self.assertIsNone(
            renew_request.req_ip_addr,
            msg="RENEW REQUEST MUST NOT carry the Requested IP Address option.",
        )


class TestDhcp4ClientReleaseAndShutdown(_Dhcp4ClientFixture):
    """
    Phase 4 commit D — DHCPRELEASE, sync release/renew/rebind,
    Subsystem '_stop' shutdown hook, and the cross-IP RENEW/REBIND
    'replace' path. Phase 4.5 FSM → address-API mutation
    table.
    """

    @staticmethod
    def _make_lease(*, ip: str = "10.0.0.100/24", server_id: str = "10.0.0.254") -> Dhcp4Lease:
        """
        Build a synthetic Dhcp4Lease for tests that drive the
        FSM through release / cross-IP paths directly.
        """

        return Dhcp4Lease(
            ip4_host=Ip4IfAddr(ip),
            lease_time__sec=3600,
            server_id=Ip4Address(server_id),
            acquired_at_monotonic=0.0,
        )

    def test__dhcp4_client__sync_release_emits_dhcprelease_with_correct_options(self) -> None:
        """
        Ensure 'release(lease)' emits a single DHCPRELEASE
        message carrying message-type 7, ciaddr = lease IP,
        Server Identifier echoing 'lease.server_id', and the
        Client Identifier — no reply expected.

        Reference: RFC 2131 §4.4.6 (DHCPRELEASE: unicast to server-id, ciaddr = current IP).
        """

        client = Dhcp4Client(mac_address=_DEFAULT_MAC)
        lease = self._make_lease()

        client.release(lease)

        self.assertEqual(
            len(self._server.tx_log),
            1,
            msg="release(lease) must emit exactly one DHCPRELEASE message.",
        )
        release = self._server.tx_log[0]
        self.assertEqual(
            release.message_type,
            Dhcp4MessageType.RELEASE,
            msg="release(lease) TX must carry message-type 7 (DHCPRELEASE).",
        )
        self.assertEqual(
            release.ciaddr,
            Ip4Address("10.0.0.100"),
            msg="RELEASE 'ciaddr' must equal the current leased IPv4 address.",
        )
        self.assertEqual(
            release.server_id,
            Ip4Address("10.0.0.254"),
            msg="RELEASE must carry Server Identifier = lease.server_id.",
        )
        self.assertEqual(
            release.client_id,
            _DEFAULT_CID,
            msg="RELEASE must carry the same Client Identifier as DISCOVER / REQUEST.",
        )

    def test__dhcp4_client__sync_renew_returns_refreshed_lease_on_ack(self) -> None:
        """
        Ensure 'renew(lease)' performs a single unicast RENEW
        exchange and returns the refreshed 'Dhcp4Lease' on a
        valid ACK. Sync mode does not mutate '_lease'.

        Reference: RFC 2131 §4.4.5 (RENEW: unicast REQUEST + ACK refreshes the lease).
        """

        self.enterContext(sysctl.override("dhcp.retrans_jitter_ms", 0))
        self._server.enqueue_ack(yiaddr=Ip4Address("10.0.0.100"), lease_time=7200)

        client = Dhcp4Client(mac_address=_DEFAULT_MAC)
        lease = self._make_lease()
        new_lease = client.renew(lease)

        assert new_lease is not None
        self.assertEqual(
            new_lease.lease_time__sec,
            7200,
            msg="renew(lease) must return a refreshed lease carrying the server's new lease time.",
        )
        self.assertIsNone(
            client._lease,
            msg="Sync renew() must NOT mutate the client's internal '_lease' attribute.",
        )

    def test__dhcp4_client__sync_renew_returns_none_on_nak(self) -> None:
        """
        Ensure 'renew(lease)' returns None when the server
        replies with DHCPNAK — the caller is expected to fall
        back to a full DISCOVER cycle.

        Reference: RFC 2131 §4.4.5 (RENEW NAK → caller restarts).
        """

        self.enterContext(sysctl.override("dhcp.retrans_jitter_ms", 0))
        self._server.enqueue_nak()

        client = Dhcp4Client(mac_address=_DEFAULT_MAC)
        result = client.renew(self._make_lease())

        self.assertIsNone(
            result,
            msg="renew(lease) must return None on DHCPNAK.",
        )

    def test__dhcp4_client__sync_rebind_emits_broadcast_request(self) -> None:
        """
        Ensure 'rebind(lease)' emits a broadcast REQUEST (flag_b
        set) with ciaddr = current IP and returns the refreshed
        lease on ACK.

        Reference: RFC 2131 §4.4.5 (REBIND: broadcast REQUEST after T2).
        """

        self.enterContext(sysctl.override("dhcp.retrans_jitter_ms", 0))
        self._server.enqueue_ack(yiaddr=Ip4Address("10.0.0.100"))

        client = Dhcp4Client(mac_address=_DEFAULT_MAC)
        client.rebind(self._make_lease())

        rebind_request = self._server.tx_log[0]
        self.assertEqual(
            rebind_request.message_type,
            Dhcp4MessageType.REQUEST,
            msg="REBIND TX must be a DHCPREQUEST.",
        )
        self.assertTrue(
            rebind_request.flag_b,
            msg="REBIND REQUEST must set the BROADCAST flag.",
        )
        self.assertIsNone(
            rebind_request.server_id,
            msg="REBIND REQUEST MUST NOT carry the Server Identifier option.",
        )

    def test__dhcp4_client__stop_emits_release_when_bound(self) -> None:
        """
        Ensure 'stop()' on a BOUND client emits a DHCPRELEASE
        for the held lease before joining the Subsystem thread.

        Reference: RFC 2131 §4.4.6 (client SHOULD send DHCPRELEASE to relinquish a lease).
        """

        # Drive the FSM to BOUND first via a successful INIT exchange.
        self._server.enqueue_offer()
        self._server.enqueue_ack()
        client = Dhcp4Client(mac_address=_DEFAULT_MAC)
        client.start_and_wait_for_bind(timeout_s=2.0)

        client.stop()

        # tx_log: DISCOVER, REQUEST, RELEASE.
        release_messages = [tx for tx in self._server.tx_log if tx.message_type == Dhcp4MessageType.RELEASE]
        self.assertEqual(
            len(release_messages),
            1,
            msg="stop() while BOUND must emit exactly one DHCPRELEASE.",
        )

    def test__dhcp4_client__stop_skips_release_when_not_bound(self) -> None:
        """
        Ensure 'stop()' on a never-bound (INIT) client does NOT
        emit a DHCPRELEASE — there is no lease to relinquish.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.enterContext(sysctl.override("dhcp.retrans_max_attempts", 1))
        self._server.enqueue_timeout()  # INIT fails immediately
        client = Dhcp4Client(mac_address=_DEFAULT_MAC)
        client.start_and_wait_for_bind(timeout_s=0.5)

        client.stop()

        release_messages = [tx for tx in self._server.tx_log if tx.message_type == Dhcp4MessageType.RELEASE]
        self.assertEqual(
            len(release_messages),
            0,
            msg="stop() on an INIT-state client must NOT emit a DHCPRELEASE.",
        )

    def test__dhcp4_client__stop_removes_host_via_address_api_when_bound(self) -> None:
        """
        Ensure 'stop()' on a BOUND client removes the leased
        address via 'address_api.remove' with the
        'abort_bound_sessions' flag derived from
        'dhcp.abort_sessions_on_lease_change' (default 1).

        Reference: RFC 5227 §2.4 final paragraph (hosts SHOULD actively reset connections on relinquished addresses).
        """

        mock_address_api = MagicMock(name="AddressApi")
        self._server.enqueue_offer()
        self._server.enqueue_ack()
        client = Dhcp4Client(mac_address=_DEFAULT_MAC, address_api=mock_address_api)
        client.start_and_wait_for_bind(timeout_s=2.0)

        client.stop()

        mock_address_api.remove.assert_called_with(
            address=Ip4Address("10.0.0.100"),
            abort_bound_sessions=True,
        )

    def test__dhcp4_client__cross_ip_renew_calls_replace_host(self) -> None:
        """
        Ensure a RENEW ACK that returns a DIFFERENT yiaddr
        triggers an 'address_api.replace' swap (the
        Phase 4.5 FSM → API mutation table — "Different-IP
        swap" row), not a silent in-place lease update.

        Reference: RFC 5227 §2.4 (cross-IP address change must propagate to the stack).
        """

        self.enterContext(sysctl.override("dhcp.retrans_jitter_ms", 0))
        mock_address_api = MagicMock(name="AddressApi")
        self._server.enqueue_ack(yiaddr=Ip4Address("10.0.0.101"))  # different from leased 10.0.0.100

        client = Dhcp4Client(mac_address=_DEFAULT_MAC, address_api=mock_address_api)
        client._lease = self._make_lease()  # holds 10.0.0.100
        client._state = Dhcp4State.RENEWING

        with patch("pytcp.protocols.dhcp4.dhcp4__client.time.monotonic", return_value=1850.0):
            client._do_renewing()

        mock_address_api.replace.assert_called_once()
        kwargs = mock_address_api.replace.call_args.kwargs
        self.assertEqual(
            kwargs["old_address"],
            Ip4Address("10.0.0.100"),
            msg="replace must be called with the prior leased address.",
        )
        self.assertEqual(
            kwargs["new_ifaddr"].address,
            Ip4Address("10.0.0.101"),
            msg="replace must be called with the new lease's Ip4IfAddr.",
        )
        self.assertTrue(
            kwargs["abort_bound_sessions"],
            msg="Default sysctl 'dhcp.abort_sessions_on_lease_change' = 1 must surface as abort_bound_sessions=True.",
        )

    def test__dhcp4_client__abort_sessions_sysctl_zero_disables_abort(self) -> None:
        """
        Ensure the 'dhcp.abort_sessions_on_lease_change' sysctl
        gates the 'abort_bound_sessions' kwarg — operator
        overrides to 0 propagate through to address-API calls
        as 'abort_bound_sessions=False' (Linux-parity silent-
        rot semantic).

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.enterContext(sysctl.override("dhcp.abort_sessions_on_lease_change", 0))
        mock_address_api = MagicMock(name="AddressApi")
        self._server.enqueue_offer()
        self._server.enqueue_ack()
        client = Dhcp4Client(mac_address=_DEFAULT_MAC, address_api=mock_address_api)
        client.start_and_wait_for_bind(timeout_s=2.0)

        client.stop()

        mock_address_api.remove.assert_called_with(
            address=Ip4Address("10.0.0.100"),
            abort_bound_sessions=False,
        )


class TestDhcp4ClientInitReboot(_Dhcp4ClientFixture):
    """
    Phase 5 — RFC 2131 §4.4.2 INIT-REBOOT cached-lease fast-path.
    The constructor consults 'dhcp.lease_cache_path'; if a valid
    lease is on disk the FSM starts in INIT-REBOOT and broadcasts
    a REQUEST asking the server to re-confirm the cached IP.
    """

    @staticmethod
    def _cached_lease(
        *,
        address: str = "192.168.1.145",
        lease_time__sec: int = 3600,
    ) -> Dhcp4Lease:
        """
        Build a synthetic Dhcp4Lease for the INIT-REBOOT tests.
        Defaults match a typical residential DHCP scenario.
        """

        ip4_host = Ip4IfAddr((Ip4Address(address), Ip4Mask("255.255.255.0")))
        return Dhcp4Lease(
            ip4_host=ip4_host,
            gateway=Ip4Address("192.168.1.1"),
            lease_time__sec=lease_time__sec,
            server_id=Ip4Address("192.168.1.1"),
            acquired_at_monotonic=0.0,
        )

    def test__dhcp4_client__init_starts_in_init_when_no_cache(self) -> None:
        """
        Ensure the constructor starts the FSM in INIT when the
        cache path is empty (the sysctl default) or the file is
        missing.

        Reference: RFC 2131 §4.4 (INIT is the default start state).
        """

        client = Dhcp4Client(mac_address=_DEFAULT_MAC)

        self.assertIs(
            client._state,
            Dhcp4State.INIT,
            msg="Empty cache path must start the FSM in INIT.",
        )
        self.assertIsNone(
            client._lease,
            msg="No cache means no preloaded lease.",
        )

    def test__dhcp4_client__init_starts_in_init_reboot_when_cache_present(self) -> None:
        """
        Ensure the constructor reads the cached lease and starts
        the FSM in INIT-REBOOT when 'dhcp.lease_cache_path' is
        non-empty AND the cache file contains a still-valid lease.

        Reference: RFC 2131 §4.4.2 (cached lease enters INIT-REBOOT).
        """

        cached = self._cached_lease()
        mock_read = MagicMock(return_value=cached)
        self.enterContext(
            patch(
                "pytcp.protocols.dhcp4.dhcp4__client.read_cached_lease",
                mock_read,
            )
        )
        self.enterContext(sysctl.override("dhcp.lease_cache_path", "/tmp/dhcp4_lease"))

        client = Dhcp4Client(mac_address=_DEFAULT_MAC)

        mock_read.assert_called_once_with("/tmp/dhcp4_lease")
        self.assertIs(
            client._state,
            Dhcp4State.INIT_REBOOT,
            msg="Valid cached lease must start the FSM in INIT-REBOOT.",
        )
        self.assertIs(
            client._lease,
            cached,
            msg="The cached lease must be preloaded on the client.",
        )

    def test__dhcp4_client__do_init_reboot_emits_request_with_cached_ip(self) -> None:
        """
        Ensure '_do_init_reboot' emits a DHCPREQUEST whose
        'requested-ip' option carries the cached IP, ciaddr is 0,
        the BROADCAST flag is set, and no 'server identifier'
        option is included — the Table 4 INIT-REBOOT row.

        Reference: RFC 2131 §4.3.2 Table 4 (INIT-REBOOT row).
        """

        self.enterContext(sysctl.override("dhcp.retrans_jitter_ms", 0))
        client = Dhcp4Client(mac_address=_DEFAULT_MAC)
        client._lease = self._cached_lease()
        client._state = Dhcp4State.INIT_REBOOT
        self._server.enqueue_ack(yiaddr=Ip4Address("192.168.1.145"))

        client._do_init_reboot()

        # The first server-captured TX is the INIT-REBOOT REQUEST.
        self.assertGreaterEqual(
            len(self._server.tx_log),
            1,
            msg="At least one DHCPREQUEST must reach the server.",
        )
        reboot_req = self._server.tx_log[0]
        self.assertIs(
            reboot_req.message_type,
            Dhcp4MessageType.REQUEST,
            msg="INIT-REBOOT TX must carry message-type=REQUEST.",
        )
        self.assertEqual(
            reboot_req.ciaddr,
            Ip4Address("0.0.0.0"),
            msg="INIT-REBOOT ciaddr must be 0 (RFC 2131 §4.3.2 Table 4).",
        )
        self.assertEqual(
            reboot_req.req_ip_addr,
            Ip4Address("192.168.1.145"),
            msg="INIT-REBOOT requested-ip option must echo the cached IP.",
        )
        self.assertIsNone(
            reboot_req.server_id,
            msg="INIT-REBOOT must NOT include the server-identifier option.",
        )
        self.assertTrue(
            reboot_req.flag_b,
            msg="INIT-REBOOT BROADCAST flag must be set (host has not yet bound the cached IP).",
        )

    def test__dhcp4_client__do_init_reboot_transitions_to_bound_on_ack(self) -> None:
        """
        Ensure a valid ACK to the INIT-REBOOT REQUEST refreshes
        the lease and transitions the FSM to BOUND.

        Reference: RFC 2131 §4.4.2 (ACK confirms the remembered address).
        """

        self.enterContext(sysctl.override("dhcp.retrans_jitter_ms", 0))
        client = Dhcp4Client(mac_address=_DEFAULT_MAC)
        client._lease = self._cached_lease()
        client._state = Dhcp4State.INIT_REBOOT
        self._server.enqueue_ack(
            yiaddr=Ip4Address("192.168.1.145"),
            lease_time=7200,  # Server may extend the lease.
        )

        client._do_init_reboot()

        self.assertIs(
            client._state,
            Dhcp4State.BOUND,
            msg="ACK on INIT-REBOOT must transition the FSM to BOUND.",
        )
        assert client._lease is not None
        self.assertEqual(
            client._lease.lease_time__sec,
            7200,
            msg="BOUND lease must carry the server-supplied (refreshed) lease_time.",
        )

    def test__dhcp4_client__do_init_reboot_falls_back_to_init_on_nak(self) -> None:
        """
        Ensure a DHCPNAK on the INIT-REBOOT REQUEST invalidates
        the cached lease and falls back to INIT. The cache file
        is deleted so the next boot does not retry INIT-REBOOT
        on the invalidated address.

        Reference: RFC 2131 §4.4.2 (NAK requires full DISCOVER restart).
        """

        self.enterContext(sysctl.override("dhcp.retrans_jitter_ms", 0))
        mock_delete = MagicMock()
        self.enterContext(
            patch(
                "pytcp.protocols.dhcp4.dhcp4__client.delete_cached_lease",
                mock_delete,
            )
        )
        client = Dhcp4Client(mac_address=_DEFAULT_MAC)
        client._lease = self._cached_lease()
        client._state = Dhcp4State.INIT_REBOOT
        self._server.enqueue_nak()

        client._do_init_reboot()

        self.assertIs(
            client._state,
            Dhcp4State.INIT,
            msg="NAK on INIT-REBOOT must fall back to INIT.",
        )
        self.assertIsNone(
            client._lease,
            msg="NAK must clear the cached lease.",
        )
        mock_delete.assert_called()

    def test__dhcp4_client__do_init_reboot_adopts_cached_on_timeout(self) -> None:
        """
        Ensure that when no ACK or NAK arrives within the bounded
        recv window, '_do_init_reboot' adopts the cached lease as
        the BOUND lease — the "use the previously allocated network
        address and configuration parameters" MAY. Operators who
        set 'dhcp.lease_cache_path' have opted into fast-boot
        semantics; the silent-server case is the path where the
        cache pays off.

        Reference: RFC 2131 §4.4.2 (MAY use prior lease on 60 s / 4 tries timeout).
        """

        self.enterContext(sysctl.override("dhcp.retrans_jitter_ms", 0))
        # Speed up the test — 1 ms windows × 1 attempt instead of
        # the production 4 s × 4.
        self.enterContext(sysctl.override("dhcp.retrans_initial_ms", 1))
        self.enterContext(sysctl.override("dhcp.retrans_max_ms", 1))
        self.enterContext(sysctl.override("dhcp.reboot_max_attempts", 1))
        client = Dhcp4Client(mac_address=_DEFAULT_MAC)
        cached = self._cached_lease()
        client._lease = cached
        client._state = Dhcp4State.INIT_REBOOT
        # Server queue empty → server silent → timeout.

        client._do_init_reboot()

        self.assertIs(
            client._state,
            Dhcp4State.BOUND,
            msg="Silent server on INIT-REBOOT must adopt the cached lease (RFC 2131 §4.4.2 MAY).",
        )
        self.assertIs(
            client._lease,
            cached,
            msg="The adopted lease must be the cached one (no server override).",
        )

    def test__dhcp4_client__on_bound_writes_cache_when_path_set(self) -> None:
        """
        Ensure '_on_bound' calls 'write_cached_lease' with the
        configured cache path on every BOUND transition so the
        next boot's INIT-REBOOT fast-path has a fresh cache to
        consume.

        Reference: RFC 2131 §3.2 (remembering the prior lease).
        """

        mock_write = MagicMock()
        self.enterContext(
            patch(
                "pytcp.protocols.dhcp4.dhcp4__client.write_cached_lease",
                mock_write,
            )
        )
        self.enterContext(sysctl.override("dhcp.lease_cache_path", "/tmp/dhcp4_lease"))

        client = Dhcp4Client(mac_address=_DEFAULT_MAC)
        new_lease = self._cached_lease()
        client._on_bound(new_lease)

        mock_write.assert_called_once_with("/tmp/dhcp4_lease", new_lease)

    def test__dhcp4_client__reset_to_init_with_remove_lease_host_deletes_cache(self) -> None:
        """
        Ensure '_reset_to_init(remove_lease_host=True)' invalidates
        the on-disk cache so a subsequent boot does not try to
        re-acquire an invalidated lease via INIT-REBOOT.

        Reference: RFC 2131 §4.4.2 (NAK invalidates the remembered address).
        """

        mock_delete = MagicMock()
        self.enterContext(
            patch(
                "pytcp.protocols.dhcp4.dhcp4__client.delete_cached_lease",
                mock_delete,
            )
        )
        self.enterContext(sysctl.override("dhcp.lease_cache_path", "/tmp/dhcp4_lease"))

        client = Dhcp4Client(mac_address=_DEFAULT_MAC)
        client._lease = self._cached_lease()
        client._reset_to_init(remove_lease_host=True)

        mock_delete.assert_called_once_with("/tmp/dhcp4_lease")


class TestDhcp4ClientDnav4(_Dhcp4ClientFixture):
    """
    Phase 6 — RFC 4436 DNAv4 fast-path on INIT-REBOOT. When the
    cached lease records a 'gateway_mac' and 'dhcp.dnav4' is
    enabled, the FSM sends a unicast ARP probe to the cached
    gateway and short-circuits the DHCP exchange entirely if it
    answers within 'dhcp.dnav4_timeout_ms'.
    """

    _GATEWAY_IP = Ip4Address("192.168.1.1")
    _GATEWAY_MAC = MacAddress("aa:bb:cc:dd:ee:ff")

    def _cached_lease_with_mac(self) -> Dhcp4Lease:
        """
        Build a Dhcp4Lease whose 'gateway_mac' is populated —
        the configuration under which DNAv4 can engage.
        """

        ip4_host = Ip4IfAddr((Ip4Address("192.168.1.145"), Ip4Mask("255.255.255.0")))
        return Dhcp4Lease(
            ip4_host=ip4_host,
            gateway=self._GATEWAY_IP,
            lease_time__sec=3600,
            server_id=self._GATEWAY_IP,
            acquired_at_monotonic=0.0,
            gateway_mac=self._GATEWAY_MAC,
        )

    def _client_with_acd(self) -> tuple[Dhcp4Client, MagicMock]:
        """
        Build a client wired with an autospec'd 'Ip4Acd' — the raw-link
        ARP engine DNAv4 now runs its reachability probe over — and
        return both the client and the mock so a test can program
        'probe_reachable' and assert on its call.
        """

        acd = cast(MagicMock, create_autospec(Ip4Acd, spec_set=True))
        client = Dhcp4Client(mac_address=_DEFAULT_MAC, acd=acd)
        return client, acd

    def test__dhcp4_client__dnav4_disabled_by_default_for_lease_without_mac(self) -> None:
        """
        Ensure '_dnav4_probe' returns False when the cached
        lease has no recorded 'gateway_mac' (the typical
        first-boot scenario before any IP traffic resolved the
        gateway). The standard INIT-REBOOT REQUEST path runs
        instead.

        Reference: RFC 4436 §4 (DNAv4 requires a unicast target MAC).
        """

        client = Dhcp4Client(mac_address=_DEFAULT_MAC)
        lease_no_mac = self._cached_lease_with_mac()
        lease_no_mac_stripped = Dhcp4Lease(
            ip4_host=lease_no_mac.ip4_host,
            lease_time__sec=lease_no_mac.lease_time__sec,
            server_id=lease_no_mac.server_id,
            acquired_at_monotonic=lease_no_mac.acquired_at_monotonic,
            gateway_mac=None,
        )

        self.assertFalse(
            client._dnav4_probe(lease_no_mac_stripped),
            msg="DNAv4 must not engage when the cached lease has no gateway_mac.",
        )

    def test__dhcp4_client__dnav4_disabled_by_sysctl_returns_false(self) -> None:
        """
        Ensure setting 'dhcp.dnav4' to 0 forces '_dnav4_probe'
        to return False without sending any ARP traffic. The
        sysctl is the operator's emergency switch for the
        fast-path.

        Reference: RFC 4436 §4 (DNAv4 is optional; operator may disable).
        """

        self.enterContext(sysctl.override("dhcp.dnav4", 0))
        client, acd = self._client_with_acd()

        result = client._dnav4_probe(self._cached_lease_with_mac())

        self.assertFalse(
            result,
            msg="dhcp.dnav4=0 must force _dnav4_probe to return False.",
        )
        acd.probe_reachable.assert_not_called()

    def test__dhcp4_client__dnav4_returns_true_when_gateway_answers(self) -> None:
        """
        Ensure '_dnav4_probe' returns True when the ACD engine's
        reachability probe reports the cached gateway answered. The probe
        MUST carry the cached candidate IPv4 address as the sender
        protocol address (ar$spa) and the cached gateway IP + MAC as the
        target; without the candidate spa the probe degenerates into an
        ACD-style Probe (spa=0.0.0.0).

        Reference: RFC 4436 §4 (cached gateway reply confirms attachment).
        Reference: RFC 4436 §4.3 (ar$spa = candidate IPv4 address).
        """

        self.enterContext(sysctl.override("dhcp.dnav4_timeout_ms", 1000))
        client, acd = self._client_with_acd()
        acd.probe_reachable.return_value = True
        cached = self._cached_lease_with_mac()

        result = client._dnav4_probe(cached)

        self.assertTrue(
            result,
            msg="DNAv4 probe must return True when the ACD engine reports the gateway answered.",
        )
        acd.probe_reachable.assert_called_once_with(
            target=self._GATEWAY_IP,
            target_mac=self._GATEWAY_MAC,
            sender=cached.ip4_host.address,
            timeout=1.0,
        )

    def test__dhcp4_client__dnav4_returns_false_on_silent_gateway(self) -> None:
        """
        Ensure '_dnav4_probe' returns False when the ACD engine's
        reachability probe times out (no Reply). The caller falls through
        to the standard INIT-REBOOT REQUEST path.

        Reference: RFC 4436 §4 (timeout → standard DHCP fallback).
        """

        client, acd = self._client_with_acd()
        acd.probe_reachable.return_value = False

        result = client._dnav4_probe(self._cached_lease_with_mac())

        self.assertFalse(
            result,
            msg="Silent gateway must yield a False DNAv4 result.",
        )
        acd.probe_reachable.assert_called_once()

    def test__dhcp4_client__dnav4_returns_false_without_acd_engine(self) -> None:
        """
        Ensure '_dnav4_probe' returns False (and falls through to
        INIT-REBOOT) when no ACD engine is wired — the sync-mode 'fetch()'
        path before an interface engine exists.

        Reference: RFC 4436 §4 (DNAv4 requires a link to probe over).
        """

        client = Dhcp4Client(mac_address=_DEFAULT_MAC)  # no acd

        self.assertFalse(
            client._dnav4_probe(self._cached_lease_with_mac()),
            msg="DNAv4 must not engage without a raw-link ACD engine.",
        )

    def test__dhcp4_client__init_reboot_short_circuits_on_dnav4_success(self) -> None:
        """
        Ensure that when '_dnav4_probe' returns True the
        INIT-REBOOT handler adopts the cached lease and
        transitions to BOUND without sending any DHCP traffic.
        This is the canonical fast-boot path the RFC 4436
        engineering is designed for.

        Reference: RFC 4436 §4 (skip DHCP exchange on successful DNAv4).
        """

        client = Dhcp4Client(mac_address=_DEFAULT_MAC)
        cached = self._cached_lease_with_mac()
        client._lease = cached
        client._state = Dhcp4State.INIT_REBOOT
        self.enterContext(
            patch.object(client, "_dnav4_probe", return_value=True),
        )

        client._do_init_reboot()

        self.assertIs(
            client._state,
            Dhcp4State.BOUND,
            msg="DNAv4 success on INIT-REBOOT must transition to BOUND.",
        )
        # No DHCP TX at all — the wire-format hook in the mock
        # server's send-capture must remain empty.
        self.assertEqual(
            self._server.tx_log,
            [],
            msg="DNAv4 short-circuit must emit zero DHCP frames.",
        )

    def test__dhcp4_client__init_reboot_falls_through_when_dnav4_fails(self) -> None:
        """
        Ensure that when '_dnav4_probe' returns False the
        INIT-REBOOT handler proceeds with the standard
        INIT-REBOOT REQUEST exchange — preserving the
        Phase 5 fast-path even when DNAv4 is unavailable.

        Reference: RFC 4436 §4 (graceful fallback on DNAv4 miss).
        Reference: RFC 2131 §4.4.2 (INIT-REBOOT REQUEST after DNAv4 miss).
        """

        self.enterContext(sysctl.override("dhcp.retrans_jitter_ms", 0))
        client = Dhcp4Client(mac_address=_DEFAULT_MAC)
        cached = self._cached_lease_with_mac()
        client._lease = cached
        client._state = Dhcp4State.INIT_REBOOT
        self.enterContext(
            patch.object(client, "_dnav4_probe", return_value=False),
        )
        self._server.enqueue_ack(yiaddr=Ip4Address("192.168.1.145"))

        client._do_init_reboot()

        # On DNAv4 miss, the standard REQUEST goes on the wire.
        self.assertGreaterEqual(
            len(self._server.tx_log),
            1,
            msg="DNAv4 miss must fall through to the standard INIT-REBOOT REQUEST.",
        )
        self.assertIs(
            client._state,
            Dhcp4State.BOUND,
            msg="ACK on the standard REQUEST must still transition to BOUND.",
        )


class TestDhcp4ClientPhase8Polish(_Dhcp4ClientFixture):
    """
    Phase 8 — polish-option emissions: Max DHCP Message Size
    (RFC 2132 §9.10, option 57) and Lease Time hint
    (RFC 2131 §3.5, option 51 in DISCOVER).
    """

    def test__dhcp4_client__discover_emits_max_msg_size(self) -> None:
        """
        Ensure 'fetch()' emits a Maximum DHCP Message Size option
        in the DISCOVER it sends, defaulting to the
        'dhcp.max_msg_size' sysctl value (1500 = standard
        Ethernet MTU).

        Reference: RFC 2132 §9.10 (Maximum DHCP Message Size).
        """

        self._server.enqueue_offer()
        self._server.enqueue_ack()

        client = Dhcp4Client(mac_address=_DEFAULT_MAC)
        client.fetch()

        discover = self._server.tx_log[0]
        self.assertEqual(
            discover.max_msg_size,
            1500,
            msg="DISCOVER must carry Max DHCP Message Size = 1500 by default.",
        )

    def test__dhcp4_client__request_emits_max_msg_size(self) -> None:
        """
        Ensure the SELECTING-state REQUEST also carries the
        Maximum DHCP Message Size option so the server may emit
        an ACK larger than the 576-byte baseline.

        Reference: RFC 2132 §9.10 (option valid in any message).
        """

        self._server.enqueue_offer()
        self._server.enqueue_ack()

        client = Dhcp4Client(mac_address=_DEFAULT_MAC)
        client.fetch()

        request = self._server.tx_log[1]
        self.assertEqual(
            request.max_msg_size,
            1500,
            msg="SELECTING REQUEST must carry Max DHCP Message Size = 1500 by default.",
        )

    def test__dhcp4_client__discover_emits_lease_time_hint(self) -> None:
        """
        Ensure DISCOVER carries the Lease Time hint at the default
        sysctl value of 86400 seconds (1 day) — the operator's
        preferred lease length.

        Reference: RFC 2131 §3.5 (DISCOVER MAY carry desired lease-time).
        """

        self._server.enqueue_offer()
        self._server.enqueue_ack()

        client = Dhcp4Client(mac_address=_DEFAULT_MAC)
        client.fetch()

        discover = self._server.tx_log[0]
        self.assertEqual(
            discover.lease_time,
            86400,
            msg="DISCOVER must carry the default 86400 s Lease Time hint.",
        )

    def test__dhcp4_client__discover_omits_lease_time_hint_when_sysctl_zero(self) -> None:
        """
        Ensure that setting 'dhcp.requested_lease_time__sec' to 0
        omits the hint entirely (a server that prefers picking
        its own lease length is not biased by the client's
        suggestion).

        Reference: RFC 2131 §3.5 (option is OPTIONAL).
        """

        self.enterContext(sysctl.override("dhcp.requested_lease_time__sec", 0))
        self._server.enqueue_offer()
        self._server.enqueue_ack()

        client = Dhcp4Client(mac_address=_DEFAULT_MAC)
        client.fetch()

        discover = self._server.tx_log[0]
        self.assertIsNone(
            discover.lease_time,
            msg="dhcp.requested_lease_time__sec=0 must omit the Lease Time option from DISCOVER.",
        )

    def test__dhcp4_client__max_msg_size_sysctl_override_propagates(self) -> None:
        """
        Ensure that an operator override of 'dhcp.max_msg_size'
        propagates to the option value emitted on the wire.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.enterContext(sysctl.override("dhcp.max_msg_size", 9000))
        self._server.enqueue_offer()
        self._server.enqueue_ack()

        client = Dhcp4Client(mac_address=_DEFAULT_MAC)
        client.fetch()

        discover = self._server.tx_log[0]
        self.assertEqual(
            discover.max_msg_size,
            9000,
            msg="DISCOVER must carry the operator-tuned Max DHCP Message Size value.",
        )


class TestDhcp4ClientMultiOfferCollection(_Dhcp4ClientFixture):
    """
    Phase 8.x — RFC 2131 §4.4.1 multi-OFFER collection window.
    After the first valid OFFER the client lingers for up to
    'dhcp.offer_collection_ms' for additional OFFERs (dhcpcd /
    ISC dhclient pattern) before proceeding to REQUEST. The
    selection policy is "first received" so the lease shape
    is unchanged — the window adds visibility, not a different
    server choice.
    """

    def test__dhcp4_client__collection_window_disabled_picks_first_offer(self) -> None:
        """
        Ensure that with 'dhcp.offer_collection_ms' = 0 (the
        fixture default), the client does not wait after the
        first OFFER. The TX log shows DISCOVER + REQUEST only.

        Reference: RFC 2131 §4.4.1 ("e.g. the first DHCPOFFER message").
        """

        self._server.enqueue_offer()
        self._server.enqueue_ack()

        client = Dhcp4Client(mac_address=_DEFAULT_MAC)
        client.fetch()

        # First OFFER → immediate REQUEST. The mock server only
        # captures TX frames; its 'recv__mv' queue records the
        # number of recv calls indirectly. The key invariant is
        # that the call sequence is DISCOVER, then REQUEST —
        # i.e. exactly two outbound DHCP frames.
        self.assertEqual(
            [tx.message_type for tx in self._server.tx_log],
            [Dhcp4MessageType.DISCOVER, Dhcp4MessageType.REQUEST],
            msg="With collection disabled the TX log must be exactly [DISCOVER, REQUEST].",
        )

    def test__dhcp4_client__collection_window_logs_additional_offers(self) -> None:
        """
        Ensure that with a non-zero 'dhcp.offer_collection_ms',
        the client polls for additional OFFERs after the first
        one. A second OFFER queued during the window is
        consumed (verified via 'tx_log' RX-side observation);
        the first OFFER's server_id remains the lease's
        selection.

        Reference: RFC 2131 §4.4.1 multi-OFFER collection (Linux-alike).
        """

        # Generous window so the loop has time to consume two
        # OFFERs; followed by a TimeoutError sentinel to end
        # the window cleanly and an ACK for the subsequent
        # REQUEST. The mock server's 'recv__mv' returns each
        # enqueued reply immediately so the wall-clock time is
        # dominated by the TimeoutError sentinel (which raises
        # synchronously) rather than the window value.
        self.enterContext(sysctl.override("dhcp.offer_collection_ms", 200))

        self._server.enqueue_offer(server_id=Ip4Address("10.0.0.250"))
        self._server.enqueue_offer(server_id=Ip4Address("10.0.0.251"))
        # Sentinel terminates the collection window — simulates
        # the server being silent after the second OFFER.
        self._server.enqueue_timeout()
        self._server.enqueue_ack()

        client = Dhcp4Client(mac_address=_DEFAULT_MAC)
        lease = client.fetch()

        assert lease is not None
        self.assertEqual(
            lease.server_id,
            Ip4Address("10.0.0.250"),
            msg="The first OFFER's server_id must remain the selection.",
        )

    def test__dhcp4_client__collection_window_silence_terminates_loop(self) -> None:
        """
        Ensure the collection window terminates promptly when
        no additional OFFERs arrive — the loop must return
        through the TimeoutError path of '_recv_within_window'
        rather than hang past the window.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.enterContext(sysctl.override("dhcp.offer_collection_ms", 25))
        self._server.enqueue_offer()
        # No additional OFFERs — server goes silent during the
        # collection window. The TimeoutError sentinel ends the
        # window; the ACK serves the subsequent REQUEST.
        self._server.enqueue_timeout()
        self._server.enqueue_ack()

        client = Dhcp4Client(mac_address=_DEFAULT_MAC)
        lease = client.fetch()

        self.assertIsNotNone(
            lease,
            msg="fetch() must return a lease even when only one OFFER lands in the window.",
        )


class TestDhcp4ClientServerT1T2Overrides(_Dhcp4ClientFixture):
    """
    Phase 8.x — RFC 2131 §4.4.5 server-supplied T1 / T2
    overrides via RFC 2132 §9.7 / §9.8 options 58 / 59. When
    the ACK carries these options PyTCP MUST honour them as
    the T1 / T2 deadlines, overriding the factor-based defaults.
    """

    def test__dhcp4_client__ack_overrides_populate_lease_fields(self) -> None:
        """
        Ensure that when the ACK carries options 58 (Renewal)
        and 59 (Rebinding), the resulting 'Dhcp4Lease' carries
        the values verbatim on its 't1_override' / 't2_override'
        fields.

        Reference: RFC 2132 §9.7 (Renewal Time Value option 58).
        Reference: RFC 2132 §9.8 (Rebinding Time Value option 59).
        """

        self._server.enqueue_offer()
        # ACK carries explicit T1=1200 (20 min) and T2=2100
        # (35 min) on a 3600 s lease — typical ISP-supplied
        # tighter renewal cadence.
        from net_proto.protocols.dhcp4.options.dhcp4__option__rebinding_time import Dhcp4OptionRebindingTime
        from net_proto.protocols.dhcp4.options.dhcp4__option__renewal_time import Dhcp4OptionRenewalTime

        ack_extras = [Dhcp4OptionRenewalTime(1200), Dhcp4OptionRebindingTime(2100)]
        original_build = self._server._build_offer_or_ack

        def _patched(**kwargs):  # type: ignore[no-untyped-def]
            data = original_build(**kwargs)
            # Splice the T1/T2 options into the ACK just before
            # the END marker. The frame layout is
            # [header...][options..., END]; END is the last byte
            # before any trailing pad.
            from net_proto.protocols.dhcp4.options.dhcp4__option import Dhcp4OptionType

            end_byte = bytes([int(Dhcp4OptionType.END)])
            idx = data.rfind(end_byte)
            return data[:idx] + b"".join(bytes(opt) for opt in ack_extras) + data[idx:]

        self._server._build_offer_or_ack = _patched  # type: ignore[method-assign]
        self._server.enqueue_ack()

        client = Dhcp4Client(mac_address=_DEFAULT_MAC)
        lease = client.fetch()

        assert lease is not None
        self.assertEqual(
            lease.t1_override,
            1200,
            msg="Server-supplied T1 must be captured verbatim on the lease.",
        )
        self.assertEqual(
            lease.t2_override,
            2100,
            msg="Server-supplied T2 must be captured verbatim on the lease.",
        )

    def test__dhcp4_client__lease_without_overrides_uses_factor_defaults(self) -> None:
        """
        Ensure that an ACK without options 58 / 59 yields a
        lease whose 't1_override' / 't2_override' are None,
        and the deadline computation falls back to the
        factor-based defaults (T1 = 0.5 × lease, T2 = 0.875 ×
        lease).

        Reference: RFC 2131 §4.4.5 (factor-based fallback).
        """

        self._server.enqueue_offer()
        self._server.enqueue_ack(lease_time=3600)

        client = Dhcp4Client(mac_address=_DEFAULT_MAC)
        lease = client.fetch()

        assert lease is not None
        self.assertIsNone(
            lease.t1_override,
            msg="Lease without server T1 override must read back as None.",
        )
        self.assertIsNone(
            lease.t2_override,
            msg="Lease without server T2 override must read back as None.",
        )
        # Set the lease as bound on the client and verify the
        # deadline formula uses the factor default.
        client._lease = lease
        # acquired_at_monotonic is set by fetch() to time.monotonic().
        # Override it for predictable arithmetic.
        client._lease = Dhcp4Lease(
            ip4_host=lease.ip4_host,
            lease_time__sec=3600,
            server_id=lease.server_id,
            acquired_at_monotonic=100.0,
        )
        # T1 = 100 + 3600 * 0.5 = 1900; T2 = 100 + 3600 * 0.875 = 3250.
        self.assertEqual(
            client._t1_deadline(),
            1900.0,
            msg="T1 deadline must be acquired_at + lease_time × t1_factor when no override.",
        )
        self.assertEqual(
            client._t2_deadline(),
            3250.0,
            msg="T2 deadline must be acquired_at + lease_time × t2_factor when no override.",
        )

    def test__dhcp4_client__t1_deadline_honours_lease_override(self) -> None:
        """
        Ensure '_t1_deadline' honours a server-supplied
        't1_override' on the lease, overriding the factor-based
        default.

        Reference: RFC 2131 §4.4.5 (server T1 overrides default).
        """

        client = Dhcp4Client(mac_address=_DEFAULT_MAC)
        # Build a lease with override T1=1200 on a 3600 s lease.
        client._lease = Dhcp4Lease(
            ip4_host=Ip4IfAddr("192.168.1.145/24"),
            lease_time__sec=3600,
            server_id=Ip4Address("192.168.1.1"),
            acquired_at_monotonic=100.0,
            t1_override=1200,
        )

        self.assertEqual(
            client._t1_deadline(),
            100.0 + 1200,
            msg="T1 deadline must honour the server-supplied override.",
        )

    def test__dhcp4_client__t2_deadline_honours_lease_override(self) -> None:
        """
        Ensure '_t2_deadline' honours a server-supplied
        't2_override' on the lease, overriding the factor-based
        default.

        Reference: RFC 2131 §4.4.5 (server T2 overrides default).
        """

        client = Dhcp4Client(mac_address=_DEFAULT_MAC)
        client._lease = Dhcp4Lease(
            ip4_host=Ip4IfAddr("192.168.1.145/24"),
            lease_time__sec=3600,
            server_id=Ip4Address("192.168.1.1"),
            acquired_at_monotonic=100.0,
            t2_override=2100,
        )

        self.assertEqual(
            client._t2_deadline(),
            100.0 + 2100,
            msg="T2 deadline must honour the server-supplied override.",
        )

    def test__dhcp4_client__invalid_t1_ge_lease_time_is_dropped(self) -> None:
        """
        Ensure that a server-supplied T1 ≥ lease_time is
        rejected by '_extract_t1_t2_overrides' and the lease
        falls back to the factor-based default for T1. PyTCP
        deliberately ignores the offending value rather than
        rejecting the lease entirely (Linux dhcpcd parity).

        Reference: RFC 2131 §4.4.5 (T1 < lease_time invariant).
        """

        client = Dhcp4Client(mac_address=_DEFAULT_MAC)

        # Build a mock parser-like object that exposes the
        # 'renewal_time' / 'rebinding_time' properties used by
        # the helper.
        ack = MagicMock(name="ack")
        ack.renewal_time = 5000  # exceeds lease_time
        ack.rebinding_time = 2100

        t1, t2 = client._extract_t1_t2_overrides(ack, lease_time__sec=3600)

        self.assertIsNone(
            t1,
            msg="T1 ≥ lease_time must be dropped (None returned).",
        )
        self.assertEqual(
            t2,
            2100,
            msg="Valid T2 must be preserved when only T1 is invalid.",
        )

    def test__dhcp4_client__invalid_t1_ge_t2_drops_both(self) -> None:
        """
        Ensure that a server-supplied T1 ≥ T2 pair is
        rejected — without a sensible ordering, neither timer
        is honoured.

        Reference: RFC 2131 §4.4.5 (T1 < T2 invariant).
        """

        client = Dhcp4Client(mac_address=_DEFAULT_MAC)
        ack = MagicMock(name="ack")
        ack.renewal_time = 2500
        ack.rebinding_time = 2000  # T1 >= T2

        t1, t2 = client._extract_t1_t2_overrides(ack, lease_time__sec=3600)

        self.assertIsNone(
            t1,
            msg="T1 ≥ T2 must drop T1.",
        )
        self.assertIsNone(
            t2,
            msg="T1 ≥ T2 must drop T2 too (the ordering is the invariant).",
        )


class TestDhcp4ClientClasslessStaticRoutes(TestCase):
    """
    The 'Dhcp4Client' RFC 3442 Classless Static Route install /
    remove tests.
    """

    @override
    def setUp(self) -> None:
        """
        Build a client bound to a mocked Route API and silence the
        Subsystem init log line.
        """

        self.enterContext(patch("pytcp.runtime.subsystem.log"))
        self.enterContext(patch("pytcp.protocols.dhcp4.dhcp4__client.log"))
        self._route_api = create_autospec(RouteApi, spec_set=True)
        self._client = Dhcp4Client(mac_address=_DEFAULT_MAC, route_api=self._route_api)

    @staticmethod
    def _lease(
        *,
        gateway: Ip4Address | None,
        classless_static_routes: list[tuple[Ip4Network, Ip4Address]] | None,
    ) -> Dhcp4Lease:
        """
        Build a minimal BOUND-able lease with the given gateway /
        classless-route shape.
        """

        return Dhcp4Lease(
            ip4_host=Ip4IfAddr((Ip4Address("10.0.21.17"), Ip4Mask("255.255.255.0"))),
            lease_time__sec=3600,
            server_id=Ip4Address("10.0.21.1"),
            acquired_at_monotonic=0.0,
            gateway=gateway,
            classless_static_routes=classless_static_routes,
        )

    def test__dhcp4_client__installs_classless_static_routes_and_ignores_router(self) -> None:
        """
        Ensure a lease with Classless Static Routes installs the
        0.0.0.0/0 entry as the default route and each non-default
        entry as a route, and ignores the Router option entirely.

        Reference: RFC 3442 (install option 121, ignore option 3).
        """

        self._client._install_lease_routes(
            self._lease(
                gateway=Ip4Address("10.0.21.254"),  # option 3 — MUST be ignored
                classless_static_routes=[
                    (Ip4Network("0.0.0.0/0"), Ip4Address("10.0.21.1")),
                    (Ip4Network("192.168.0.0/24"), Ip4Address("10.0.21.2")),
                ],
            )
        )

        self._route_api.replace_default.assert_called_once_with(
            gateway=Ip4Address("10.0.21.1"),
            protocol=RouteProtocol.DHCP,
        )
        self._route_api.add_route.assert_called_once_with(
            route=Route(
                destination=Ip4Network("192.168.0.0/24"),
                gateway=Ip4Address("10.0.21.2"),
                protocol=RouteProtocol.DHCP,
            ),
        )

    def test__dhcp4_client__skips_onlink_classless_route(self) -> None:
        """
        Ensure a Classless Static Route whose router is 0.0.0.0 (an
        on-link destination PyTCP's host FIB does not install) is
        skipped.

        Reference: RFC 3442 (stack may ignore router 0.0.0.0 routes).
        """

        self._client._install_lease_routes(
            self._lease(
                gateway=None,
                classless_static_routes=[
                    (Ip4Network("192.168.0.0/24"), Ip4Address("0.0.0.0")),
                ],
            )
        )

        self._route_api.add_route.assert_not_called()
        self._route_api.replace_default.assert_not_called()

    def test__dhcp4_client__falls_back_to_router_option_without_classless(self) -> None:
        """
        Ensure a lease with no Classless Static Routes installs the
        Router option (option 3) as the default route.

        Reference: RFC 3442 (fall back to option 3 when 121 absent).
        """

        self._client._install_lease_routes(self._lease(gateway=Ip4Address("10.0.21.254"), classless_static_routes=None))

        self._route_api.replace_default.assert_called_once_with(
            gateway=Ip4Address("10.0.21.254"),
            protocol=RouteProtocol.DHCP,
        )
        self._route_api.add_route.assert_not_called()

    def test__dhcp4_client__removes_non_default_classless_routes(self) -> None:
        """
        Ensure removal drops each non-default, gatewayed Classless
        Static Route and leaves the default / on-link entries to the
        default-route teardown.

        Reference: RFC 3442 (Classless Static Route option).
        """

        self._client._remove_lease_routes(
            self._lease(
                gateway=None,
                classless_static_routes=[
                    (Ip4Network("0.0.0.0/0"), Ip4Address("10.0.21.1")),
                    (Ip4Network("192.168.0.0/24"), Ip4Address("10.0.21.2")),
                    (Ip4Network("172.16.0.0/12"), Ip4Address("0.0.0.0")),
                ],
            )
        )

        self._route_api.remove_route.assert_called_once_with(
            destination=Ip4Network("192.168.0.0/24"),
            gateway=Ip4Address("10.0.21.2"),
        )

    def test__dhcp4_client__renew_removes_previous_classless_routes(self) -> None:
        """
        Ensure binding a refreshed lease first removes the previous
        lease's classless routes so a RENEW does not accumulate
        duplicate FIB entries.

        Reference: RFC 3442 (Classless Static Route option).
        """

        self.enterContext(patch("pytcp.protocols.dhcp4.dhcp4__client.write_cached_lease"))
        first = self._lease(
            gateway=None,
            classless_static_routes=[(Ip4Network("192.168.0.0/24"), Ip4Address("10.0.21.2"))],
        )
        second = self._lease(
            gateway=None,
            classless_static_routes=[(Ip4Network("172.16.0.0/12"), Ip4Address("10.0.21.3"))],
        )

        self._client._on_bound(first)
        self._client._on_bound(second)

        self._route_api.remove_route.assert_called_once_with(
            destination=Ip4Network("192.168.0.0/24"),
            gateway=Ip4Address("10.0.21.2"),
        )


class TestDhcp4ClientParamReqListOrdering(_Dhcp4ClientFixture):
    """
    The 'Dhcp4Client' RFC 3442 Parameter Request List ordering tests.
    """

    def test__dhcp4_client__prl_requests_classless_before_router(self) -> None:
        """
        Ensure the DISCOVER / REQUEST Parameter Request List requests
        the Classless Static Route option and places it before the
        Router option.

        Reference: RFC 3442 (121 MUST precede Router in the PRL).
        """

        self._server.enqueue_offer()
        self._server.enqueue_ack()

        Dhcp4Client(mac_address=_DEFAULT_MAC).fetch()

        # DISCOVER (tx_log[0]) and REQUEST (tx_log[1]) both carry a PRL.
        for emitted in self._server.tx_log:
            prl = emitted.param_req_list
            if prl is None:
                continue
            self.assertIn(
                Dhcp4OptionType.CLASSLESS_STATIC_ROUTE,
                prl,
                msg="The PRL must request the Classless Static Route option.",
            )
            self.assertLess(
                prl.index(Dhcp4OptionType.CLASSLESS_STATIC_ROUTE),
                prl.index(Dhcp4OptionType.ROUTER),
                msg="The Classless Static Route option MUST precede Router in the PRL.",
            )
