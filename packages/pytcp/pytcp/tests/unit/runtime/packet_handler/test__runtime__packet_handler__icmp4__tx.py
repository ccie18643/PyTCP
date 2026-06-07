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
This module contains unit tests for the 'PacketHandlerIcmp4Tx' mixin.

pytcp/tests/unit/runtime/packet_handler/test__runtime__packet_handler__icmp4__tx.py

ver 3.0.8
"""

from collections.abc import Callable
from typing import TYPE_CHECKING, cast, override
from unittest import TestCase

from net_addr import Ip4Address
from net_proto import (
    Icmp4Assembler,
    Icmp4MessageDestinationUnreachable,
    Icmp4MessageEchoReply,
    Icmp4MessageEchoRequest,
)
from net_proto.protocols.icmp4.message.icmp4__message__destination_unreachable import (
    Icmp4DestinationUnreachableCode,
)
from pytcp import stack
from pytcp.lib.packet_stats import PacketStatsTx
from pytcp.lib.tx_status import TxStatus
from pytcp.runtime.packet_handler.packet_handler__icmp4__tx import Icmp4TxHandler

if TYPE_CHECKING:
    from pytcp.runtime.packet_handler import PacketHandlerL2, PacketHandlerL3

# Snapshot log channels so 'setUpModule' can silence output during this
# module's tests and 'tearDownModule' can restore the global state.
_ORIGINAL_LOG_CHANNEL: set[str] = stack.LOG__CHANNEL


def setUpModule() -> None:
    """
    Silence log output for the duration of this module's tests.
    """

    stack.LOG__CHANNEL = set()


def tearDownModule() -> None:
    """
    Restore the snapshot of log channels after this module's tests finish.
    """

    stack.LOG__CHANNEL = _ORIGINAL_LOG_CHANNEL


STACK__IP4_ADDRESS = Ip4Address("10.0.1.7")
HOST_A__IP4 = Ip4Address("10.0.1.91")


class _StubInterface:
    """
    Minimal stand-in for the owning 'PacketHandlerL2' / 'PacketHandlerL3'
    interface.

    Carries the TX-stat counters, the TX marshal seam, and the
    '_phtx_ip4' entry the ICMPv4 TX sub-handler reaches through
    'self._if', recording each call for assertions. A purpose-built
    double is used rather than 'create_autospec(PacketHandlerL2)' —
    the god-class still carries 'TYPE_CHECKING'-only annotations
    'inspect.signature' (which autospec walks) cannot evaluate at
    runtime.
    """

    def _marshal_tx(self, run: Callable[[], TxStatus], /) -> TxStatus:
        # Marshaled TX entry points route '_phtx_*' through '_marshal_tx';
        # with no TX worker under test, run the callable inline.
        return run()

    def __init__(self) -> None:
        self._packet_stats_tx = PacketStatsTx()
        self.ip4_tx_calls: list[dict[str, object]] = []

    def _phtx_ip4(self, **kwargs: object) -> TxStatus:
        self.ip4_tx_calls.append(kwargs)
        return TxStatus.PASSED__ETHERNET__TO_TX_RING


class TestPacketHandlerIcmp4Tx(TestCase):
    """
    The 'Icmp4TxHandler._phtx_icmp4' behaviour tests.
    """

    @override
    def setUp(self) -> None:
        self._if = _StubInterface()
        self._icmp4_tx = Icmp4TxHandler(interface=cast("PacketHandlerL2 | PacketHandlerL3", self._if))

    def test__stack__packet_handler__icmp4__tx__echo_reply_counted_and_forwarded(self) -> None:
        """
        Ensure an Echo Reply is counted in 'icmp4__echo_reply__send'
        and forwarded to '_phtx_ip4' with the assembled ICMPv4 payload.

        Reference: RFC 792 (Echo Reply).
        """

        status = self._icmp4_tx._phtx_icmp4(
            ip4__src=STACK__IP4_ADDRESS,
            ip4__dst=HOST_A__IP4,
            icmp4__message=Icmp4MessageEchoReply(id=1, seq=1, data=b"hello"),
        )

        self.assertEqual(status, TxStatus.PASSED__ETHERNET__TO_TX_RING)
        self.assertEqual(self._if._packet_stats_tx.icmp4__pre_assemble, 1)
        self.assertEqual(self._if._packet_stats_tx.icmp4__echo_reply__send, 1)
        self.assertEqual(len(self._if.ip4_tx_calls), 1)
        call = self._if.ip4_tx_calls[0]
        self.assertEqual(call["ip4__src"], STACK__IP4_ADDRESS)
        self.assertEqual(call["ip4__dst"], HOST_A__IP4)
        self.assertIsInstance(call["ip4__payload"], Icmp4Assembler)

    def test__stack__packet_handler__icmp4__tx__echo_request_counted(self) -> None:
        """
        Ensure an Echo Request is counted in 'icmp4__echo_request__send'.

        Reference: RFC 792 (Echo).
        """

        self._icmp4_tx._phtx_icmp4(
            ip4__src=STACK__IP4_ADDRESS,
            ip4__dst=HOST_A__IP4,
            icmp4__message=Icmp4MessageEchoRequest(id=1, seq=1, data=b"hello"),
        )

        self.assertEqual(self._if._packet_stats_tx.icmp4__echo_request__send, 1)

    def test__stack__packet_handler__icmp4__tx__port_unreachable_counted(self) -> None:
        """
        Ensure a Destination Unreachable (code=PORT) is counted in
        'icmp4__destination_unreachable__port__send'.

        Reference: RFC 792 (Destination Unreachable Code 3).
        """

        self._icmp4_tx._phtx_icmp4(
            ip4__src=STACK__IP4_ADDRESS,
            ip4__dst=HOST_A__IP4,
            icmp4__message=Icmp4MessageDestinationUnreachable(
                code=Icmp4DestinationUnreachableCode.PORT,
                data=b"\x00" * 20,
            ),
        )

        self.assertEqual(self._if._packet_stats_tx.icmp4__destination_unreachable__port__send, 1)

    def test__stack__packet_handler__icmp4__tx__unsupported_type_drops(self) -> None:
        """
        Ensure an unsupported ICMPv4 message type / code combination
        is dropped with 'TxStatus.DROPPED__ICMP4__UNKNOWN' and bumps
        the 'icmp4__unknown__drop' counter — defensive over the old
        'raise ValueError' behaviour. Destination Unreachable with
        code=NETWORK is not in the supported match arms.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        status = self._icmp4_tx._phtx_icmp4(
            ip4__src=STACK__IP4_ADDRESS,
            ip4__dst=HOST_A__IP4,
            icmp4__message=Icmp4MessageDestinationUnreachable(
                code=Icmp4DestinationUnreachableCode.NETWORK,
                data=b"\x00" * 20,
            ),
        )

        self.assertIs(
            status,
            TxStatus.DROPPED__ICMP4__UNKNOWN,
            msg="Unsupported ICMPv4 type must return DROPPED__ICMP4__UNKNOWN.",
        )
        self.assertEqual(
            self._if._packet_stats_tx.icmp4__unknown__drop,
            1,
            msg="Unsupported ICMPv4 type must bump 'icmp4__unknown__drop'.",
        )
        self.assertEqual(
            len(self._if.ip4_tx_calls),
            0,
            msg="Unsupported ICMPv4 type must NOT forward to '_phtx_ip4'.",
        )

    def test__stack__packet_handler__icmp4__tx__send_icmp4_packet_forwards(self) -> None:
        """
        Ensure the public 'send_icmp4_packet' helper forwards its
        arguments verbatim to '_phtx_icmp4'.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        status = self._icmp4_tx.send_icmp4_packet(
            ip4__local_address=STACK__IP4_ADDRESS,
            ip4__remote_address=HOST_A__IP4,
            icmp4__message=Icmp4MessageEchoRequest(id=1, seq=1, data=b"hello"),
        )

        self.assertEqual(status, TxStatus.PASSED__ETHERNET__TO_TX_RING)
        self.assertEqual(self._if._packet_stats_tx.icmp4__echo_request__send, 1)
