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
This module contains the 'Dhcp4MockServer' test helper — a stub
DHCPv4 server that captures outbound client frames via real
'Dhcp4Parser' and serves canned replies built via real
'Dhcp4Assembler', so unit tests exercise the actual wire-format
path rather than 'SimpleNamespace' stand-ins.

pytcp/tests/lib/dhcp4_mock_server.py

ver 3.0.8
"""

from collections import deque
from typing import Callable
from unittest.mock import MagicMock

from net_addr import Ip4Address, Ip4Mask, MacAddress
from net_proto.protocols.dhcp4.dhcp4__assembler import Dhcp4Assembler
from net_proto.protocols.dhcp4.dhcp4__enums import (
    Dhcp4MessageType,
    Dhcp4Operation,
)
from net_proto.protocols.dhcp4.dhcp4__parser import Dhcp4Parser
from net_proto.protocols.dhcp4.options.dhcp4__option import Dhcp4Option
from net_proto.protocols.dhcp4.options.dhcp4__option__client_id import (
    Dhcp4OptionClientId,
)
from net_proto.protocols.dhcp4.options.dhcp4__option__end import (
    Dhcp4OptionEnd,
)
from net_proto.protocols.dhcp4.options.dhcp4__option__lease_time import (
    Dhcp4OptionLeaseTime,
)
from net_proto.protocols.dhcp4.options.dhcp4__option__message_type import (
    Dhcp4OptionMessageType,
)
from net_proto.protocols.dhcp4.options.dhcp4__option__router import (
    Dhcp4OptionRouter,
)
from net_proto.protocols.dhcp4.options.dhcp4__option__server_id import (
    Dhcp4OptionServerId,
)
from net_proto.protocols.dhcp4.options.dhcp4__option__subnet_mask import (
    Dhcp4OptionSubnetMask,
)
from net_proto.protocols.dhcp4.options.dhcp4__options import Dhcp4Options

_UNSET: object = object()

# Sentinel: "derive this field from the last captured client TX
# (xid echo, chaddr echo, client_id echo)". Distinct from None,
# which means "deliberately omit this option from the reply".


class Dhcp4MockServer:
    """
    Stub DHCPv4 server for unit and integration tests.

    Wire the server into a 'create_autospec'-d socket via 'wire()':
    'sock.send(...)' calls flow through 'Dhcp4Parser' into 'tx_log',
    and 'sock.recv__mv(...)' calls dequeue canned replies built via
    'Dhcp4Assembler' at recv time so 'xid' / 'chaddr' / 'client_id'
    echo derive from the most recently captured client TX.
    """

    def __init__(
        self,
        *,
        server_id: Ip4Address = Ip4Address("10.0.0.254"),
        server_mac: MacAddress | None = None,
    ) -> None:
        """
        Build an empty mock server. Use 'enqueue_offer' / 'enqueue_ack'
        / 'enqueue_nak' / 'enqueue_timeout' / 'enqueue_raw' to plan the
        responses before the test calls 'Dhcp4Client.fetch()'.
        """

        self._server_id = server_id
        self._server_mac = server_mac or MacAddress("02:00:00:00:00:fe")
        self._tx_log: list[Dhcp4Parser] = []
        self._reply_queue: deque[Callable[[], bytes] | BaseException] = deque()

    @property
    def tx_log(self) -> list[Dhcp4Parser]:
        """
        Return a snapshot of every client TX captured so far, parsed
        back through the real 'Dhcp4Parser' so callers can assert on
        any field or option.
        """

        return list(self._tx_log)

    def enqueue_offer(
        self,
        *,
        xid: int | object = _UNSET,
        yiaddr: Ip4Address = Ip4Address("10.0.0.100"),
        subnet_mask: Ip4Mask | None = Ip4Mask("255.255.255.0"),
        router: list[Ip4Address] | None = None,
        lease_time: int | None = 3600,
        server_id: Ip4Address | None | object = _UNSET,
        chaddr: MacAddress | object = _UNSET,
        client_id_echo: bytes | None | object = _UNSET,
        message_type: Dhcp4MessageType = Dhcp4MessageType.OFFER,
    ) -> None:
        """
        Plan a DHCPOFFER reply built lazily from the next client TX —
        unspecified fields ('xid', 'chaddr', 'client_id_echo') are
        copied from the last captured TX at recv time. Pass an
        explicit value (including None) to override an echo or to
        deliberately omit an option from the reply.
        """

        self._reply_queue.append(
            lambda: self._build_offer_or_ack(
                xid=xid,
                yiaddr=yiaddr,
                subnet_mask=subnet_mask,
                router=router,
                lease_time=lease_time,
                server_id=server_id,
                chaddr=chaddr,
                client_id_echo=client_id_echo,
                message_type=message_type,
            )
        )

    def enqueue_ack(
        self,
        *,
        xid: int | object = _UNSET,
        yiaddr: Ip4Address = Ip4Address("10.0.0.100"),
        subnet_mask: Ip4Mask | None = Ip4Mask("255.255.255.0"),
        router: list[Ip4Address] | None = None,
        lease_time: int | None = 3600,
        server_id: Ip4Address | None | object = _UNSET,
        chaddr: MacAddress | object = _UNSET,
        client_id_echo: bytes | None | object = _UNSET,
        message_type: Dhcp4MessageType = Dhcp4MessageType.ACK,
    ) -> None:
        """
        Plan a DHCPACK reply built lazily from the next client TX —
        same echo rules as 'enqueue_offer'.
        """

        self._reply_queue.append(
            lambda: self._build_offer_or_ack(
                xid=xid,
                yiaddr=yiaddr,
                subnet_mask=subnet_mask,
                router=router,
                lease_time=lease_time,
                server_id=server_id,
                chaddr=chaddr,
                client_id_echo=client_id_echo,
                message_type=message_type,
            )
        )

    def enqueue_nak(
        self,
        *,
        xid: int | object = _UNSET,
        chaddr: MacAddress | object = _UNSET,
        client_id_echo: bytes | None | object = _UNSET,
        server_id: Ip4Address | None | object = _UNSET,
    ) -> None:
        """
        Plan a DHCPNAK reply. A NAK carries no 'yiaddr' / Subnet Mask
        / Router / Lease Time; only Message Type, Server Identifier,
        and the echoed Client Identifier.
        """

        self._reply_queue.append(
            lambda: self._build_nak(
                xid=xid,
                chaddr=chaddr,
                client_id_echo=client_id_echo,
                server_id=server_id,
            )
        )

    def enqueue_timeout(self) -> None:
        """
        Plan a 'recv__mv' that raises 'TimeoutError' — the canonical
        signal that the test wants the client to observe a silent
        server.
        """

        self._reply_queue.append(TimeoutError())

    def enqueue_raw(self, frame: bytes, /) -> None:
        """
        Plan a raw byte frame returned verbatim from 'recv__mv' —
        for tests that need to inject malformed or otherwise hand-
        rolled replies (corrupted magic cookie, truncated options,
        etc.).
        """

        self._reply_queue.append(lambda: frame)

    def wire(self, mock_socket: MagicMock, /) -> None:
        """
        Plug the mock server into a 'create_autospec'-d socket. The
        socket's 'send' captures the outbound frame into 'tx_log';
        'recv__mv' dequeues the next planned reply (raising
        'TimeoutError' if the queue is empty).
        """

        def on_send(data: bytes) -> int:
            self._tx_log.append(Dhcp4Parser(memoryview(bytes(data))))
            return len(data)

        def on_recv(
            bufsize: int | None = None,
            timeout: float | None = None,
        ) -> memoryview:
            del bufsize, timeout
            if not self._reply_queue:
                raise TimeoutError
            item = self._reply_queue.popleft()
            if isinstance(item, BaseException):
                raise item
            return memoryview(item())

        mock_socket.send.side_effect = on_send
        mock_socket.recv__mv.side_effect = on_recv

    def _resolved_echo(
        self,
        *,
        explicit: object,
        default_extractor: Callable[[Dhcp4Parser], object],
    ) -> object:
        """
        Resolve a maybe-explicit field — if 'explicit' is the
        '_UNSET' sentinel, derive from the most recent client TX via
        the supplied extractor; otherwise return 'explicit' verbatim
        (including 'None' to mean "omit").
        """

        if explicit is not _UNSET:
            return explicit
        if not self._tx_log:
            raise RuntimeError(
                "Dhcp4MockServer cannot derive an echo field without a "
                "prior client TX in tx_log; pass the field explicitly "
                "or send a frame first.",
            )
        return default_extractor(self._tx_log[-1])

    def _build_offer_or_ack(
        self,
        *,
        xid: int | object,
        yiaddr: Ip4Address,
        subnet_mask: Ip4Mask | None,
        router: list[Ip4Address] | None,
        lease_time: int | None,
        server_id: Ip4Address | None | object,
        chaddr: MacAddress | object,
        client_id_echo: bytes | None | object,
        message_type: Dhcp4MessageType,
    ) -> bytes:
        """
        Build the canned OFFER / ACK frame bytes. Options included
        only when the corresponding kwarg is not None; this lets a
        single test deliberately omit Subnet Mask, Lease Time, etc.
        to exercise the client's missing-mandatory-option rejection.
        """

        resolved_xid = self._resolved_echo(
            explicit=xid,
            default_extractor=lambda tx: tx.xid,
        )
        resolved_chaddr = self._resolved_echo(
            explicit=chaddr,
            default_extractor=lambda tx: tx.chaddr,
        )
        resolved_cid = self._resolved_echo(
            explicit=client_id_echo,
            default_extractor=lambda tx: tx.client_id,
        )
        resolved_srv_id = self._server_id if server_id is _UNSET else server_id

        assert isinstance(resolved_xid, int)
        assert isinstance(resolved_chaddr, MacAddress)

        options: list[Dhcp4Option] = [Dhcp4OptionMessageType(message_type=message_type)]
        if subnet_mask is not None:
            options.append(Dhcp4OptionSubnetMask(subnet_mask=subnet_mask))
        if router:
            options.append(Dhcp4OptionRouter(routers=router))
        if lease_time is not None:
            options.append(Dhcp4OptionLeaseTime(lease_time=lease_time))
        if resolved_srv_id is not None:
            assert isinstance(resolved_srv_id, Ip4Address)
            options.append(Dhcp4OptionServerId(server_id=resolved_srv_id))
        if resolved_cid is not None:
            assert isinstance(resolved_cid, (bytes, bytearray))
            options.append(Dhcp4OptionClientId(bytes(resolved_cid)))
        options.append(Dhcp4OptionEnd())

        siaddr = resolved_srv_id if isinstance(resolved_srv_id, Ip4Address) else Ip4Address()
        reply = Dhcp4Assembler(
            dhcp4__operation=Dhcp4Operation.REPLY,
            dhcp4__xid=resolved_xid,
            dhcp4__yiaddr=yiaddr,
            dhcp4__siaddr=siaddr,
            dhcp4__chaddr=resolved_chaddr,
            dhcp4__options=Dhcp4Options(*options),
        )
        return bytes(reply)

    def _build_nak(
        self,
        *,
        xid: int | object,
        chaddr: MacAddress | object,
        client_id_echo: bytes | None | object,
        server_id: Ip4Address | None | object,
    ) -> bytes:
        """
        Build the canned NAK frame bytes. NAK carries the minimum
        option set: Message Type, Server Identifier, and the echoed
        Client Identifier.
        """

        resolved_xid = self._resolved_echo(
            explicit=xid,
            default_extractor=lambda tx: tx.xid,
        )
        resolved_chaddr = self._resolved_echo(
            explicit=chaddr,
            default_extractor=lambda tx: tx.chaddr,
        )
        resolved_cid = self._resolved_echo(
            explicit=client_id_echo,
            default_extractor=lambda tx: tx.client_id,
        )
        resolved_srv_id = self._server_id if server_id is _UNSET else server_id

        assert isinstance(resolved_xid, int)
        assert isinstance(resolved_chaddr, MacAddress)

        options: list[Dhcp4Option] = [Dhcp4OptionMessageType(message_type=Dhcp4MessageType.NAK)]
        if resolved_srv_id is not None:
            assert isinstance(resolved_srv_id, Ip4Address)
            options.append(Dhcp4OptionServerId(server_id=resolved_srv_id))
        if resolved_cid is not None:
            assert isinstance(resolved_cid, (bytes, bytearray))
            options.append(Dhcp4OptionClientId(bytes(resolved_cid)))
        options.append(Dhcp4OptionEnd())

        reply = Dhcp4Assembler(
            dhcp4__operation=Dhcp4Operation.REPLY,
            dhcp4__xid=resolved_xid,
            dhcp4__chaddr=resolved_chaddr,
            dhcp4__options=Dhcp4Options(*options),
        )
        return bytes(reply)


def autospec_dhcp4_socket() -> MagicMock:
    """
    Build a 'create_autospec'-d, 'spec_set'-locked stand-in for
    'pytcp.socket.socket'. Returned mock is callable (mirroring the
    socket factory) and yields an instance-shape autospec on each
    call. Wire 'Dhcp4MockServer.wire(mock_socket)' into the
    returned-value instance.

    Defined here rather than inline in test modules so every
    DHCP4-client test uses the same locked-down mock surface.
    """

    from typing import cast
    from unittest.mock import create_autospec

    from pytcp.socket import socket as _pytcp_socket

    factory: MagicMock = cast(MagicMock, create_autospec(_pytcp_socket, spec_set=True))
    instance: MagicMock = cast(MagicMock, create_autospec(_pytcp_socket, spec_set=True, instance=True))
    factory.return_value = instance
    return factory
