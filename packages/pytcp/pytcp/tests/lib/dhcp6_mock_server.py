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
This module contains the 'Dhcp6MockServer' test helper — a stub
DHCPv6 server that captures outbound client frames via real
'Dhcp6Parser' and serves canned REPLY frames built via real
'Dhcp6Assembler', so unit tests exercise the actual wire-format
path rather than 'SimpleNamespace' stand-ins.

pytcp/tests/lib/dhcp6_mock_server.py

ver 3.0.9
"""

from collections import deque
from typing import Callable, cast
from unittest.mock import MagicMock, create_autospec

from net_addr import Ip6Address
from net_proto import (
    Dhcp6Assembler,
    Dhcp6MessageType,
    Dhcp6OptionClientId,
    Dhcp6OptionDnsServers,
    Dhcp6OptionIaAddr,
    Dhcp6OptionIaNa,
    Dhcp6OptionPreference,
    Dhcp6OptionRapidCommit,
    Dhcp6Options,
    Dhcp6OptionServerId,
    Dhcp6OptionStatusCode,
    Dhcp6Parser,
    Dhcp6StatusCode,
)
from net_proto.protocols.dhcp6.options.dhcp6__option import Dhcp6Option

_UNSET: object = object()


class _GatedLeaseReply:
    """
    A lease-granting REPLY that the server only dispenses once the
    client has left the SOLICIT phase (its most recent transmission is
    not a SOLICIT) — modelling that a server sends the address-granting
    REPLY in response to a REQUEST / RENEW / REBIND, never during the
    client's first-RT ADVERTISE-collection window (RFC 8415 §18.2.1).

    When 'for_server' is set, the REPLY is additionally withheld until the
    client's most recent transmission carries that Server Identifier — so
    a REPLY meant for one server is not handed to another server's
    REQUEST (used to exercise the §18.2.9 alternate-server fallback).
    """

    def __init__(self, builder: Callable[[], bytes], /, *, for_server: bytes | None = None) -> None:
        self.builder = builder
        self.for_server = for_server


# Sentinel: "derive this field from the last captured client TX
# (xid echo, client_id echo)". Distinct from None, which means
# "deliberately omit this option from the reply".

_DEFAULT_SERVER_DUID = b"\x00\x03\x00\x01\x02\x00\x00\x00\x00\xfe"


class Dhcp6MockServer:
    """
    Stub DHCPv6 server for unit tests.

    Wire the server into a 'create_autospec'-d socket via 'wire()':
    'sock.sendto(...)' calls flow through 'Dhcp6Parser' into 'tx_log',
    and 'sock.recv__mv(...)' calls dequeue canned REPLY frames built
    via 'Dhcp6Assembler' at recv time so 'xid' / Client Identifier
    echo derive from the most recently captured client TX.
    """

    def __init__(self, *, server_duid: bytes = _DEFAULT_SERVER_DUID) -> None:
        """
        Build an empty mock server. Use 'enqueue_reply' /
        'enqueue_timeout' / 'enqueue_raw' to plan the responses before
        the test calls 'Dhcp6Client.fetch_other_config()'.
        """

        self._server_duid = server_duid
        self._tx_log: list[Dhcp6Parser] = []
        self._reply_queue: deque[Callable[[], bytes] | _GatedLeaseReply | BaseException] = deque()

    @property
    def tx_log(self) -> list[Dhcp6Parser]:
        """
        Return a snapshot of every client TX captured so far, parsed
        back through the real 'Dhcp6Parser' so callers can assert on
        any field or option.
        """

        return list(self._tx_log)

    def enqueue_reply(
        self,
        *,
        xid: int | object = _UNSET,
        dns_servers: list[Ip6Address] | None = None,
        client_id_echo: bytes | None | object = _UNSET,
        server_id: bytes | None | object = _UNSET,
    ) -> None:
        """
        Plan a DHCPv6 REPLY built lazily from the next client TX —
        unspecified fields ('xid', 'client_id_echo') are copied from
        the last captured TX at recv time. Pass an explicit value
        (including None) to override an echo or to deliberately omit
        an option from the reply.
        """

        self._reply_queue.append(
            lambda: self._build_reply(
                xid=xid,
                dns_servers=dns_servers,
                client_id_echo=client_id_echo,
                server_id=server_id,
            )
        )

    def enqueue_advertise(
        self,
        *,
        preference: int | None = None,
        xid: int | object = _UNSET,
        client_id_echo: bytes | None | object = _UNSET,
        server_id: bytes | None | object = _UNSET,
    ) -> None:
        """
        Plan a DHCPv6 ADVERTISE built lazily from the next client TX —
        carries the Server Identifier and the echoed Client Identifier
        so the client can select this server and address its REQUEST.
        Pass 'preference' to include a Preference option (RFC 8415
        §21.8); omit it (None) for an ADVERTISE with no Preference
        option (treated as preference 0 by the client).
        """

        self._reply_queue.append(
            lambda: self._build_advertise(
                preference=preference, xid=xid, client_id_echo=client_id_echo, server_id=server_id
            )
        )

    def enqueue_lease_reply(
        self,
        *,
        address: Ip6Address,
        preferred_lifetime: int = 3600,
        valid_lifetime: int = 7200,
        t1: int = 1800,
        t2: int = 2880,
        iaid: int = 0,
        ia_status: Dhcp6StatusCode | None = None,
        top_status: Dhcp6StatusCode | None = None,
        omit_ia_address: bool = False,
        ia_na_options_override: bytes | None = None,
        for_server: bytes | None = None,
        xid: int | object = _UNSET,
        client_id_echo: bytes | None | object = _UNSET,
        server_id: bytes | None | object = _UNSET,
    ) -> None:
        """
        Plan a DHCPv6 REPLY granting an IA_NA lease — carries the
        Server Identifier, the echoed Client Identifier, and an IA_NA
        whose sub-option block holds the IA Address (and, when
        'ia_status' is set, a nested Status Code). Set 'top_status' to add
        a top-level (message-level) Status Code (e.g. NotOnLink /
        UseMulticast / UnspecFail). Set 'omit_ia_address' to emit an IA_NA
        with no address (e.g. a NoAddrsAvail reply), or
        'ia_na_options_override' to stuff the IA_NA with raw (possibly
        malformed) sub-option bytes. Set 'for_server' to withhold the
        REPLY until the client's REQUEST targets that Server Identifier
        (exercises the alternate-server fallback).
        """

        self._reply_queue.append(
            _GatedLeaseReply(
                lambda: self._build_lease_reply(
                    address=address,
                    preferred_lifetime=preferred_lifetime,
                    valid_lifetime=valid_lifetime,
                    t1=t1,
                    t2=t2,
                    iaid=iaid,
                    ia_status=ia_status,
                    top_status=top_status,
                    omit_ia_address=omit_ia_address,
                    ia_na_options_override=ia_na_options_override,
                    rapid_commit=False,
                    xid=xid,
                    client_id_echo=client_id_echo,
                    server_id=server_id,
                ),
                for_server=for_server,
            )
        )

    def enqueue_rapid_reply(
        self,
        *,
        address: Ip6Address,
        with_rapid_commit: bool = True,
        preferred_lifetime: int = 3600,
        valid_lifetime: int = 7200,
        t1: int = 1800,
        t2: int = 2880,
        iaid: int = 0,
        xid: int | object = _UNSET,
        client_id_echo: bytes | None | object = _UNSET,
        server_id: bytes | None | object = _UNSET,
    ) -> None:
        """
        Plan a DHCPv6 REPLY answering a SOLICIT directly (RFC 8415 §18.2.1
        Rapid Commit two-message exchange). Unlike 'enqueue_lease_reply'
        this is NOT gated — it is dispensed during the client's SOLICIT
        collection window, mirroring a server that committed the lease on
        the SOLICIT. Set 'with_rapid_commit=False' to emit a REPLY that
        omits the Rapid Commit option (which a client must discard).
        """

        self._reply_queue.append(
            lambda: self._build_lease_reply(
                address=address,
                preferred_lifetime=preferred_lifetime,
                valid_lifetime=valid_lifetime,
                t1=t1,
                t2=t2,
                iaid=iaid,
                ia_status=None,
                top_status=None,
                omit_ia_address=False,
                ia_na_options_override=None,
                rapid_commit=with_rapid_commit,
                xid=xid,
                client_id_echo=client_id_echo,
                server_id=server_id,
            )
        )

    def enqueue_timeout(self) -> None:
        """
        Plan a 'recv__mv' that raises 'TimeoutError' — the canonical
        signal that the test wants the client to observe a silent
        server for one recv window.
        """

        self._reply_queue.append(TimeoutError())

    def enqueue_raw(self, frame: bytes, /) -> None:
        """
        Plan a raw byte frame returned verbatim from 'recv__mv' — for
        tests that need to inject malformed or otherwise hand-rolled
        replies.
        """

        self._reply_queue.append(lambda: frame)

    def wire(self, mock_socket: MagicMock, /) -> None:
        """
        Plug the mock server into a 'create_autospec'-d socket. The
        socket's 'sendto' captures the outbound frame into 'tx_log';
        'recv__mv' dequeues the next planned reply (raising
        'TimeoutError' if the queue is empty).
        """

        def on_sendto(data: bytes, address: tuple[str, int]) -> int:
            del address
            self._tx_log.append(Dhcp6Parser(memoryview(bytes(data))))
            return len(data)

        def on_recv(bufsize: int | None = None, timeout: float | None = None) -> memoryview:
            del bufsize, timeout
            if not self._reply_queue:
                raise TimeoutError
            front = self._reply_queue[0]
            if isinstance(front, _GatedLeaseReply):
                # Defer a lease-granting REPLY while the client is still
                # in its SOLICIT collection window (last TX is a SOLICIT);
                # leave it queued for after the REQUEST / RENEW / REBIND.
                last_tx = self._tx_log[-1] if self._tx_log else None
                if last_tx is None or last_tx.msg_type is Dhcp6MessageType.SOLICIT:
                    raise TimeoutError
                # Withhold a server-targeted REPLY until the client's most
                # recent message is addressed to that server.
                if front.for_server is not None and last_tx.server_id != front.for_server:
                    raise TimeoutError
                self._reply_queue.popleft()
                return memoryview(front.builder())
            self._reply_queue.popleft()
            if isinstance(front, BaseException):
                raise front
            return memoryview(front())

        mock_socket.sendto.side_effect = on_sendto
        mock_socket.recv__mv.side_effect = on_recv

    def _resolved_echo(self, *, explicit: object, default_extractor: Callable[[Dhcp6Parser], object]) -> object:
        """
        Resolve a maybe-explicit field — if 'explicit' is the '_UNSET'
        sentinel, derive from the most recent client TX via the
        supplied extractor; otherwise return 'explicit' verbatim
        (including 'None' to mean "omit").
        """

        if explicit is not _UNSET:
            return explicit
        if not self._tx_log:
            raise RuntimeError(
                "Dhcp6MockServer cannot derive an echo field without a prior client TX in "
                "tx_log; pass the field explicitly or send a frame first.",
            )
        return default_extractor(self._tx_log[-1])

    def _build_reply(
        self,
        *,
        xid: int | object,
        dns_servers: list[Ip6Address] | None,
        client_id_echo: bytes | None | object,
        server_id: bytes | None | object,
    ) -> bytes:
        """
        Build the canned REPLY frame bytes. A REPLY to an
        INFORMATION-REQUEST carries the Server Identifier, the echoed
        Client Identifier, and the requested other-config options
        (RFC 8415 §18.3.6 / §18.3.7).
        """

        resolved_xid = self._resolved_echo(explicit=xid, default_extractor=lambda tx: tx.xid)
        resolved_cid = self._resolved_echo(explicit=client_id_echo, default_extractor=lambda tx: tx.client_id)
        resolved_sid = self._server_duid if server_id is _UNSET else server_id

        assert isinstance(resolved_xid, int)

        options: list[Dhcp6Option] = []
        if resolved_sid is not None:
            assert isinstance(resolved_sid, (bytes, bytearray))
            options.append(Dhcp6OptionServerId(bytes(resolved_sid)))
        if resolved_cid is not None:
            assert isinstance(resolved_cid, (bytes, bytearray))
            options.append(Dhcp6OptionClientId(bytes(resolved_cid)))
        if dns_servers:
            options.append(Dhcp6OptionDnsServers(dns_servers))

        reply = Dhcp6Assembler(
            dhcp6__msg_type=Dhcp6MessageType.REPLY,
            dhcp6__xid=resolved_xid,
            dhcp6__options=Dhcp6Options(*options),
        )
        return bytes(reply)

    def _identity_options(
        self,
        *,
        xid: int | object,
        client_id_echo: bytes | None | object,
        server_id: bytes | None | object,
    ) -> tuple[int, list[Dhcp6Option]]:
        """
        Resolve the echoed transaction-id and build the Server
        Identifier + echoed Client Identifier options common to every
        ADVERTISE / REPLY.
        """

        resolved_xid = self._resolved_echo(explicit=xid, default_extractor=lambda tx: tx.xid)
        resolved_cid = self._resolved_echo(explicit=client_id_echo, default_extractor=lambda tx: tx.client_id)
        resolved_sid = self._server_duid if server_id is _UNSET else server_id

        assert isinstance(resolved_xid, int)

        options: list[Dhcp6Option] = []
        if resolved_sid is not None:
            assert isinstance(resolved_sid, (bytes, bytearray))
            options.append(Dhcp6OptionServerId(bytes(resolved_sid)))
        if resolved_cid is not None:
            assert isinstance(resolved_cid, (bytes, bytearray))
            options.append(Dhcp6OptionClientId(bytes(resolved_cid)))
        return resolved_xid, options

    def _build_advertise(
        self,
        *,
        preference: int | None,
        xid: int | object,
        client_id_echo: bytes | None | object,
        server_id: bytes | None | object,
    ) -> bytes:
        """
        Build the canned ADVERTISE frame bytes (Server Identifier +
        echoed Client Identifier, plus an optional Preference option).
        """

        resolved_xid, options = self._identity_options(xid=xid, client_id_echo=client_id_echo, server_id=server_id)
        if preference is not None:
            options.append(Dhcp6OptionPreference(preference))
        return bytes(
            Dhcp6Assembler(
                dhcp6__msg_type=Dhcp6MessageType.ADVERTISE,
                dhcp6__xid=resolved_xid,
                dhcp6__options=Dhcp6Options(*options),
            )
        )

    def _build_lease_reply(
        self,
        *,
        address: Ip6Address,
        preferred_lifetime: int,
        valid_lifetime: int,
        t1: int,
        t2: int,
        iaid: int,
        ia_status: Dhcp6StatusCode | None,
        top_status: Dhcp6StatusCode | None,
        omit_ia_address: bool,
        ia_na_options_override: bytes | None,
        rapid_commit: bool,
        xid: int | object,
        client_id_echo: bytes | None | object,
        server_id: bytes | None | object,
    ) -> bytes:
        """
        Build the canned lease-granting REPLY frame bytes (Server
        Identifier + echoed Client Identifier + an optional top-level
        Status Code + an optional Rapid Commit option + IA_NA with a
        nested IA Address and/or Status Code).
        """

        resolved_xid, options = self._identity_options(xid=xid, client_id_echo=client_id_echo, server_id=server_id)

        if top_status is not None:
            options.append(Dhcp6OptionStatusCode(top_status, ""))
        if rapid_commit:
            options.append(Dhcp6OptionRapidCommit())

        if ia_na_options_override is not None:
            ia_na_blob = ia_na_options_override
        else:
            sub_options: list[Dhcp6Option] = []
            if not omit_ia_address:
                sub_options.append(
                    Dhcp6OptionIaAddr(
                        address=address, preferred_lifetime=preferred_lifetime, valid_lifetime=valid_lifetime
                    )
                )
            if ia_status is not None:
                sub_options.append(Dhcp6OptionStatusCode(ia_status, ""))
            ia_na_blob = bytes(Dhcp6Options(*sub_options))

        options.append(Dhcp6OptionIaNa(iaid=iaid, t1=t1, t2=t2, options=ia_na_blob))

        return bytes(
            Dhcp6Assembler(
                dhcp6__msg_type=Dhcp6MessageType.REPLY,
                dhcp6__xid=resolved_xid,
                dhcp6__options=Dhcp6Options(*options),
            )
        )


def autospec_dhcp6_socket() -> MagicMock:
    """
    Build a 'create_autospec'-d, 'spec_set'-locked stand-in for
    'pytcp.runtime.socket.socket'. The returned mock is callable (mirroring
    the socket factory) and yields an instance-shape autospec on each
    call. Wire 'Dhcp6MockServer.wire(mock_socket)' into the
    returned-value instance.

    Defined here rather than inline in test modules so every
    DHCP6-client test uses the same locked-down mock surface.
    """

    from pytcp.runtime.socket import socket as _pytcp_socket

    factory: MagicMock = cast(MagicMock, create_autospec(_pytcp_socket, spec_set=True))
    instance: MagicMock = cast(MagicMock, create_autospec(_pytcp_socket, spec_set=True, instance=True))
    factory.return_value = instance
    return factory
