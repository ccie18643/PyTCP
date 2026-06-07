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
This module contains tests for the IP helper functions.

pytcp/tests/unit/runtime/socket/test__runtime__socket__bind_helpers.py

ver 3.0.8
"""

from types import SimpleNamespace
from unittest import TestCase
from unittest.mock import patch

from net_addr import Ip4Address, Ip6Address
from pytcp.runtime.socket import AddressFamily, SocketType
from pytcp.runtime.socket.socket__bind_helpers import (
    is_address_in_use,
    pick_local_ip4_address,
    pick_local_ip6_address,
    pick_local_ip_address,
    pick_local_port,
    pick_local_port_for,
)


class TestPickLocalIp6Address(TestCase):
    """
    The 'pick_local_ip6_address()' delegation tests.
    """

    def test__ip_helper__pick_local_ip6__delegates_to_egress_aware_selector(self) -> None:
        """
        Ensure pick_local_ip6_address() delegates to the egress-aware
        'stack.select_local_ip6_source', which resolves the egress
        interface and selects a source from THAT interface's addresses, so
        a multi-homed host never sources from a non-egress interface.

        Reference: RFC 6724 §5 (egress-interface-scoped source selection).
        """

        with patch(
            "pytcp.runtime.socket.socket__bind_helpers.stack.select_local_ip6_source",
            return_value=Ip6Address("2001:db8::abcd"),
        ) as select:
            result = pick_local_ip6_address(remote_ip6_address=Ip6Address("2606:4700::1"))

        select.assert_called_once_with(Ip6Address("2606:4700::1"))
        self.assertEqual(
            result,
            Ip6Address("2001:db8::abcd"),
            msg="pick_local_ip6_address() must return the egress-aware selector's choice.",
        )

    def test__ip_helper__pick_local_ip6__unresolved_egress_returns_unspecified(self) -> None:
        """
        Ensure pick_local_ip6_address() returns the unspecified address
        when the egress-aware selector resolves no source (no egress
        interface / routing plane down).

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with patch(
            "pytcp.runtime.socket.socket__bind_helpers.stack.select_local_ip6_source",
            return_value=Ip6Address(),
        ):
            result = pick_local_ip6_address(remote_ip6_address=Ip6Address("2606:4700::1"))

        self.assertEqual(
            result,
            Ip6Address(),
            msg="pick_local_ip6_address() must surface the unspecified address when no source resolves.",
        )


class TestPickLocalIp4Address(TestCase):
    """
    The 'pick_local_ip4_address()' delegation tests.
    """

    def test__ip_helper__pick_local_ip4__delegates_to_egress_aware_selector(self) -> None:
        """
        Ensure pick_local_ip4_address() delegates to the egress-aware
        'stack.select_local_ip4_source'.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with patch(
            "pytcp.runtime.socket.socket__bind_helpers.stack.select_local_ip4_source",
            return_value=Ip4Address("192.0.2.55"),
        ) as select:
            result = pick_local_ip4_address(remote_ip4_address=Ip4Address("1.1.1.1"))

        select.assert_called_once_with(Ip4Address("1.1.1.1"))
        self.assertEqual(
            result,
            Ip4Address("192.0.2.55"),
            msg="pick_local_ip4_address() must return the egress-aware selector's choice.",
        )

    def test__ip_helper__pick_local_ip4__unresolved_egress_returns_unspecified(self) -> None:
        """
        Ensure pick_local_ip4_address() returns the unspecified address
        when the egress-aware selector resolves no source.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with patch(
            "pytcp.runtime.socket.socket__bind_helpers.stack.select_local_ip4_source",
            return_value=Ip4Address(),
        ):
            result = pick_local_ip4_address(remote_ip4_address=Ip4Address("1.1.1.1"))

        self.assertEqual(
            result,
            Ip4Address(),
            msg="pick_local_ip4_address() must surface the unspecified address when no source resolves.",
        )


class TestPickLocalIpAddressDispatch(TestCase):
    """
    The 'pick_local_ip_address()' generic-dispatch tests.
    """

    def test__ip_helper__pick_local_ip__dispatches_to_ip6(self) -> None:
        """
        Ensure the generic helper forwards to the IPv6 helper and
        propagates its return value when the remote is an IPv6 address.
        The generic signature is type-parametrized, so the return type
        must match the input type.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        expected = Ip6Address("2001:db8::cafe")
        remote = Ip6Address("2001:db8::1")

        with (
            patch(
                "pytcp.runtime.socket.socket__bind_helpers.pick_local_ip6_address", return_value=expected
            ) as mock_ip6,
            patch("pytcp.runtime.socket.socket__bind_helpers.pick_local_ip4_address") as mock_ip4,
        ):
            result = pick_local_ip_address(remote_ip_address=remote)

        mock_ip6.assert_called_once_with(remote_ip6_address=remote)
        mock_ip4.assert_not_called()
        self.assertEqual(
            result,
            expected,
            msg="pick_local_ip_address() must return the IPv6 helper's result for IPv6 input.",
        )

    def test__ip_helper__pick_local_ip__dispatches_to_ip4(self) -> None:
        """
        Ensure the generic helper forwards to the IPv4 helper and
        propagates its return value when the remote is an IPv4 address.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        expected = Ip4Address("10.0.0.100")
        remote = Ip4Address("8.8.8.8")

        with (
            patch(
                "pytcp.runtime.socket.socket__bind_helpers.pick_local_ip4_address", return_value=expected
            ) as mock_ip4,
            patch("pytcp.runtime.socket.socket__bind_helpers.pick_local_ip6_address") as mock_ip6,
        ):
            result = pick_local_ip_address(remote_ip_address=remote)

        mock_ip4.assert_called_once_with(remote_ip4_address=remote)
        mock_ip6.assert_not_called()
        self.assertEqual(
            result,
            expected,
            msg="pick_local_ip_address() must return the IPv4 helper's result for IPv4 input.",
        )


class TestPickLocalPort(TestCase):
    """
    The 'pick_local_port()' ephemeral-port-allocator tests.
    """

    def test__ip_helper__pick_local_port__returns_value_from_range(self) -> None:
        """
        Ensure the helper returns a port drawn from
        '_ephemeral_port_pool()' when no socket has claimed anything
        yet.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with (
            patch(
                "pytcp.runtime.socket.socket__bind_helpers._ephemeral_port_pool", return_value=range(10000, 10004, 2)
            ),
            patch("pytcp.runtime.socket.socket__bind_helpers.stack.sockets", {}),
        ):
            port = pick_local_port()

        self.assertIn(
            port,
            {10000, 10002},
            msg="pick_local_port() must return a value from the configured ephemeral port range.",
        )

    def test__ip_helper__pick_local_port__skips_ports_already_in_use(self) -> None:
        """
        Ensure ports currently used by any open socket are excluded from
        the pool. If every port-but-one is taken, the helper must pick
        that last remaining port.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        sockets = {
            "s1": SimpleNamespace(local_port=10000),
            "s2": SimpleNamespace(local_port=10002),
        }

        with (
            patch(
                "pytcp.runtime.socket.socket__bind_helpers._ephemeral_port_pool", return_value=range(10000, 10006, 2)
            ),
            patch("pytcp.runtime.socket.socket__bind_helpers.stack.sockets", sockets),
        ):
            port = pick_local_port()

        self.assertEqual(
            port,
            10004,
            msg="pick_local_port() must pick the single remaining free port when all others are in use.",
        )

    def test__ip_helper__pick_local_port__uses_secrets_choice_for_entropy(self) -> None:
        """
        Ensure the picker delegates the final selection to
        'secrets.choice', a CSPRNG-backed primitive, rather than
        relying on Python set-pop hash ordering. The
        'secrets.choice' call MUST receive the unused-ports
        collection (anything in the ephemeral-port pool that no
        existing socket has claimed) so an attacker observing
        one selection learns nothing useful about future ones.

        Reference: RFC 6056 §3.1 (obfuscate the ephemeral port
        selection; needs cryptographic-quality randomness).
        """

        sockets = {"s1": SimpleNamespace(local_port=10002)}

        with (
            patch("pytcp.runtime.socket.socket__bind_helpers._ephemeral_port_pool", return_value=range(10000, 10006)),
            patch("pytcp.runtime.socket.socket__bind_helpers.stack.sockets", sockets),
            patch("pytcp.runtime.socket.socket__bind_helpers.secrets.choice", return_value=10005) as mock_choice,
        ):
            port = pick_local_port()

        self.assertEqual(
            port,
            10005,
            msg="pick_local_port() must return the value secrets.choice yields.",
        )
        mock_choice.assert_called_once()
        (passed_pool,), _kwargs = mock_choice.call_args
        self.assertEqual(
            sorted(passed_pool),
            [10000, 10001, 10003, 10004, 10005],
            msg=(
                "secrets.choice must be invoked with every port from "
                "the ephemeral-port pool that no existing socket has claimed."
            ),
        )

    def test__ip_helper__pick_local_port__raises_when_exhausted(self) -> None:
        """
        Ensure 'pick_local_port()' raises 'OSError' with the canonical
        '[Errno 98] Address already in use' message when every port in
        the ephemeral range is claimed.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        sockets = {f"s{p}": SimpleNamespace(local_port=p) for p in range(10000, 10006, 2)}

        with (
            patch(
                "pytcp.runtime.socket.socket__bind_helpers._ephemeral_port_pool", return_value=range(10000, 10006, 2)
            ),
            patch("pytcp.runtime.socket.socket__bind_helpers.stack.sockets", sockets),
        ):
            with self.assertRaises(OSError) as context:
                pick_local_port()

        self.assertIn(
            "[Errno 98] Address already in use",
            str(context.exception),
            msg="pick_local_port() must raise with the canonical Errno 98 message when exhausted.",
        )


class TestPickLocalPortFor(TestCase):
    """
    The 'pick_local_port_for()' destination-aware Algorithm 3 tests.
    """

    def test__ip_helper__pick_local_port_for__deterministic_for_same_inputs(self) -> None:
        """
        Ensure two calls with identical (local_ip, remote_ip,
        remote_port) and the same stack secret pick the same
        port — Algorithm 3 is a keyed-hash offset, deterministic
        in its inputs.

        Reference: RFC 6056 §3.3.3 (Algorithm 3: same offset for
        the same five-tuple inputs).
        """

        with (
            patch("pytcp.runtime.socket.socket__bind_helpers._ephemeral_port_pool", return_value=range(40000, 50000)),
            patch("pytcp.runtime.socket.socket__bind_helpers.stack.sockets", {}),
            patch("pytcp.runtime.socket.socket__bind_helpers.stack.TCP__PORT_SECRET", b"\x00" * 16),
        ):
            port_a = pick_local_port_for(
                local_ip=Ip4Address("10.0.0.1"),
                remote_ip=Ip4Address("198.51.100.1"),
                remote_port=443,
            )
            port_b = pick_local_port_for(
                local_ip=Ip4Address("10.0.0.1"),
                remote_ip=Ip4Address("198.51.100.1"),
                remote_port=443,
            )

        self.assertEqual(
            port_a,
            port_b,
            msg="Algorithm 3 must return the same port for identical inputs + secret.",
        )

    def test__ip_helper__pick_local_port_for__different_destinations_isolated(self) -> None:
        """
        Ensure two calls with different remote tuples produce
        different starting offsets — the Algorithm 3 §3.3.3
        per-destination isolation property. Without isolation
        an attacker who learns one source port could predict
        others.

        Reference: RFC 6056 §3.3.3 (per-destination subspace).
        """

        with (
            patch("pytcp.runtime.socket.socket__bind_helpers._ephemeral_port_pool", return_value=range(40000, 50000)),
            patch("pytcp.runtime.socket.socket__bind_helpers.stack.sockets", {}),
            patch("pytcp.runtime.socket.socket__bind_helpers.stack.TCP__PORT_SECRET", b"\x00" * 16),
        ):
            port_to_server_a = pick_local_port_for(
                local_ip=Ip4Address("10.0.0.1"),
                remote_ip=Ip4Address("198.51.100.1"),
                remote_port=443,
            )
            port_to_server_b = pick_local_port_for(
                local_ip=Ip4Address("10.0.0.1"),
                remote_ip=Ip4Address("198.51.100.2"),
                remote_port=443,
            )

        self.assertNotEqual(
            port_to_server_a,
            port_to_server_b,
            msg="Algorithm 3 must yield different ports for different remote addresses.",
        )

    def test__ip_helper__pick_local_port_for__secret_keyed(self) -> None:
        """
        Ensure two calls with identical inputs but DIFFERENT
        stack secrets pick different ports — the offset must be
        keyed by the per-process secret so an off-path attacker
        cannot precompute the offset table.

        Reference: RFC 6056 §3.4 (secret-key considerations).
        """

        local_ip = Ip4Address("10.0.0.1")
        remote_ip = Ip4Address("198.51.100.1")
        remote_port = 443

        with (
            patch("pytcp.runtime.socket.socket__bind_helpers._ephemeral_port_pool", return_value=range(40000, 50000)),
            patch("pytcp.runtime.socket.socket__bind_helpers.stack.sockets", {}),
            patch("pytcp.runtime.socket.socket__bind_helpers.stack.TCP__PORT_SECRET", b"\x00" * 16),
        ):
            port_secret_zero = pick_local_port_for(
                local_ip=local_ip,
                remote_ip=remote_ip,
                remote_port=remote_port,
            )

        with (
            patch("pytcp.runtime.socket.socket__bind_helpers._ephemeral_port_pool", return_value=range(40000, 50000)),
            patch("pytcp.runtime.socket.socket__bind_helpers.stack.sockets", {}),
            patch("pytcp.runtime.socket.socket__bind_helpers.stack.TCP__PORT_SECRET", b"\xff" * 16),
        ):
            port_secret_ones = pick_local_port_for(
                local_ip=local_ip,
                remote_ip=remote_ip,
                remote_port=remote_port,
            )

        self.assertNotEqual(
            port_secret_zero,
            port_secret_ones,
            msg="Algorithm 3 offset must change when the per-stack secret changes.",
        )

    def test__ip_helper__pick_local_port_for__skips_ports_already_in_use(self) -> None:
        """
        Ensure the picker scans forward from the hashed offset
        when the initial pick is already taken — Algorithm 3's
        linear scan over the ephemeral-port pool.

        Reference: RFC 6056 §3.3.3 (linear scan on collision).
        """

        # Build a sockets map that occupies the first many ports
        # in the range; the picker must walk past them.
        used_ports = list(range(40000, 40050))
        sockets = {f"s{p}": SimpleNamespace(local_port=p) for p in used_ports}

        with (
            patch("pytcp.runtime.socket.socket__bind_helpers._ephemeral_port_pool", return_value=range(40000, 50000)),
            patch("pytcp.runtime.socket.socket__bind_helpers.stack.sockets", sockets),
            patch("pytcp.runtime.socket.socket__bind_helpers.stack.TCP__PORT_SECRET", b"\x00" * 16),
        ):
            port = pick_local_port_for(
                local_ip=Ip4Address("10.0.0.1"),
                remote_ip=Ip4Address("198.51.100.1"),
                remote_port=443,
            )

        self.assertNotIn(
            port,
            used_ports,
            msg="pick_local_port_for must skip ports held by existing sockets.",
        )
        self.assertIn(
            port,
            range(40000, 50000),
            msg="pick_local_port_for must return a value from the configured range.",
        )

    def test__ip_helper__pick_local_port_for__raises_when_exhausted(self) -> None:
        """
        Ensure the picker raises OSError with the canonical
        '[Errno 98] Address already in use' message when every
        port in the range is claimed, matching the contract of
        the bare 'pick_local_port'.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        sockets = {f"s{p}": SimpleNamespace(local_port=p) for p in range(40000, 40010)}

        with (
            patch("pytcp.runtime.socket.socket__bind_helpers._ephemeral_port_pool", return_value=range(40000, 40010)),
            patch("pytcp.runtime.socket.socket__bind_helpers.stack.sockets", sockets),
            patch("pytcp.runtime.socket.socket__bind_helpers.stack.TCP__PORT_SECRET", b"\x00" * 16),
        ):
            with self.assertRaises(OSError) as context:
                pick_local_port_for(
                    local_ip=Ip4Address("10.0.0.1"),
                    remote_ip=Ip4Address("198.51.100.1"),
                    remote_port=443,
                )

        self.assertIn(
            "[Errno 98] Address already in use",
            str(context.exception),
            msg="pick_local_port_for must raise with the canonical Errno 98 message when exhausted.",
        )


class TestIsAddressInUse(TestCase):
    """
    The 'is_address_in_use()' tests.
    """

    def _make_socket(
        self,
        *,
        family: AddressFamily,
        type: SocketType,
        local_ip_address: Ip4Address | Ip6Address,
        local_port: int,
        reuseport: bool = False,
    ) -> SimpleNamespace:
        """
        Build a namespace stub whose attribute surface matches the small
        slice of the socket API that 'is_address_in_use' inspects.
        """

        return SimpleNamespace(
            family=family,
            type=type,
            local_ip_address=local_ip_address,
            local_port=local_port,
            _so_reuseport=reuseport,
        )

    def test__ip_helper__is_address_in_use__exact_match_returns_true(self) -> None:
        """
        Ensure an open socket bound to exactly the same
        (family, type, IP, port) tuple flags the address as in use.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        opened = self._make_socket(
            family=AddressFamily.INET4,
            type=SocketType.STREAM,
            local_ip_address=Ip4Address("10.0.0.1"),
            local_port=8080,
        )

        with patch("pytcp.runtime.socket.socket__bind_helpers.stack.sockets", {"s1": opened}):
            result = is_address_in_use(
                local_ip_address=Ip4Address("10.0.0.1"),
                local_port=8080,
                address_family=AddressFamily.INET4,
                socket_type=SocketType.STREAM,
            )

        self.assertTrue(
            result,
            msg="is_address_in_use() must return True when an identical socket is already open.",
        )

    def test__ip_helper__is_address_in_use__open_on_unspecified_blocks_specific(self) -> None:
        """
        Ensure a socket bound to the unspecified address (e.g. 0.0.0.0)
        blocks subsequent binds on any specific address using the same
        port/family/type — the BSD 'bound to ANY' semantics.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        opened = self._make_socket(
            family=AddressFamily.INET4,
            type=SocketType.STREAM,
            local_ip_address=Ip4Address(),
            local_port=8080,
        )

        with patch("pytcp.runtime.socket.socket__bind_helpers.stack.sockets", {"s1": opened}):
            result = is_address_in_use(
                local_ip_address=Ip4Address("10.0.0.1"),
                local_port=8080,
                address_family=AddressFamily.INET4,
                socket_type=SocketType.STREAM,
            )

        self.assertTrue(
            result,
            msg="A socket bound to 0.0.0.0 must block a specific-IP bind on the same port.",
        )

    def test__ip_helper__is_address_in_use__new_unspecified_blocks_specific(self) -> None:
        """
        Ensure a new bind request on the unspecified address is blocked
        by any existing socket bound to a specific IP on the same port,
        family, and socket type.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        opened = self._make_socket(
            family=AddressFamily.INET4,
            type=SocketType.STREAM,
            local_ip_address=Ip4Address("10.0.0.1"),
            local_port=8080,
        )

        with patch("pytcp.runtime.socket.socket__bind_helpers.stack.sockets", {"s1": opened}):
            result = is_address_in_use(
                local_ip_address=Ip4Address(),
                local_port=8080,
                address_family=AddressFamily.INET4,
                socket_type=SocketType.STREAM,
            )

        self.assertTrue(
            result,
            msg="A specific-IP bind must block a subsequent 0.0.0.0 bind on the same port.",
        )

    def test__ip_helper__is_address_in_use__different_port_returns_false(self) -> None:
        """
        Ensure a different port is considered free even when the family,
        type, and local IP match an existing socket.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        opened = self._make_socket(
            family=AddressFamily.INET4,
            type=SocketType.STREAM,
            local_ip_address=Ip4Address("10.0.0.1"),
            local_port=8080,
        )

        with patch("pytcp.runtime.socket.socket__bind_helpers.stack.sockets", {"s1": opened}):
            result = is_address_in_use(
                local_ip_address=Ip4Address("10.0.0.1"),
                local_port=9090,
                address_family=AddressFamily.INET4,
                socket_type=SocketType.STREAM,
            )

        self.assertFalse(
            result,
            msg="is_address_in_use() must return False for a different port.",
        )

    def test__ip_helper__is_address_in_use__different_family_returns_false(self) -> None:
        """
        Ensure sockets in a different address family are ignored so an
        IPv4 bind is not blocked by an IPv6 listener on the same port.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        opened = self._make_socket(
            family=AddressFamily.INET6,
            type=SocketType.STREAM,
            local_ip_address=Ip6Address("::"),
            local_port=8080,
        )

        with patch("pytcp.runtime.socket.socket__bind_helpers.stack.sockets", {"s1": opened}):
            result = is_address_in_use(
                local_ip_address=Ip4Address("10.0.0.1"),
                local_port=8080,
                address_family=AddressFamily.INET4,
                socket_type=SocketType.STREAM,
            )

        self.assertFalse(
            result,
            msg="is_address_in_use() must ignore sockets from a different address family.",
        )

    def test__ip_helper__is_address_in_use__different_type_returns_false(self) -> None:
        """
        Ensure sockets of a different type (STREAM vs DGRAM) are ignored
        so a TCP bind is not blocked by a UDP listener on the same port.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        opened = self._make_socket(
            family=AddressFamily.INET4,
            type=SocketType.DGRAM,
            local_ip_address=Ip4Address("10.0.0.1"),
            local_port=8080,
        )

        with patch("pytcp.runtime.socket.socket__bind_helpers.stack.sockets", {"s1": opened}):
            result = is_address_in_use(
                local_ip_address=Ip4Address("10.0.0.1"),
                local_port=8080,
                address_family=AddressFamily.INET4,
                socket_type=SocketType.STREAM,
            )

        self.assertFalse(
            result,
            msg="is_address_in_use() must ignore sockets of a different socket type.",
        )

    def test__ip_helper__is_address_in_use__different_ip_returns_false(self) -> None:
        """
        Ensure a different specific local IP on the same port/family/type
        is considered free — BSD sockets allow multiple binds at the
        same port as long as the specific addresses differ.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        opened = self._make_socket(
            family=AddressFamily.INET4,
            type=SocketType.STREAM,
            local_ip_address=Ip4Address("10.0.0.1"),
            local_port=8080,
        )

        with patch("pytcp.runtime.socket.socket__bind_helpers.stack.sockets", {"s1": opened}):
            result = is_address_in_use(
                local_ip_address=Ip4Address("10.0.0.2"),
                local_port=8080,
                address_family=AddressFamily.INET4,
                socket_type=SocketType.STREAM,
            )

        self.assertFalse(
            result,
            msg="is_address_in_use() must return False for a different specific local IP on the same port.",
        )

    def test__ip_helper__is_address_in_use__empty_sockets_returns_false(self) -> None:
        """
        Ensure a completely empty socket table always resolves to free.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with patch("pytcp.runtime.socket.socket__bind_helpers.stack.sockets", {}):
            result = is_address_in_use(
                local_ip_address=Ip4Address("10.0.0.1"),
                local_port=8080,
                address_family=AddressFamily.INET4,
                socket_type=SocketType.STREAM,
            )

        self.assertFalse(
            result,
            msg="is_address_in_use() must return False when no sockets are open.",
        )

    def _make_socket_v6only(
        self,
        *,
        family: AddressFamily,
        type: SocketType,
        local_ip_address: Ip4Address | Ip6Address,
        local_port: int,
        ipv6_v6only: bool = True,
    ) -> SimpleNamespace:
        """
        Build a stub like '_make_socket' but with the extra
        '_ipv6_v6only' flag the dual-stack conflict logic reads.
        """

        return SimpleNamespace(
            family=family,
            type=type,
            local_ip_address=local_ip_address,
            local_port=local_port,
            _ipv6_v6only=ipv6_v6only,
        )

    def test__ip_helper__is_address_in_use__ipv6_v6only_off_blocks_ipv4(self) -> None:
        """
        Ensure an open AF_INET6 listener bound to '::' with
        'IPV6_V6ONLY = 0' (dual-stack mode) blocks a subsequent
        AF_INET bind on the same port — Linux's cross-family
        EADDRINUSE semantic when an IPv6 dual-stack listener
        already occupies the port.

        Reference: Linux IPV6_V6ONLY (0 = dual-stack reserves both families).
        """

        opened = self._make_socket_v6only(
            family=AddressFamily.INET6,
            type=SocketType.STREAM,
            local_ip_address=Ip6Address(),  # ::
            local_port=8080,
            ipv6_v6only=False,
        )

        with patch("pytcp.runtime.socket.socket__bind_helpers.stack.sockets", {"s1": opened}):
            result = is_address_in_use(
                local_ip_address=Ip4Address("10.0.0.1"),
                local_port=8080,
                address_family=AddressFamily.INET4,
                socket_type=SocketType.STREAM,
            )

        self.assertTrue(
            result,
            msg=(
                "An AF_INET6 V6ONLY=0 listener on '::' must block an AF_INET bind on the "
                "same port (Linux cross-family EADDRINUSE)."
            ),
        )

    def test__ip_helper__is_address_in_use__ipv6_v6only_on_does_not_block_ipv4(self) -> None:
        """
        Ensure an open AF_INET6 listener bound to '::' with
        'IPV6_V6ONLY = 1' (strict IPv6) does NOT block a
        subsequent AF_INET bind on the same port — the default
        Python / Linux behaviour where IPv4 and IPv6 are
        separate namespaces.

        Reference: Linux IPV6_V6ONLY (1 = strict IPv6 namespace).
        """

        opened = self._make_socket_v6only(
            family=AddressFamily.INET6,
            type=SocketType.STREAM,
            local_ip_address=Ip6Address(),  # ::
            local_port=8080,
            ipv6_v6only=True,
        )

        with patch("pytcp.runtime.socket.socket__bind_helpers.stack.sockets", {"s1": opened}):
            result = is_address_in_use(
                local_ip_address=Ip4Address("10.0.0.1"),
                local_port=8080,
                address_family=AddressFamily.INET4,
                socket_type=SocketType.STREAM,
            )

        self.assertFalse(
            result,
            msg=(
                "An AF_INET6 V6ONLY=1 listener must NOT block an AF_INET bind on the same "
                "port (separate namespaces)."
            ),
        )

    def test__ip_helper__is_address_in_use__ipv4_blocks_new_v6only_off_ipv6(self) -> None:
        """
        Ensure a pre-existing AF_INET listener on '0.0.0.0'
        blocks a new AF_INET6 socket attempting to bind to
        '::' with 'V6ONLY = 0' — the same cross-family lock
        symmetrically in the other direction.

        Reference: Linux IPV6_V6ONLY (0 = dual-stack vs existing IPv4 conflict).
        """

        opened = self._make_socket_v6only(
            family=AddressFamily.INET4,
            type=SocketType.STREAM,
            local_ip_address=Ip4Address(),  # 0.0.0.0
            local_port=8080,
        )

        with patch("pytcp.runtime.socket.socket__bind_helpers.stack.sockets", {"s1": opened}):
            result = is_address_in_use(
                local_ip_address=Ip6Address(),  # ::
                local_port=8080,
                address_family=AddressFamily.INET6,
                socket_type=SocketType.STREAM,
                dual_stack=True,
            )

        self.assertTrue(
            result,
            msg=("A new V6ONLY=0 IPv6 bind to '::' must see an existing IPv4 listener as a " "conflict."),
        )

    def test__ip_helper__is_address_in_use__ipv4_does_not_block_new_strict_ipv6(self) -> None:
        """
        Ensure a pre-existing AF_INET listener does NOT block a
        new AF_INET6 'V6ONLY = 1' (strict) bind on '::' same
        port — strict IPv6 lives in its own namespace.

        Reference: Linux IPV6_V6ONLY (1 = no cross-family conflict).
        """

        opened = self._make_socket_v6only(
            family=AddressFamily.INET4,
            type=SocketType.STREAM,
            local_ip_address=Ip4Address(),
            local_port=8080,
        )

        with patch("pytcp.runtime.socket.socket__bind_helpers.stack.sockets", {"s1": opened}):
            result = is_address_in_use(
                local_ip_address=Ip6Address(),
                local_port=8080,
                address_family=AddressFamily.INET6,
                socket_type=SocketType.STREAM,
                dual_stack=False,
            )

        self.assertFalse(
            result,
            msg="A new V6ONLY=1 IPv6 bind must NOT see an existing IPv4 listener as a conflict.",
        )

    def test__ip_helper__is_address_in_use__v6only_off_on_specific_address_does_not_block_ipv4(self) -> None:
        """
        Ensure an open AF_INET6 'V6ONLY = 0' listener bound to
        a SPECIFIC IPv6 address (not '::') does NOT block a
        subsequent AF_INET bind same port — dual-stack
        reservation only triggers when the IPv6 socket is bound
        to the wildcard.

        Reference: Linux IPV6_V6ONLY (dual-stack reserves only when bound to '::').
        """

        opened = self._make_socket_v6only(
            family=AddressFamily.INET6,
            type=SocketType.STREAM,
            local_ip_address=Ip6Address("2001:db8::1"),
            local_port=8080,
            ipv6_v6only=False,
        )

        with patch("pytcp.runtime.socket.socket__bind_helpers.stack.sockets", {"s1": opened}):
            result = is_address_in_use(
                local_ip_address=Ip4Address("10.0.0.1"),
                local_port=8080,
                address_family=AddressFamily.INET4,
                socket_type=SocketType.STREAM,
            )

        self.assertFalse(
            result,
            msg=(
                "A V6ONLY=0 listener bound to a SPECIFIC IPv6 address must NOT cross-block "
                "IPv4 — dual-stack reservation triggers only on '::'."
            ),
        )

    def test__ip_helper__is_address_in_use__reuseport_both_set_returns_false(self) -> None:
        """
        Ensure an otherwise-conflicting overlap is permitted when both
        the binding socket and the open socket carry SO_REUSEPORT —
        the cohort case.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        opened = self._make_socket(
            family=AddressFamily.INET4,
            type=SocketType.STREAM,
            local_ip_address=Ip4Address("10.0.0.1"),
            local_port=8080,
            reuseport=True,
        )

        with patch("pytcp.runtime.socket.socket__bind_helpers.stack.sockets", {"s1": opened}):
            result = is_address_in_use(
                local_ip_address=Ip4Address("10.0.0.1"),
                local_port=8080,
                address_family=AddressFamily.INET4,
                socket_type=SocketType.STREAM,
                reuseport=True,
            )

        self.assertFalse(
            result,
            msg="An exact overlap must NOT be in use when both sockets set SO_REUSEPORT.",
        )

    def test__ip_helper__is_address_in_use__reuseport_only_new_returns_true(self) -> None:
        """
        Ensure a new SO_REUSEPORT bind still conflicts when the open
        socket on the same tuple lacks SO_REUSEPORT — the group rule
        requires every member to set the flag.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        opened = self._make_socket(
            family=AddressFamily.INET4,
            type=SocketType.STREAM,
            local_ip_address=Ip4Address("10.0.0.1"),
            local_port=8080,
            reuseport=False,
        )

        with patch("pytcp.runtime.socket.socket__bind_helpers.stack.sockets", {"s1": opened}):
            result = is_address_in_use(
                local_ip_address=Ip4Address("10.0.0.1"),
                local_port=8080,
                address_family=AddressFamily.INET4,
                socket_type=SocketType.STREAM,
                reuseport=True,
            )

        self.assertTrue(
            result,
            msg="SO_REUSEPORT must not join a group with a non-REUSEPORT open socket.",
        )

    def test__ip_helper__is_address_in_use__reuseport_only_opened_returns_true(self) -> None:
        """
        Ensure a plain (non-SO_REUSEPORT) bind still conflicts with an
        open SO_REUSEPORT socket on the same tuple — the new socket
        cannot join the existing cohort without the flag.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        opened = self._make_socket(
            family=AddressFamily.INET4,
            type=SocketType.STREAM,
            local_ip_address=Ip4Address("10.0.0.1"),
            local_port=8080,
            reuseport=True,
        )

        with patch("pytcp.runtime.socket.socket__bind_helpers.stack.sockets", {"s1": opened}):
            result = is_address_in_use(
                local_ip_address=Ip4Address("10.0.0.1"),
                local_port=8080,
                address_family=AddressFamily.INET4,
                socket_type=SocketType.STREAM,
                reuseport=False,
            )

        self.assertTrue(
            result,
            msg="A plain bind must conflict with an existing SO_REUSEPORT socket.",
        )


def _open_socket(*, port: int, ifindex: int | None) -> SimpleNamespace:
    """
    Build a stand-in already-open UDP/IPv4 socket bound to 0.0.0.0:'port'
    and pinned to '_egress_ifindex' (None when unbound) for the
    'is_address_in_use' SO_BINDTODEVICE tests.
    """

    return SimpleNamespace(
        type=SocketType.DGRAM,
        local_port=port,
        family=AddressFamily.INET4,
        local_ip_address=Ip4Address(),
        _so_reuseport=False,
        _ipv6_v6only=True,
        _egress_ifindex=ifindex,
    )


class TestIsAddressInUseBindToDevice(TestCase):
    """
    The 'is_address_in_use' SO_BINDTODEVICE device-awareness tests.
    """

    def _in_use(self, *, sockets: dict[str, SimpleNamespace], bound_ifindex: int | None) -> bool:
        """
        Run 'is_address_in_use' for a 0.0.0.0:68 UDP/IPv4 bind against a
        patched 'stack.sockets', returning whether it reports a conflict.
        """

        with patch("pytcp.runtime.socket.socket__bind_helpers.stack.sockets", sockets):
            return is_address_in_use(
                local_ip_address=Ip4Address(),
                local_port=68,
                address_family=AddressFamily.INET4,
                socket_type=SocketType.DGRAM,
                bound_ifindex=bound_ifindex,
            )

    def test__is_address_in_use__same_port_different_device_no_conflict(self) -> None:
        """
        Ensure two sockets bound to the same (0.0.0.0, 68) but pinned to
        different interfaces via SO_BINDTODEVICE do not conflict — each
        only sees traffic on its own device (two DHCP clients on a
        multi-homed host).

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertFalse(
            self._in_use(sockets={"s1": _open_socket(port=68, ifindex=1)}, bound_ifindex=2),
            msg="Sockets on the same port but different interfaces must not conflict.",
        )

    def test__is_address_in_use__same_port_same_device_conflicts(self) -> None:
        """
        Ensure two sockets bound to the same (0.0.0.0, 68) on the SAME
        interface still conflict.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertTrue(
            self._in_use(sockets={"s1": _open_socket(port=68, ifindex=1)}, bound_ifindex=1),
            msg="Sockets on the same port and the same interface must conflict.",
        )

    def test__is_address_in_use__unbound_binder_conflicts_with_device_bound(self) -> None:
        """
        Ensure an unbound binding socket conflicts with a device-bound open
        socket on the same port — the unbound socket spans every interface,
        including the bound one.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertTrue(
            self._in_use(sockets={"s1": _open_socket(port=68, ifindex=1)}, bound_ifindex=None),
            msg="An unbound binder must conflict with a device-bound open socket on the same port.",
        )

    def test__is_address_in_use__device_bound_binder_conflicts_with_unbound(self) -> None:
        """
        Ensure a device-bound binding socket conflicts with an unbound open
        socket on the same port — the unbound open socket already spans
        every interface.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertTrue(
            self._in_use(sockets={"s1": _open_socket(port=68, ifindex=None)}, bound_ifindex=1),
            msg="A device-bound binder must conflict with an unbound open socket on the same port.",
        )
