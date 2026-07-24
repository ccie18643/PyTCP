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
Tests for the IPC control-plane tagged value codec.

pytcp/tests/unit/ipc/test__ipc__values.py

ver 3.0.8
"""

import json
from typing import Any
from unittest import TestCase

from net_addr import (
    Ip4Address,
    Ip4IfAddr,
    Ip4Mask,
    Ip4Network,
    Ip6Address,
    Ip6IfAddr,
    Ip6Mask,
    Ip6Network,
    MacAddress,
)
from net_proto.lib.enums import EtherType
from pytcp.ipc.ipc__errors import IpcValueError
from pytcp.ipc.ipc__values import decode_value, encode_value
from pytcp.lib.interface_layer import InterfaceLayer
from pytcp.lib.neighbor import NudState
from pytcp.runtime.fib import Route, RouteProtocol, RouteScope
from pytcp.runtime.socket import (
    IP_TTL,
    IPPROTO_TCP,
    IPV6_UNICAST_HOPS,
    SO_KEEPALIVE,
    SOL_SOCKET,
    TCP_NODELAY,
    AddressFamily,
    PacketType,
    SocketType,
)
from pytcp.runtime.socket.sockaddr_ll import SockAddrLl
from pytcp.stack.activity_introspect import InterfaceActivity
from pytcp.stack.link import LinkFlag, LinkStats
from pytcp.stack.neighbor import NeighborSnapshot


class TestIpcValuesRoundTrip(TestCase):
    """
    The IPC value-codec round-trip tests.
    """

    def test__ipc__values__primitives(self) -> None:
        """
        Ensure JSON-native primitives survive an encode/decode round
        trip unchanged and untagged.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        for value in [0, -7, 42, 3.5, "hello", "", True, False, None]:
            with self.subTest(value=value):
                self.assertEqual(
                    decode_value(encode_value(value)),
                    value,
                    msg=f"Primitive {value!r} must round-trip unchanged.",
                )

    def test__ipc__values__net_addr_types(self) -> None:
        """
        Ensure each net_addr value type round-trips to an equal value
        via its canonical string form.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        for value in [
            Ip4Address("10.0.1.7"),
            Ip6Address("2001:db8::7"),
            MacAddress("02:00:00:00:00:07"),
            Ip4Network("10.0.1.0/24"),
            Ip6Network("2001:db8::/64"),
            Ip4IfAddr("10.0.1.7/24"),
            Ip6IfAddr("2001:db8::7/64"),
            Ip4Mask("/24"),
            Ip6Mask("/64"),
        ]:
            with self.subTest(value=value):
                self.assertEqual(
                    decode_value(encode_value(value)),
                    value,
                    msg=f"net_addr value {value!r} must round-trip to an equal value.",
                )

    def test__ipc__values__bytes_round_trip(self) -> None:
        """
        Ensure a bytes value round-trips unchanged via its base64 tagged
        form, so a setsockopt value / getsockopt return that is raw
        bytes survives the JSON-bodied control channel.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        for value in [b"", b"\x00\x01\x02\xff", b"SO_OPT", bytes(range(256))]:
            with self.subTest(value=value):
                self.assertEqual(
                    decode_value(encode_value(value)),
                    value,
                    msg=f"Bytes value {value!r} must round-trip unchanged.",
                )

    def test__ipc__values__bytes_encoded_form_is_json_serialisable(self) -> None:
        """
        Ensure the encoded bytes form contains only JSON-native
        structures, so it survives a json.dumps / json.loads cycle.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            decode_value(json.loads(json.dumps(encode_value(b"\xde\xad\xbe\xef")))),
            b"\xde\xad\xbe\xef",
            msg="An encoded bytes value must survive a JSON serialise/parse cycle.",
        )

    def test__ipc__values__enums_round_trip_to_same_member(self) -> None:
        """
        Ensure each control-plane enum round-trips to the identical
        member, so an IntEnum is not flattened to a bare integer on the
        wire.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        for value in [
            AddressFamily.INET4,
            AddressFamily.INET6,
            SocketType.STREAM,
            SocketType.DGRAM,
            RouteProtocol.STATIC,
            RouteScope.LINK,
            NudState.PERMANENT,
            InterfaceLayer.L2,
            LinkFlag.MULTICAST,
        ]:
            with self.subTest(value=value):
                self.assertIs(
                    decode_value(encode_value(value)),
                    value,
                    msg=f"Enum {value!r} must round-trip to the identical member.",
                )

    def test__ipc__values__socket_option_enums_round_trip(self) -> None:
        """
        Ensure each setsockopt / getsockopt level and option-name enum
        round-trips to the identical member, so an IPPROTO_* level (a
        net_proto ProtoEnum, which is not equal to its integer) survives
        the boundary and still compares equal on the daemon side.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        for value in [
            SOL_SOCKET,
            SO_KEEPALIVE,
            IPPROTO_TCP,
            TCP_NODELAY,
            IP_TTL,
            IPV6_UNICAST_HOPS,
        ]:
            with self.subTest(value=value):
                self.assertIs(
                    decode_value(encode_value(value)),
                    value,
                    msg=f"Socket-option enum {value!r} must round-trip to the identical member.",
                )

    def test__ipc__values__containers(self) -> None:
        """
        Ensure list / tuple / frozenset / dict containers round-trip
        with their element types preserved and their container kind
        distinguished (a tuple does not decode as a list).

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        for value in [
            [Ip4Address("10.0.1.7"), 1, "x"],
            (Ip4Address("10.0.1.7"), RouteScope.LINK),
            frozenset({LinkFlag.MULTICAST, LinkFlag.BROADCAST}),
            {"arp.cache.max_age": 60, "name": "tap7"},
        ]:
            with self.subTest(value=value):
                self.assertEqual(
                    decode_value(encode_value(value)),
                    value,
                    msg=f"Container {value!r} must round-trip with kind preserved.",
                )

    def test__ipc__values__tuple_not_decoded_as_list(self) -> None:
        """
        Ensure a tuple decodes back to a tuple, not a list, so the
        container kind is faithfully carried (JSON arrays alone would
        lose it).

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertIsInstance(
            decode_value(encode_value((1, 2, 3))),
            tuple,
            msg="A tuple must decode back to a tuple, not a list.",
        )

    def test__ipc__values__route_snapshot(self) -> None:
        """
        Ensure a Route snapshot round-trips field-by-field, including
        the optional gateway / prefsrc fields in both their set and
        None forms.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        for route in [
            Route(
                destination=Ip4Network("10.0.2.0/24"),
                gateway=Ip4Address("10.0.1.1"),
                prefsrc=Ip4Address("10.0.1.7"),
                metric=100,
                scope=RouteScope.UNIVERSE,
                protocol=RouteProtocol.STATIC,
                oif=2,
            ),
            Route(
                destination=Ip4Network("10.0.1.0/24"),
                metric=0,
                scope=RouteScope.LINK,
                protocol=RouteProtocol.KERNEL,
            ),
        ]:
            with self.subTest(route=route):
                self.assertEqual(
                    decode_value(encode_value(route)),
                    route,
                    msg=f"Route {route!r} must round-trip field-by-field.",
                )

    def test__ipc__values__neighbor_snapshot(self) -> None:
        """
        Ensure a NeighborSnapshot round-trips, including the optional
        mac_address field in both its set and None forms.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        for snapshot in [
            NeighborSnapshot(
                address=Ip4Address("10.0.1.91"),
                mac_address=MacAddress("02:00:00:00:00:91"),
                state=NudState.REACHABLE,
            ),
            NeighborSnapshot(
                address=Ip6Address("2001:db8::91"),
                mac_address=None,
                state=NudState.INCOMPLETE,
            ),
        ]:
            with self.subTest(snapshot=snapshot):
                self.assertEqual(
                    decode_value(encode_value(snapshot)),
                    snapshot,
                    msg=f"NeighborSnapshot {snapshot!r} must round-trip.",
                )

    def test__ipc__values__sockaddr_ll_round_trip(self) -> None:
        """
        Ensure a SockAddrLl link-layer address round-trips field-by-field,
        including its EtherType / PacketType enum members and MacAddress.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        for address in [
            SockAddrLl(
                ifindex=2,
                ethertype=EtherType.ARP,
                pkttype=PacketType.PACKET_HOST,
                mac=MacAddress("02:00:00:00:00:91"),
            ),
            SockAddrLl(),
        ]:
            with self.subTest(address=address):
                self.assertEqual(
                    decode_value(encode_value(address)),
                    address,
                    msg=f"SockAddrLl {address!r} must round-trip field-by-field.",
                )

    def test__ipc__values__link_stats_snapshot(self) -> None:
        """
        Ensure a LinkStats snapshot round-trips all eight counter
        fields.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        stats = LinkStats(
            rx_packets=10,
            rx_bytes=640,
            rx_errors=0,
            rx_dropped=1,
            tx_packets=5,
            tx_bytes=320,
            tx_errors=0,
            tx_dropped=0,
        )

        self.assertEqual(
            decode_value(encode_value(stats)),
            stats,
            msg="LinkStats must round-trip all eight counter fields.",
        )

    def test__ipc__values__encoded_form_is_json_serialisable(self) -> None:
        """
        Ensure the encoded form contains only JSON-native structures, so
        the control-plane body can be carried as a JSON document end to
        end (encode -> json.dumps -> json.loads -> decode is identity).

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        value: Any = (
            Route(
                destination=Ip6Network("2001:db8::/64"),
                gateway=Ip6Address("fe80::1"),
                metric=1,
                scope=RouteScope.UNIVERSE,
                protocol=RouteProtocol.RA,
                oif=2,
            ),
            [MacAddress("02:00:00:00:00:07"), None],
        )

        self.assertEqual(
            decode_value(json.loads(json.dumps(encode_value(value)))),
            value,
            msg="Encoded values must survive a JSON serialise/parse cycle.",
        )

    def test__ipc__values__interface_activity_snapshot(self) -> None:
        """
        Ensure an InterfaceActivity round-trips field-by-field, including
        the tuple-of-Ip6Address tentative-address field in both its
        populated and empty forms.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        for activity in [
            InterfaceActivity(
                ifindex=2,
                name="tap9",
                dhcp4_state="SELECTING",
                tentative_ip6=(Ip6Address("2603:808c::5"), Ip6Address("fe80::1")),
            ),
            InterfaceActivity(ifindex=3, name="tun3", dhcp4_state=None, tentative_ip6=()),
        ]:
            with self.subTest(activity=activity):
                self.assertEqual(
                    decode_value(encode_value(activity)),
                    activity,
                    msg=f"InterfaceActivity {activity!r} must round-trip.",
                )


class TestIpcValuesErrors(TestCase):
    """
    The IPC value-codec error-path tests.
    """

    def test__ipc__values__encode_unsupported_type_raises(self) -> None:
        """
        Ensure encoding a value of an unregistered type raises
        'IpcValueError' rather than silently producing an unusable
        encoding.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(IpcValueError) as error:
            encode_value(object())

        self.assertEqual(
            str(error.exception),
            "[IPC] Cannot encode value of unsupported type 'object'.",
            msg="Encoding an unsupported type must raise IpcValueError.",
        )

    def test__ipc__values__decode_untagged_dict_raises(self) -> None:
        """
        Ensure decoding a JSON object without the type-tag key raises
        'IpcValueError', surfacing a malformed body rather than a bare
        KeyError.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(IpcValueError) as error:
            decode_value({"not_a_tag": 1})

        self.assertEqual(
            str(error.exception),
            "[IPC] Cannot decode object without a type tag.",
            msg="Decoding an untagged object must raise IpcValueError.",
        )

    def test__ipc__values__decode_unknown_tag_raises(self) -> None:
        """
        Ensure decoding a value whose type tag is not registered raises
        'IpcValueError'.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(IpcValueError) as error:
            decode_value({"__t__": "NoSuchType", "v": "x"})

        self.assertEqual(
            str(error.exception),
            "[IPC] Cannot decode value with unknown type tag 'NoSuchType'.",
            msg="Decoding an unknown type tag must raise IpcValueError.",
        )
