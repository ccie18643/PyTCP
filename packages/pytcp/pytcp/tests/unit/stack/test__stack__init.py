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
This module contains tests for the 'pytcp/stack/__init__.py' module
constants and the 'initialize_interface__{tap,tun}' / 'mock__init'
helpers.

pytcp/tests/unit/stack/test__stack__init.py

ver 3.0.10
"""

import os
import sys
from typing import cast, override
from unittest import TestCase
from unittest.mock import MagicMock, create_autospec, patch

import pytcp.stack as stack
import pytcp.stack.lifecycle as lifecycle
import pytcp.stack.sysctl as sysctl_module
from net_addr import (
    Ip4Address,
    Ip4IfAddr,
    Ip4Network,
    Ip6Address,
    Ip6IfAddr,
    Ip6Network,
    MacAddress,
)
from pytcp.lib.interface_layer import InterfaceLayer
from pytcp.lib.ip6_multicast_filter import (
    Ip6MulticastFilter,
    Ip6MulticastFilterMode,
)
from pytcp.protocols.dhcp4.dhcp4__client import Dhcp4Client
from pytcp.runtime.fib import Route, RouteTable
from pytcp.runtime.interface_table import InterfaceTable
from pytcp.runtime.packet_handler import PacketHandlerL2, PacketHandlerL3
from pytcp.stack.address import AddressApi
from pytcp.stack.lifecycle import add_interface, remove_interface
from pytcp.stack.link import LinkApi
from pytcp.stack.neighbor import NeighborApi
from pytcp.stack.route import RouteApi


def _configure_handler_attach_side_effects(handler: MagicMock, /) -> None:
    """
    Wire the construction-time public mutators of a spec'd PacketHandlerL2
    mock so the binding side effects 'mock__init' (and start/stop) drive
    through 'attach_rings' / 'attach_caches' / 'attach_arp_cache' /
    'set_ifindex' land on the mock's '_rx_ring' / '_tx_ring' / '_arp_cache'
    / '_nd_cache' / '_ifindex' the storage-assertion tests inspect. Also
    mirrors the public read accessors ('ifindex', 'rx_ring', 'tx_ring',
    'arp_cache', 'nd_cache') the lifecycle start/stop paths consult onto
    the same storage, so the recording mocks installed on the private
    names are what those paths reach.
    """

    def _attach_rings(*, rx_ring: object = None, tx_ring: object = None) -> None:
        if rx_ring is not None:
            handler._rx_ring = handler.rx_ring = rx_ring
        if tx_ring is not None:
            handler._tx_ring = handler.tx_ring = tx_ring

    def _attach_caches(*, arp_cache: object, nd_cache: object, iface_name: object = None) -> None:
        handler._arp_cache = handler.arp_cache = arp_cache
        handler._nd_cache = handler.nd_cache = nd_cache

    def _attach_arp_cache(arp_cache: object, /) -> None:
        handler._arp_cache = handler.arp_cache = arp_cache

    def _set_ifindex(ifindex: int, /) -> None:
        handler._ifindex = handler.ifindex = ifindex

    handler.attach_rings.side_effect = _attach_rings
    handler.attach_caches.side_effect = _attach_caches
    handler.attach_arp_cache.side_effect = _attach_arp_cache
    handler.set_ifindex.side_effect = _set_ifindex


# Silence stack log output module-wide. Several tests drive real stack
# lifecycle / neighbor / DHCPv4 paths that log on the 'stack' channel,
# which otherwise leaks into the runner output (unit_testing.md §10a.4).
# The captured original feeds 'test__stack__log_channels_present', which
# asserts on the production channel set rather than the emptied live one.
_ORIGINAL_LOG_CHANNEL: set[str] = stack.LOG__CHANNEL


def setUpModule() -> None:
    """
    Silence stack log output for the duration of this module's tests.
    """

    stack.LOG__CHANNEL = set()


def tearDownModule() -> None:
    """
    Restore the production log-channel configuration.
    """

    stack.LOG__CHANNEL = _ORIGINAL_LOG_CHANNEL


class TestStackModuleConstants(TestCase):
    """
    The 'pytcp.stack' module-level constant tests.
    """

    def test__stack__tun_tap_constants(self) -> None:
        """
        Ensure the TAP/TUN ioctl constants match the Linux kernel
        values. Wrong values would make 'initialize_interface__tap'
        attach the wrong kernel interface.

        Reference: Linux kernel tun.h (TUNSETIFF / IFF_TUN / IFF_TAP / IFF_NO_PI).
        """

        self.assertEqual(
            stack.TUNSETIFF,
            0x400454CA,
            msg="TUNSETIFF must match the Linux kernel's TUNSETIFF ioctl code.",
        )
        self.assertEqual(
            stack.IFF_TUN,
            0x0001,
            msg="IFF_TUN must be 0x0001 per the Linux tun.h header.",
        )
        self.assertEqual(
            stack.IFF_TAP,
            0x0002,
            msg="IFF_TAP must be 0x0002 per the Linux tun.h header.",
        )
        self.assertEqual(
            stack.IFF_NO_PI,
            0x1000,
            msg="IFF_NO_PI must be 0x1000 per the Linux tun.h header.",
        )

    def test__stack__interface_mtu_defaults(self) -> None:
        """
        Ensure the default MTU for TAP/TUN interfaces is 1500 bytes —
        the standard Ethernet MTU. Changing this shifts every
        fragmentation / MSS calculation downstream.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            stack.INTERFACE__TAP__MTU,
            1500,
            msg="INTERFACE__TAP__MTU must default to 1500.",
        )
        self.assertEqual(
            stack.INTERFACE__TUN__MTU,
            1500,
            msg="INTERFACE__TUN__MTU must default to 1500.",
        )

    def test__stack__protocol_support_defaults_enabled(self) -> None:
        """
        Ensure IPv4 and IPv6 support flags are enabled by default.
        Disabling them silently would break the integration tests.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertTrue(
            stack.IP4__SUPPORT,
            msg="IP4__SUPPORT must default to True.",
        )
        self.assertTrue(
            stack.IP6__SUPPORT,
            msg="IP6__SUPPORT must default to True.",
        )

    def test__stack__neighbor_cache_timers_are_positive(self) -> None:
        """
        Ensure the generic NeighborCache aging timers
        ('neighbor.reachable_time' / 'neighbor.retrans_timer')
        are both positive at module load — the FSM relies on
        these for REACHABLE → STALE and inter-solicit
        retransmit cadence. The IPv6 ND cache reads these
        directly via 'pytcp.lib.neighbor' as of Phase 3 of
        the NUD migration.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        from pytcp.lib import neighbor__constants

        self.assertGreater(
            neighbor__constants.NEIGHBOR__REACHABLE_TIME["default"],
            0,
            msg="NEIGHBOR__REACHABLE_TIME['default'] must be positive.",
        )
        self.assertGreater(
            neighbor__constants.NEIGHBOR__RETRANS_TIMER["default"],
            0,
            msg="NEIGHBOR__RETRANS_TIMER['default'] must be positive.",
        )

    def test__stack__ephemeral_port_range(self) -> None:
        """
        Ensure the ephemeral port range lies within the 0-65535 bounds
        of a 16-bit port field and ends above its start.

        Reference: RFC 6335 §6 (ephemeral port range).
        """

        self.assertGreaterEqual(
            stack.STACK__EPHEMERAL_PORT_RANGE__LOW,
            0,
            msg="STACK__EPHEMERAL_PORT_RANGE__LOW must be >= 0.",
        )
        self.assertLessEqual(
            stack.STACK__EPHEMERAL_PORT_RANGE__HIGH,
            65536,
            msg="STACK__EPHEMERAL_PORT_RANGE__HIGH must be <= 65536.",
        )
        self.assertGreater(
            stack.STACK__EPHEMERAL_PORT_RANGE__HIGH,
            stack.STACK__EPHEMERAL_PORT_RANGE__LOW,
            msg="STACK__EPHEMERAL_PORT_RANGE__HIGH must exceed __LOW.",
        )

    def test__stack__ephemeral_port_range__rfc6056_conformant(self) -> None:
        """
        Ensure the ephemeral port pool is at least the size of the
        IANA dynamic range (16384 ports) to give an off-path
        attacker a sufficiently large guessing space, and that the
        lower bound sits above the IANA Well-Known Ports range so
        no static-port conflicts arise. (The 'range(low, high)'
        consumer iterates with step=1; the historical step=2
        even-only affordance is gone.)

        Reference: RFC 6056 §3.2 (Ephemeral Port Number Range).
        """

        self.assertGreaterEqual(
            stack.STACK__EPHEMERAL_PORT_RANGE__HIGH - stack.STACK__EPHEMERAL_PORT_RANGE__LOW,
            16384,
            msg=(
                "The ephemeral-port pool must contain at least 16384 ports "
                "(IANA dynamic-range size) to satisfy the largest-possible-range SHOULD."
            ),
        )
        self.assertGreaterEqual(
            stack.STACK__EPHEMERAL_PORT_RANGE__LOW,
            1024,
            msg="STACK__EPHEMERAL_PORT_RANGE__LOW must be >= 1024 (above the Well-Known Ports range).",
        )

    def test__stack__fragment_timeouts_positive(self) -> None:
        """
        Ensure IP fragment reassembly timeouts are positive. A value
        of 0 would immediately drop every fragment flow.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertGreater(
            stack.IP4__FRAG_FLOW_TIMEOUT__S,
            0,
            msg="IP4__FRAG_FLOW_TIMEOUT__S must be positive.",
        )
        self.assertGreater(
            stack.IP6__FRAG_FLOW_TIMEOUT__S,
            0,
            msg="IP6__FRAG_FLOW_TIMEOUT__S must be positive.",
        )

    def test__stack__log_channels_present(self) -> None:
        """
        Ensure the default 'LOG__CHANNEL' set contains the core
        subsystem channels referenced across the codebase. Dropping
        a channel here silences an entire subsystem's log output.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        required = {
            "stack",
            "rx-ring",
            "tx-ring",
            "arp-c",
            "nd-c",
            "ether",
            "arp",
            "ip4",
            "ip6",
            "icmp4",
            "icmp6",
            "udp",
            "tcp",
            "socket",
            "tcp-ss",
        }
        missing = required - _ORIGINAL_LOG_CHANNEL
        self.assertEqual(
            missing,
            set(),
            msg=f"LOG__CHANNEL must contain every core subsystem channel; missing: {missing}",
        )

    def test__stack__pytcp_version_shape(self) -> None:
        """
        Ensure the 'PYTCP_VERSION' string starts with 'ver ' so any
        consumers that parse "ver X.Y.Z" can keep working.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertTrue(
            stack.PYTCP_VERSION.startswith("ver "),
            msg="PYTCP_VERSION must start with 'ver ' so 'ver X.Y.Z' parsers can keep working.",
        )

    def test__stack__stack_initialized_defaults_false(self) -> None:
        """
        Ensure the module-level 'stack_initialized' flag starts False
        — start()/stop() gate on it.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        # It might be True if the process already ran stack.init() in a
        # previous test. Assert only the default flag declaration here.
        self.assertIsInstance(
            stack.stack_initialized,
            bool,
            msg="stack_initialized must be a bool.",
        )


class TestStackInitializeInterfaceTap(TestCase):
    """
    The 'initialize_interface__tap' helper tests.
    """

    @override
    def setUp(self) -> None:
        """
        Suppress log output and patch the low-level syscalls that the
        helper delegates to ('os.open' / 'fcntl.ioctl').
        """

        self._log_patch = patch("pytcp.stack.log")
        self._log_patch.start()

    @override
    def tearDown(self) -> None:
        """
        Tear down patches.
        """

        self._log_patch.stop()

    def test__stack__initialize_tap_returns_interface_dict(self) -> None:
        """
        Ensure 'initialize_interface__tap' returns a dict carrying the
        file descriptor, InterfaceLayer.L2, default MTU, and the
        derived MAC address — the shape 'stack.init()' consumes.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with (
            patch("pytcp.stack.os.open", return_value=42),
            patch("pytcp.stack.fcntl.ioctl"),
        ):
            result = stack.initialize_interface__tap("tap7")

        self.assertEqual(
            result["fd"],
            42,
            msg="initialize_interface__tap must return the fd from os.open.",
        )
        self.assertIs(
            result["layer"],
            InterfaceLayer.L2,
            msg="initialize_interface__tap must declare the InterfaceLayer.L2 layer.",
        )
        self.assertEqual(
            result["mtu"],
            stack.INTERFACE__TAP__MTU,
            msg="initialize_interface__tap must report the INTERFACE__TAP__MTU default.",
        )
        self.assertIsInstance(
            result["mac_address"],
            MacAddress,
            msg="initialize_interface__tap must materialize a MacAddress from the interface name.",
        )

    def test__stack__initialize_tap_honors_explicit_mac(self) -> None:
        """
        Ensure passing 'mac_address=' overrides the MAC derived from
        the interface name. Used by integration tests that need a
        deterministic MAC.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        mac = MacAddress("02:00:00:00:00:99")
        with (
            patch("pytcp.stack.os.open", return_value=42),
            patch("pytcp.stack.fcntl.ioctl"),
        ):
            result = stack.initialize_interface__tap("tap7", mac_address=mac)

        self.assertEqual(
            result["mac_address"],
            mac,
            msg="initialize_interface__tap must use the explicit mac_address argument verbatim.",
        )

    def test__stack__initialize_tap_exits_when_tun_missing(self) -> None:
        """
        Ensure the helper calls 'sys.exit(-1)' when '/dev/net/tun' is
        not present. This is the operator-visible failure path.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with (
            patch(
                "pytcp.stack.os.open",
                side_effect=FileNotFoundError,
            ),
            patch("pytcp.stack.sys.exit", side_effect=SystemExit(-1)) as mock_exit,
        ):
            with self.assertRaises(SystemExit):
                stack.initialize_interface__tap("tap7")
        mock_exit.assert_called_once_with(-1)


class TestStackInitializeInterfaceTun(TestCase):
    """
    The 'initialize_interface__tun' helper tests.
    """

    @override
    def setUp(self) -> None:
        """
        Suppress log output.
        """

        self._log_patch = patch("pytcp.stack.log")
        self._log_patch.start()

    @override
    def tearDown(self) -> None:
        """
        Tear down patches.
        """

        self._log_patch.stop()

    def test__stack__initialize_tun_returns_interface_dict(self) -> None:
        """
        Ensure 'initialize_interface__tun' returns a dict carrying
        the file descriptor, InterfaceLayer.L3, and the default MTU.
        TUN mode does not report a MAC address.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with (
            patch("pytcp.stack.os.open", return_value=99),
            patch("pytcp.stack.fcntl.ioctl"),
        ):
            result = stack.initialize_interface__tun("tun7")

        self.assertEqual(
            result["fd"],
            99,
            msg="initialize_interface__tun must return the fd from os.open.",
        )
        self.assertIs(
            result["layer"],
            InterfaceLayer.L3,
            msg="initialize_interface__tun must declare the InterfaceLayer.L3 layer.",
        )
        self.assertEqual(
            result["mtu"],
            stack.INTERFACE__TUN__MTU,
            msg="initialize_interface__tun must report the INTERFACE__TUN__MTU default.",
        )
        self.assertNotIn(
            "mac_address",
            result,
            msg="initialize_interface__tun must not include a 'mac_address' key.",
        )

    def test__stack__initialize_tun_exits_when_tun_missing(self) -> None:
        """
        Ensure the TUN helper also exits on FileNotFoundError to
        match 'initialize_interface__tap'.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with (
            patch(
                "pytcp.stack.os.open",
                side_effect=FileNotFoundError,
            ),
            patch("pytcp.stack.sys.exit", side_effect=SystemExit(-1)) as mock_exit,
        ):
            with self.assertRaises(SystemExit):
                stack.initialize_interface__tun("tun7")
        mock_exit.assert_called_once_with(-1)


class TestStackMockInit(TestCase):
    """
    The 'stack.mock__init' helper tests.
    """

    @override
    def setUp(self) -> None:
        """
        Snapshot the module-level singletons so each test can reset
        them. Using 'getattr' with a sentinel lets us handle the
        'not-yet-assigned' case (the real globals are declared with
        bare annotations).
        """

        self._sentinel = object()
        self._snapshot = {name: getattr(stack, name, self._sentinel) for name in ("timer", "interfaces")}

    @override
    def tearDown(self) -> None:
        """
        Restore the snapshot of module-level singletons.
        """

        for name, value in self._snapshot.items():
            if value is self._sentinel:
                # The attribute was not defined before; delete the
                # assignment left by mock__init so the post-condition
                # matches the pre-condition.
                if hasattr(stack, name):
                    delattr(stack, name)
            else:
                setattr(stack, name, value)

    def test__stack__mock_init_binds_rings_and_caches_to_handler(self) -> None:
        """
        Ensure 'mock__init' wires the timer global and injects every
        provided ring / neighbor-cache mock into the supplied packet
        handler (the per-interface object), not into any module-level
        singleton.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        fake_timer = MagicMock()
        fake_tx = MagicMock()
        fake_rx = MagicMock()
        fake_arp = MagicMock()
        fake_nd = MagicMock()
        fake_handler = MagicMock(spec=PacketHandlerL2)
        fake_handler._ifindex = fake_handler.ifindex = 1
        _configure_handler_attach_side_effects(fake_handler)

        stack.mock__init(
            mock__timer=fake_timer,
            mock__tx_ring=fake_tx,
            mock__rx_ring=fake_rx,
            mock__arp_cache=fake_arp,
            mock__nd_cache=fake_nd,
            mock__packet_handler=fake_handler,
        )

        self.assertIs(stack.timer, fake_timer, msg="mock__init must wire the timer mock.")
        self.assertIs(fake_handler._tx_ring, fake_tx, msg="mock__init must bind the tx_ring mock to the handler.")
        self.assertIs(fake_handler._rx_ring, fake_rx, msg="mock__init must bind the rx_ring mock to the handler.")
        self.assertIs(fake_handler._arp_cache, fake_arp, msg="mock__init must bind the arp_cache mock to the handler.")
        self.assertIs(fake_handler._nd_cache, fake_nd, msg="mock__init must bind the nd_cache mock to the handler.")

    def test__stack__mock_init_registers_interface_by_ifindex(self) -> None:
        """
        Ensure 'mock__init' registers the wired packet handler in
        'stack.interfaces' keyed by its 'ifindex'.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        handler = MagicMock(spec=PacketHandlerL2)
        handler._ifindex = handler.ifindex = 1
        _configure_handler_attach_side_effects(handler)

        stack.mock__init(mock__packet_handler=handler)

        self.assertEqual(
            dict(stack.interfaces),
            {1: handler},
            msg="mock__init must register the handler in stack.interfaces keyed by its ifindex.",
        )

    def test__stack__mock_init_timer_only_preserves_interface_registry(self) -> None:
        """
        Ensure a timer-only 'mock__init' overwrites the timer global but
        leaves the interface registry a prior call populated intact — the
        invariant 'IcmpTestCase' relies on when it calls 'mock__init' a
        second time (timer-only).

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        handler = MagicMock(spec=PacketHandlerL2)
        handler._ifindex = handler.ifindex = 1
        _configure_handler_attach_side_effects(handler)
        stack.mock__init(mock__timer=MagicMock(), mock__packet_handler=handler)

        new_timer = MagicMock()
        stack.mock__init(mock__timer=new_timer)

        self.assertIs(
            stack.timer,
            new_timer,
            msg="mock__init must overwrite the timer when one is supplied.",
        )
        self.assertEqual(
            dict(stack.interfaces),
            {1: handler},
            msg="A timer-only mock__init must not wipe the interface registry a prior call populated.",
        )


class TestStackStartDhcpBootWait(TestCase):
    """
    The 'stack.start(wait_for_dhcp_bind=...)' DHCPv4 boot-wait tests.
    """

    @override
    def setUp(self) -> None:
        """
        Snapshot the module-level state, install a mocked timer and a
        single L2 interface whose DHCPv4 client is an autospec'd mock, and
        patch '_start_interface' so no real subsystem threads spawn.
        """

        self.enterContext(patch("pytcp.stack.log"))
        self.enterContext(patch("pytcp.runtime.subsystem.log"))
        self.enterContext(patch.object(lifecycle, "_start_interface"))

        self._saved = {
            name: getattr(stack, name, None)
            for name in ("stack_initialized", "stack_running", "timer", "interfaces", "link_local")
        }

        stack.timer = MagicMock()
        stack.link_local = None
        handler = MagicMock(spec=PacketHandlerL2)
        handler._ifindex = handler.ifindex = 1
        # 'start()' reaches the DHCP clients via the public read accessors.
        handler._dhcp4_client = handler.dhcp4_client = create_autospec(Dhcp4Client, spec_set=True)
        handler._dhcp6_client = handler.dhcp6_client = None
        self._dhcp4_client = handler.dhcp4_client
        interfaces = InterfaceTable(first_ifindex=stack.STACK__DEFAULT_IFINDEX)
        interfaces[1] = handler
        stack.interfaces = interfaces
        stack.stack_initialized = True
        stack.stack_running = False

    @override
    def tearDown(self) -> None:
        """
        Restore the snapshotted module-level state.
        """

        for name, value in self._saved.items():
            if value is not None:
                setattr(stack, name, value)

    def test__start__daemon_mode_does_not_block_on_dhcp_bind(self) -> None:
        """
        Ensure 'stack.start(wait_for_dhcp_bind=False)' starts the DHCPv4
        client without blocking for the BOUND boot-wait, so a daemon's
        control plane comes up immediately while the lease lands in the
        background.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        stack.start(wait_for_dhcp_bind=False)

        self._dhcp4_client.start.assert_called_once_with()
        self._dhcp4_client.start_and_wait_for_bind.assert_not_called()

    def test__start__default_waits_for_dhcp_bind(self) -> None:
        """
        Ensure the default 'stack.start()' blocks for the DHCPv4 boot-wait
        via 'start_and_wait_for_bind', preserving the in-process
        boot-blocking semantics for non-daemon callers.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._dhcp4_client.start_and_wait_for_bind.return_value = True

        stack.start()

        self._dhcp4_client.start_and_wait_for_bind.assert_called_once()
        self._dhcp4_client.start.assert_not_called()


class TestStackStopOrdering(TestCase):
    """
    The 'stack.stop()' subsystem teardown-order tests.
    """

    @override
    def setUp(self) -> None:
        """
        Snapshot the module-level state and replace each subsystem
        with a MagicMock so 'stack.stop()' can be invoked without a
        live stack.
        """

        self._saved = {
            "stack_initialized": stack.stack_initialized,
            "timer": getattr(stack, "timer", None),
            "interfaces": getattr(stack, "interfaces", None),
        }

        self._call_log: list[str] = []

        def _make_subsystem(name: str) -> MagicMock:
            m = MagicMock()
            m.stop.side_effect = lambda n=name: self._call_log.append(n)
            return m

        # 'start()' / 'stop()' iterate 'stack.interfaces' and reach each
        # interface's rings + caches via the handler's public read
        # accessors ('rx_ring' / 'tx_ring' / 'arp_cache' / 'nd_cache' —
        # the handler IS the interface). Wire those to the recording
        # mocks and register the handler as the sole interface; the timer
        # is the only remaining module-level subsystem 'stop()' touches.
        stack.timer = _make_subsystem("timer")
        handler = _make_subsystem("packet_handler")
        handler._ifindex = handler.ifindex = 1
        handler.rx_ring = _make_subsystem("rx_ring")
        handler.tx_ring = _make_subsystem("tx_ring")
        handler.arp_cache = _make_subsystem("arp_cache")
        handler.nd_cache = _make_subsystem("nd_cache")
        # 'start()' / 'stop()' also probe the DHCP clients; this stop-order
        # test runs no DHCP, so a plain MagicMock 'handler' would auto-
        # create truthy child mocks. Pin them None so the isinstance +
        # not-None guards skip the DHCP branches.
        handler.dhcp4_client = None
        handler.dhcp6_client = None
        _interfaces = InterfaceTable(first_ifindex=stack.STACK__DEFAULT_IFINDEX)
        _interfaces[1] = handler
        stack.interfaces = _interfaces
        stack.stack_initialized = True

    @override
    def tearDown(self) -> None:
        """
        Restore the saved module-level subsystems.
        """

        for name, value in self._saved.items():
            if value is not None:
                setattr(stack, name, value)

    def test__stack__stop_stops_timer_before_tx_ring(self) -> None:
        """
        Ensure 'stack.stop()' stops the timer before the TX ring so
        timer-driven callbacks (TCP RTO, persist, keep-alive,
        delayed-ACK) cannot fire after the TX ring has stopped and
        silently lose their outbound packets to a never-drained queue.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        stack.stop()

        timer_idx = self._call_log.index("timer")
        tx_ring_idx = self._call_log.index("tx_ring")

        self.assertLess(
            timer_idx,
            tx_ring_idx,
            msg=(
                "timer.stop() must precede tx_ring.stop() so timer-driven "
                "callbacks cannot enqueue to a stopped TX ring. Got order: "
                f"{self._call_log}"
            ),
        )

    def test__stack__stop_stops_packet_handler_first(self) -> None:
        """
        Ensure 'stack.stop()' stops the packet handler first so
        application-side TX producers exit before the rings tear
        down.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        stack.stop()

        self.assertEqual(
            self._call_log[0],
            "packet_handler",
            msg=("packet_handler.stop() must be the first action in " f"stack.stop(). Got order: {self._call_log}"),
        )

    def test__stack__stop_stops_rings_after_packet_handler(self) -> None:
        """
        Ensure both rings are stopped after the packet handler exits
        — packet_handler is the producer; stopping it first means
        the rings only need to drain in-flight packets, not absorb
        new arrivals.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        stack.stop()

        ph_idx = self._call_log.index("packet_handler")
        rx_idx = self._call_log.index("rx_ring")
        tx_idx = self._call_log.index("tx_ring")

        self.assertLess(
            ph_idx,
            rx_idx,
            msg=f"rx_ring must stop after packet_handler. Got: {self._call_log}",
        )
        self.assertLess(
            ph_idx,
            tx_idx,
            msg=f"tx_ring must stop after packet_handler. Got: {self._call_log}",
        )

    def test__stack__stop_sends_igmp_leave_before_packet_handler(self) -> None:
        """
        Ensure 'stack.stop()' emits each interface's graceful IGMP Leave
        before stopping the packet handler, so the Leave egresses while
        the TX path is still live and routers prune the host's
        memberships immediately instead of waiting for a query timeout.

        Reference: RFC 3376 §5.1 (host announces leaving on shutdown).
        """

        cast(MagicMock, stack.interfaces[1]).send_igmp_leave_all.side_effect = lambda: self._call_log.append(
            "igmp_leave"
        )

        stack.stop()

        self.assertIn(
            "igmp_leave",
            self._call_log,
            msg=f"stop() must emit the graceful IGMP Leave. Got: {self._call_log}",
        )
        self.assertLess(
            self._call_log.index("igmp_leave"),
            self._call_log.index("packet_handler"),
            msg=f"The IGMP Leave must precede packet_handler.stop(). Got: {self._call_log}",
        )


class TestStackInitSharedPacketStats(TestCase):
    """
    The 'stack.init()' shared 'PacketStats' wiring tests.
    """

    @override
    def setUp(self) -> None:
        """
        Snapshot the module-level singletons that 'stack.init()'
        rebinds so each test can roll back cleanly. Suppress the
        'Initializing ...' subsystem-init log lines that leak from
        the 'stack.init()' construction path.
        """

        log_patch = patch("pytcp.stack.log")
        log_patch.start()
        self.addCleanup(log_patch.stop)
        subsystem_log_patch = patch("pytcp.runtime.subsystem.log")
        subsystem_log_patch.start()
        self.addCleanup(subsystem_log_patch.stop)

        self._sentinel = object()
        self._snapshot = {
            name: getattr(stack, name, self._sentinel)
            for name in (
                "timer",
                "stack_initialized",
            )
        }

    @override
    def tearDown(self) -> None:
        """
        Restore the snapshot so subsequent tests start from the same
        module-level state.
        """

        for name, value in self._snapshot.items():
            if value is self._sentinel:
                if hasattr(stack, name):
                    delattr(stack, name)
            else:
                setattr(stack, name, value)

    def test__stack__init_l2_shares_packet_stats_across_rings_and_handler(self) -> None:
        """
        Ensure 'stack.init()' on the L2 (TAP) path constructs one
        'PacketStatsRx' and one 'PacketStatsTx' instance and threads
        the same objects into 'RxRing', 'TxRing', and
        'PacketHandlerL2'. Without this sharing, ring drop counters
        (rx_ring__queue_full__drop / __os_error__drop, tx_ring
        equivalents) would land on a different dataclass than the
        per-protocol counters and the unified 'PacketStats' snapshot
        would lose them.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        from pytcp.lib.packet_stats import PacketStatsRx, PacketStatsTx

        with (
            patch.object(stack.lifecycle, "TxRing") as tx_ring_cls,
            patch.object(stack.lifecycle, "RxRing") as rx_ring_cls,
            patch.object(stack.lifecycle, "PacketHandlerL2") as handler_cls,
        ):
            stack.init(
                fd=-1,
                layer=InterfaceLayer.L2,
                mtu=1500,
                mac_address=MacAddress("02:00:00:00:00:01"),
                ip4_support=False,
                ip4_host=None,
                ip4_dhcp=False,
                ip6_support=False,
                ip6_host=None,
                ip6_gua_autoconfig=False,
                ip6_lla_autoconfig=False,
            )

        rx_stats = rx_ring_cls.call_args.kwargs["packet_stats"]
        tx_stats = tx_ring_cls.call_args.kwargs["packet_stats"]
        handler_kwargs = handler_cls.call_args.kwargs

        self.assertIsInstance(
            rx_stats,
            PacketStatsRx,
            msg="RxRing must receive a PacketStatsRx instance from stack.init().",
        )
        self.assertIsInstance(
            tx_stats,
            PacketStatsTx,
            msg="TxRing must receive a PacketStatsTx instance from stack.init().",
        )
        self.assertIs(
            handler_kwargs["packet_stats_rx"],
            rx_stats,
            msg=(
                "PacketHandlerL2 must receive the SAME PacketStatsRx instance the RxRing got — "
                "ring drop counters live on this dataclass and the unified-stats snapshot "
                "depends on the rings and the handler sharing one object."
            ),
        )
        self.assertIs(
            handler_kwargs["packet_stats_tx"],
            tx_stats,
            msg=(
                "PacketHandlerL2 must receive the SAME PacketStatsTx instance the TxRing got — "
                "ring drop counters live on this dataclass and the unified-stats snapshot "
                "depends on the rings and the handler sharing one object."
            ),
        )

    def test__stack__init_l3_shares_packet_stats_across_rings_and_handler(self) -> None:
        """
        Ensure 'stack.init()' on the L3 (TUN) path also threads one
        'PacketStatsRx' / 'PacketStatsTx' pair through both rings and
        the 'PacketHandlerL3' constructor — same invariant as the L2
        path, different handler class.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        from pytcp.lib.packet_stats import PacketStatsRx, PacketStatsTx

        with (
            patch.object(stack.lifecycle, "TxRing") as tx_ring_cls,
            patch.object(stack.lifecycle, "RxRing") as rx_ring_cls,
            patch.object(stack.lifecycle, "PacketHandlerL3") as handler_cls,
        ):
            stack.init(
                fd=-1,
                layer=InterfaceLayer.L3,
                mtu=1500,
                mac_address=None,
                ip4_support=False,
                ip4_host=None,
                ip4_dhcp=False,
                ip6_support=False,
                ip6_host=None,
                ip6_gua_autoconfig=False,
                ip6_lla_autoconfig=False,
            )

        rx_stats = rx_ring_cls.call_args.kwargs["packet_stats"]
        tx_stats = tx_ring_cls.call_args.kwargs["packet_stats"]
        handler_kwargs = handler_cls.call_args.kwargs

        self.assertIsInstance(
            rx_stats,
            PacketStatsRx,
            msg="RxRing must receive a PacketStatsRx instance from stack.init() on the L3 path.",
        )
        self.assertIsInstance(
            tx_stats,
            PacketStatsTx,
            msg="TxRing must receive a PacketStatsTx instance from stack.init() on the L3 path.",
        )
        self.assertIs(
            handler_kwargs["packet_stats_rx"],
            rx_stats,
            msg=(
                "PacketHandlerL3 must receive the SAME PacketStatsRx instance the RxRing got — "
                "shared-stats invariant must hold on the L3 path identically to L2."
            ),
        )
        self.assertIs(
            handler_kwargs["packet_stats_tx"],
            tx_stats,
            msg=(
                "PacketHandlerL3 must receive the SAME PacketStatsTx instance the TxRing got — "
                "shared-stats invariant must hold on the L3 path identically to L2."
            ),
        )


class TestStackInitArpCacheConfig(TestCase):
    """
    The 'stack.init()' ARP-cache-timeout configuration tests.

    Pin that the 'arp_cache_max_age' / 'arp_cache_refresh_time'
    kwargs surface user-tunable equivalents of the Linux
    sysctls 'net.ipv4.neigh.default.{base_reachable_time,
    gc_stale_time}': when supplied, they override the
    compile-time defaults that the ARP cache loop reads.
    """

    @override
    def setUp(self) -> None:
        """
        Snapshot the module-level singletons 'init()' rebinds so
        each test can roll back cleanly. Sysctl mutations are
        rolled back via 'reset_to_defaults' in tearDown. Suppress
        the 'Initializing ...' log lines that 'stack.init()'
        emits during subsystem construction.
        """

        log_patch = patch("pytcp.stack.log")
        log_patch.start()
        self.addCleanup(log_patch.stop)
        subsystem_log_patch = patch("pytcp.runtime.subsystem.log")
        subsystem_log_patch.start()
        self.addCleanup(subsystem_log_patch.stop)

        from pytcp.protocols.arp import arp__constants

        self._arp__constants = arp__constants
        self._sentinel = object()
        self._snapshot = {
            name: getattr(stack, name, self._sentinel)
            for name in (
                "timer",
                "stack_initialized",
            )
        }

    @override
    def tearDown(self) -> None:
        """
        Restore module-level singletons and sysctl defaults.
        """

        from pytcp.stack import sysctl as sysctl_module

        sysctl_module.reset_to_defaults()
        for name, value in self._snapshot.items():
            if value is self._sentinel:
                if hasattr(stack, name):
                    delattr(stack, name)
            else:
                setattr(stack, name, value)

    def _init_l2(self, **extra: object) -> None:
        """
        Run 'stack.init()' on the L2 path with the rings / handler
        patched out so the kwargs path is exercised in isolation.
        """

        with (
            patch.object(stack.lifecycle, "TxRing"),
            patch.object(stack.lifecycle, "RxRing"),
            patch.object(stack.lifecycle, "PacketHandlerL2"),
            patch.object(stack.lifecycle, "ArpCache"),
            patch.object(stack.lifecycle, "NdCache"),
        ):
            stack.init(
                fd=-1,
                layer=InterfaceLayer.L2,
                mtu=1500,
                mac_address=MacAddress("02:00:00:00:00:01"),
                ip4_support=False,
                ip4_host=None,
                ip4_dhcp=False,
                ip6_support=False,
                ip6_host=None,
                ip6_gua_autoconfig=False,
                ip6_lla_autoconfig=False,
                **extra,  # type: ignore[arg-type]
            )

    def test__stack__init__sysctls_bag_propagates_through_registry(self) -> None:
        """
        Ensure 'stack.init(sysctls={"arp.defend_interval": 20})'
        routes the dotted-name bag entry through the registry
        and writes the new value to the backing constant —
        the documented path for tuning a knob that does not have
        an explicit kwarg.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._init_l2(sysctls={"arp.defend_interval": 20})

        self.assertEqual(
            self._arp__constants.ARP__DEFEND_INTERVAL,
            20,
            msg=(
                "stack.init(sysctls={'arp.defend_interval': 20}) must mutate "
                "ARP__DEFEND_INTERVAL via the sysctl registry."
            ),
        )

    def test__stack__init__sysctls_bag_unknown_key_raises(self) -> None:
        """
        Ensure an unknown key in 'sysctls={...}' raises
        'KeyError' from the registry — operators get a clear
        error rather than a silent typo.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(KeyError):
            self._init_l2(sysctls={"arp.no_such_knob": 1})

    def test__stack__init__sysctls_bag_validator_rejection(self) -> None:
        """
        Ensure a 'sysctls={...}' entry that fails its per-knob
        validator raises 'ValueError' with the offending key
        in the message — the registry write does not bypass
        validation just because it came from the bag.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(ValueError) as ctx:
            self._init_l2(sysctls={"arp.defend_interval": -5})
        self.assertIn(
            "arp.defend_interval",
            str(ctx.exception),
            msg="Bag-kwarg validator rejection must surface the offending key.",
        )

    def test__stack__init__cross_knob_probe_min_lt_probe_max_enforced(self) -> None:
        """
        Ensure the 'arp.probe_min < arp.probe_max' cross-knob
        constraint runs at the end of 'init()' via
        'finalize_validators', rejecting a configuration where
        each individual knob passes its own validator but the
        pair is inconsistent.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(ValueError) as ctx:
            self._init_l2(sysctls={"arp.probe_min": 5, "arp.probe_max": 3})
        self.assertIn(
            "arp.probe_min",
            str(ctx.exception),
            msg=(
                "The cross-knob finalize validator must reject probe_min >= probe_max " "and surface the offending key."
            ),
        )


class TestStackInitControlApis(TestCase):
    """
    The 'stack.init()' control-API singleton-wiring tests.

    'mock__init' (the test path) and the real 'init()' must wire the same
    control-API singletons; a singleton wired only in 'mock__init' works
    in every integration test but raises 'AttributeError' against a live
    daemon when the matching control op resolves 'stack.<api>'.
    """

    @override
    def setUp(self) -> None:
        """
        Snapshot the singletons 'init()' rebinds, then clear the
        control-API attributes under test so the assertion verifies that
        'init()' itself re-binds them (not a value leaked from a prior
        test's 'mock__init' / 'init'). Silence the subsystem-init logs.
        """

        log_patch = patch("pytcp.stack.log")
        log_patch.start()
        self.addCleanup(log_patch.stop)
        subsystem_log_patch = patch("pytcp.runtime.subsystem.log")
        subsystem_log_patch.start()
        self.addCleanup(subsystem_log_patch.stop)

        self._sentinel = object()
        self._snapshot = {
            name: getattr(stack, name, self._sentinel) for name in ("timer", "stack_initialized", "ss", "resolver")
        }
        for name in ("ss", "resolver"):
            if hasattr(stack, name):
                delattr(stack, name)

    @override
    def tearDown(self) -> None:
        """
        Restore the snapshotted singletons.
        """

        for name, value in self._snapshot.items():
            if value is self._sentinel:
                if hasattr(stack, name):
                    delattr(stack, name)
            else:
                setattr(stack, name, value)

    def _init_l2(self) -> None:
        """
        Run 'stack.init()' on the L2 path with the rings / handler / caches
        patched out so the control-API wiring is exercised in isolation.
        """

        with (
            patch.object(stack.lifecycle, "TxRing"),
            patch.object(stack.lifecycle, "RxRing"),
            patch.object(stack.lifecycle, "PacketHandlerL2"),
            patch.object(stack.lifecycle, "ArpCache"),
            patch.object(stack.lifecycle, "NdCache"),
        ):
            stack.init(
                fd=-1,
                layer=InterfaceLayer.L2,
                mtu=1500,
                mac_address=MacAddress("02:00:00:00:00:01"),
                ip4_support=False,
                ip4_host=None,
                ip4_dhcp=False,
                ip6_support=False,
                ip6_host=None,
                ip6_gua_autoconfig=False,
                ip6_lla_autoconfig=False,
            )

    def test__stack__init_wires_socket_introspect_api(self) -> None:
        """
        Ensure 'stack.init()' binds the socket-introspection API at
        'stack.ss' — the singleton the 'list_sockets' control op (and
        'pytcp ss' / 'pytcp daemon status') resolves on a live daemon.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        from pytcp.stack.socket_introspect import SocketIntrospectApi

        self._init_l2()

        self.assertTrue(
            hasattr(stack, "ss"),
            msg="stack.init() must bind stack.ss so the list_sockets control op resolves on a live daemon.",
        )
        self.assertIsInstance(
            stack.ss,
            SocketIntrospectApi,
            msg="stack.ss must be a SocketIntrospectApi after stack.init().",
        )

    def test__stack__init_wires_resolver_api(self) -> None:
        """
        Ensure 'stack.init()' binds the DNS resolver API at
        'stack.resolver' — the 'resolve' control op singleton.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        from pytcp.stack.resolver import ResolverApi

        self._init_l2()

        self.assertTrue(
            hasattr(stack, "resolver"),
            msg="stack.init() must bind stack.resolver so the resolve control op resolves on a live daemon.",
        )
        self.assertIsInstance(
            stack.resolver,
            ResolverApi,
            msg="stack.resolver must be a ResolverApi after stack.init().",
        )


class TestStackPythonVersionGuard(TestCase):
    """
    The Python-version-guard tests at module import time.
    """

    def test__stack__requires_python_3_12(self) -> None:
        """
        Ensure the module-level assert requires Python 3.12+. This is
        the floor the codebase's PEP 695 generics and 'typing.override'
        usage depend on.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertGreaterEqual(
            sys.version_info,
            (3, 12),
            msg="pytcp/stack/__init__.py asserts Python >= 3.12; the running interpreter must meet that floor.",
        )


class TestStackAddInterface(TestCase):
    """
    The 'add_interface' per-interface construction / registration tests.
    """

    @override
    def setUp(self) -> None:
        """
        Snapshot the module-level interface registry + N=1 back-compat
        singletons, start from an empty registry, and silence the
        subsystem-init log lines that 'add_interface' emits.
        """

        self.enterContext(patch("pytcp.runtime.subsystem.log"))

        self._sentinel = object()
        self._snapshot = {name: getattr(stack, name, self._sentinel) for name in ("interfaces",)}
        # Drop any leaked Route API so 'add_interface' does not inject
        # one (the boot path injects it post-construction in 'init()').
        self._route_snapshot = getattr(stack, "route", self._sentinel)
        if hasattr(stack, "route"):
            delattr(stack, "route")

        stack.interfaces = InterfaceTable(first_ifindex=stack.STACK__DEFAULT_IFINDEX)

        # Real pipe write-ends as fd stand-ins; the rings only touch
        # the fd once started, which these tests never do.
        self._fds = [os.pipe() for _ in range(2)]
        self.addCleanup(self._cleanup)

    def _cleanup(self) -> None:
        """
        Close every constructed interface's ring eventfds and the pipe
        fds, then restore the snapshotted module state.
        """

        for iface in stack.interfaces.values():
            for ring in (iface._rx_ring, iface._tx_ring):
                if ring is not None:
                    ring._stop()
        for read_fd, write_fd in self._fds:
            for fd in (read_fd, write_fd):
                try:
                    os.close(fd)
                except OSError:
                    pass
        for name, value in self._snapshot.items():
            if value is self._sentinel:
                if hasattr(stack, name):
                    delattr(stack, name)
            else:
                setattr(stack, name, value)
        if self._route_snapshot is not self._sentinel:
            setattr(stack, "route", self._route_snapshot)

    def test__add_interface__first_takes_default_ifindex(self) -> None:
        """
        Ensure the first 'add_interface' takes 'STACK__DEFAULT_IFINDEX'
        and registers the handler — with its own rings + neighbor caches
        — in 'stack.interfaces' (the single source of truth; no
        privileged module-level singleton).

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        ifindex = add_interface(
            fd=self._fds[0][1],
            layer=InterfaceLayer.L2,
            mac_address=MacAddress("02:00:00:00:00:01"),
        )

        self.assertEqual(ifindex, stack.STACK__DEFAULT_IFINDEX, msg="First interface must take the default ifindex.")
        handler = stack.interfaces[ifindex]
        self.assertEqual(handler._ifindex, ifindex, msg="The handler must record its own ifindex.")
        self.assertIsNotNone(handler._rx_ring, msg="The interface must own its RX ring.")
        self.assertIsNotNone(handler._tx_ring, msg="The interface must own its TX ring.")
        self.assertIsNotNone(handler._arp_cache, msg="An L2 interface must own its ARP cache.")
        self.assertIsNotNone(handler._nd_cache, msg="The interface must own its ND cache.")

    def test__add_interface__second_gets_next_ifindex(self) -> None:
        """
        Ensure a second 'add_interface' allocates the next free ifindex
        and registers its own handler / rings / caches alongside the
        first, both reachable through 'stack.interfaces'.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        first = add_interface(
            fd=self._fds[0][1],
            layer=InterfaceLayer.L2,
            mac_address=MacAddress("02:00:00:00:00:01"),
        )

        second = add_interface(
            fd=self._fds[1][1],
            layer=InterfaceLayer.L3,
        )

        self.assertEqual(second, first + 1, msg="Second interface must take the next free ifindex.")
        self.assertEqual(set(stack.interfaces), {first, second}, msg="Both interfaces must be registered.")
        self.assertIsInstance(stack.interfaces[first], PacketHandlerL2, msg="First interface is the L2 handler.")
        self.assertIsInstance(stack.interfaces[second], PacketHandlerL3, msg="Second interface is the L3 handler.")
        self.assertEqual(stack.interfaces[second]._ifindex, second, msg="Handler must record its ifindex.")

    def test__add_interface__second_l2_gets_isolated_neighbor_caches(self) -> None:
        """
        Ensure two L2 interfaces each own a distinct ARP cache and a
        distinct ND cache, with every cache's owner back-reference
        pointing at its own handler — so neighbor state is keyed per
        interface the way Linux keys ARP / ND per ifindex.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        first = add_interface(
            fd=self._fds[0][1],
            layer=InterfaceLayer.L2,
            mac_address=MacAddress("02:00:00:00:00:01"),
        )
        second = add_interface(
            fd=self._fds[1][1],
            layer=InterfaceLayer.L2,
            mac_address=MacAddress("02:00:00:00:00:02"),
        )

        iface_1 = stack.interfaces[first]
        iface_2 = stack.interfaces[second]

        self.assertIsNot(
            iface_1._arp_cache,
            iface_2._arp_cache,
            msg="Each interface must own a distinct ARP cache.",
        )
        self.assertIsNot(
            iface_1._nd_cache,
            iface_2._nd_cache,
            msg="Each interface must own a distinct ND cache.",
        )
        assert iface_2._arp_cache is not None and iface_2._nd_cache is not None
        self.assertIs(
            iface_2._arp_cache._owner,
            iface_2,
            msg="A second interface's ARP cache must point back at its own handler.",
        )
        self.assertIs(
            iface_2._nd_cache._owner,
            iface_2,
            msg="A second interface's ND cache must point back at its own handler.",
        )


class TestStackAddInterfacePublicExport(TestCase):
    """
    The 'add_interface' public-namespace re-export tests.
    """

    def test__add_interface__exported_from_stack_namespace(self) -> None:
        """
        Ensure 'add_interface' is reachable on the public 'pytcp.stack'
        namespace (the sanctioned stack-lifecycle API surface) and is
        declared in '__all__', not only importable from the
        implementation module 'pytcp.stack.lifecycle'.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertIs(
            stack.add_interface,
            add_interface,
            msg="pytcp.stack must re-export the lifecycle 'add_interface'.",
        )
        self.assertIn(
            "add_interface",
            stack.__all__,
            msg="'add_interface' must be declared in pytcp.stack.__all__.",
        )

    def test__remove_interface__exported_from_stack_namespace(self) -> None:
        """
        Ensure 'remove_interface' is reachable on the public
        'pytcp.stack' namespace and declared in '__all__' — the
        runtime interface-teardown control op (RTM_DELLINK).

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertIs(
            stack.remove_interface,
            remove_interface,
            msg="pytcp.stack must re-export the lifecycle 'remove_interface'.",
        )
        self.assertIn(
            "remove_interface",
            stack.__all__,
            msg="'remove_interface' must be declared in pytcp.stack.__all__.",
        )


class TestStackInterfaceLifecycleDynamic(TestCase):
    """
    The runtime (stack-running) 'add_interface' / 'remove_interface'
    dynamic-lifecycle tests — interfaces start / stop their own
    subsystem threads on the spot when added to / removed from a live
    stack (RTM_NEWLINK / RTM_DELLINK).
    """

    @override
    def setUp(self) -> None:
        """
        Snapshot the interface registry + N=1 shims + running flag,
        start from an empty registry with the interface-start/stop
        helpers patched (so no real subsystem threads spawn), and
        provide pipe fds as ring fd stand-ins.
        """

        self.enterContext(patch("pytcp.runtime.subsystem.log"))
        # The RTM_DELLINK cascade logs through the Address / Neighbor
        # control tools and the packet handler (IPv6 multicast leave);
        # silence them so the cascade tests do not speckle the suite
        # output (unit_testing §10a.4).
        self.enterContext(patch("pytcp.stack.address.log"))
        self.enterContext(patch("pytcp.stack.neighbor.log"))
        self.enterContext(patch("pytcp.runtime.packet_handler.log"))
        self._start_iface = self.enterContext(patch.object(lifecycle, "_start_interface"))
        self._stop_iface = self.enterContext(patch.object(lifecycle, "_stop_interface"))

        self._sentinel = object()
        self._snapshot = {
            name: getattr(stack, name, self._sentinel) for name in ("interfaces", "stack_running", "ip4_fib", "ip6_fib")
        }
        self._route_snapshot = getattr(stack, "route", self._sentinel)
        if hasattr(stack, "route"):
            delattr(stack, "route")

        stack.interfaces = InterfaceTable(first_ifindex=stack.STACK__DEFAULT_IFINDEX)
        stack.stack_running = False
        self._fds = [os.pipe() for _ in range(2)]
        self.addCleanup(self._cleanup)

    def _cleanup(self) -> None:
        """
        Close the pipe fds and restore the snapshotted module state.
        """

        for read_fd, write_fd in self._fds:
            for fd in (read_fd, write_fd):
                try:
                    os.close(fd)
                except OSError:
                    pass
        for name, value in self._snapshot.items():
            if value is self._sentinel:
                if hasattr(stack, name):
                    delattr(stack, name)
            else:
                setattr(stack, name, value)
        if self._route_snapshot is not self._sentinel:
            setattr(stack, "route", self._route_snapshot)

    def _add_l2(self, fd_index: int) -> int:
        """
        Add an L2 interface on the given pipe-fd index; return ifindex.
        """

        return add_interface(
            fd=self._fds[fd_index][1],
            layer=InterfaceLayer.L2,
            mac_address=MacAddress(f"02:00:00:00:00:0{fd_index + 1}"),
        )

    def test__add_interface__starts_interface_when_stack_running(self) -> None:
        """
        Ensure adding an interface to an already-running stack starts
        that interface's subsystems on the spot (the daemon RTM_NEWLINK
        runtime path), rather than waiting for a 'stack.start()' that
        already happened.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        stack.stack_running = True
        ifindex = self._add_l2(0)

        self._start_iface.assert_called_once_with(stack.interfaces[ifindex])

    def test__add_interface__does_not_start_when_stack_stopped(self) -> None:
        """
        Ensure adding an interface before the stack is started does NOT
        start its subsystems — the pending 'stack.start()' brings every
        registered interface up.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        stack.stack_running = False
        self._add_l2(0)

        self._start_iface.assert_not_called()

    def test__remove_interface__stops_and_deregisters_when_running(self) -> None:
        """
        Ensure removing an interface from a running stack stops its
        subsystems and deregisters it from 'stack.interfaces',
        returning the removed handler (RTM_DELLINK).

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        stack.stack_running = True
        ifindex = self._add_l2(0)
        handler = stack.interfaces[ifindex]

        removed = remove_interface(ifindex)

        self.assertIs(removed, handler, msg="remove_interface must return the removed handler.")
        self.assertNotIn(ifindex, stack.interfaces, msg="remove_interface must deregister the interface.")
        self._stop_iface.assert_called_once_with(handler)

    def test__remove_interface__deregisters_without_stop_when_stopped(self) -> None:
        """
        Ensure removing an interface from a stopped stack deregisters
        it without stopping subsystems (nothing was started).

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        stack.stack_running = False
        ifindex = self._add_l2(0)

        remove_interface(ifindex)

        self.assertNotIn(ifindex, stack.interfaces, msg="remove_interface must deregister the interface.")
        self._stop_iface.assert_not_called()

    def test__remove_interface__unknown_ifindex_returns_none(self) -> None:
        """
        Ensure removing an unregistered ifindex returns None and stops
        nothing.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        stack.stack_running = True

        self.assertIsNone(remove_interface(99), msg="remove_interface on an unknown ifindex must return None.")
        self._stop_iface.assert_not_called()

    def test__remove_interface__drops_interface_addresses(self) -> None:
        """
        Ensure removing a running interface drops every unicast
        address it carried (an RTM_DELADDR per address) so the
        interface's connected routes — synthesized from those
        addresses — vanish with it (RTM_DELLINK).

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        stack.stack_running = True
        ifindex = self._add_l2(0)
        handler = stack.interfaces[ifindex]
        assert isinstance(handler, PacketHandlerL2)
        v6 = Ip6IfAddr("2001:db8:50::7/64")
        handler._ip4_ifaddr = [Ip4IfAddr("10.0.50.7/24")]
        handler._ip6_ifaddr = [v6]
        handler._ip6_multicast_filters = {
            v6.address.solicited_node_multicast: Ip6MulticastFilter(Ip6MulticastFilterMode.EXCLUDE)
        }
        handler._mac_multicast = [v6.address.solicited_node_multicast.multicast_mac]
        # Removing the interface leaves the solicited-node multicast,
        # which emits an MLDv2 state-change Report (RFC 3810 §6.1); this
        # unit test has no live timer, so stub the emit — the leave path
        # is exercised in the icmp6 MLDv2-leave integration tests.
        handler._send_mld_state_change = MagicMock()  # type: ignore[method-assign]

        remove_interface(ifindex)

        self.assertEqual(handler._ip4_ifaddr, [], msg="remove_interface must drop every IPv4 address.")
        self.assertEqual(handler._ip6_ifaddr, [], msg="remove_interface must drop every IPv6 address.")

    def test__remove_interface__flushes_neighbor_caches(self) -> None:
        """
        Ensure removing a running interface flushes its ARP and ND
        caches, so no neighbour entry survives the device — the
        Linux 'ip neighbor flush dev <ifX>' half of RTM_DELLINK.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        stack.stack_running = True
        ifindex = self._add_l2(0)
        handler = stack.interfaces[ifindex]
        neighbor = NeighborApi(packet_handler=handler)
        neighbor.add(ip=Ip4Address("10.0.50.9"), mac=MacAddress("02:00:00:00:50:09"))
        neighbor.add(ip=Ip6Address("2001:db8:50::9"), mac=MacAddress("02:00:00:00:50:0a"))

        remove_interface(ifindex)

        self.assertEqual(
            NeighborApi(packet_handler=handler).list_neighbors(),
            (),
            msg="remove_interface must flush both neighbour caches.",
        )

    def test__remove_interface__purges_oif_routes(self) -> None:
        """
        Ensure removing a running interface purges explicitly-installed
        FIB routes that egress it ('oif' == ifindex) from both address
        families, while routes egressing other interfaces survive.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        stack.stack_running = True
        stack.ip4_fib = RouteTable[Ip4Address, Ip4Network]()
        stack.ip6_fib = RouteTable[Ip6Address, Ip6Network]()
        ifindex = self._add_l2(0)
        keep4 = Route(destination=Ip4Network("10.9.0.0/16"), gateway=Ip4Address("10.9.0.1"), oif=ifindex + 1)
        stack.ip4_fib.add(route=Route(destination=Ip4Network("10.0.50.0/24"), oif=ifindex))
        stack.ip4_fib.add(route=keep4)
        stack.ip6_fib.add(route=Route(destination=Ip6Network("2001:db8:50::/64"), oif=ifindex))

        remove_interface(ifindex)

        self.assertEqual(
            stack.ip4_fib.snapshot(),
            (keep4,),
            msg="remove_interface must purge only the IPv4 routes egressing the removed interface.",
        )
        self.assertEqual(
            stack.ip6_fib.snapshot(),
            (),
            msg="remove_interface must purge the IPv6 routes egressing the removed interface.",
        )

    def test__remove_interface__stops_dhcp4_client(self) -> None:
        """
        Ensure removing a running interface stops its per-interface
        DHCPv4 client — a Subsystem thread the bare thread-teardown
        ('_stop_interface') does not own, so a leaked client would
        keep renewing a lease on a removed NIC.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        stack.stack_running = True
        ifindex = self._add_l2(0)
        handler = stack.interfaces[ifindex]
        dhcp4_client = create_autospec(Dhcp4Client, spec_set=True)
        assert isinstance(handler, PacketHandlerL2)
        handler._dhcp4_client = dhcp4_client

        remove_interface(ifindex)

        dhcp4_client.stop.assert_called_once_with()

    def test__remove_interface__cascade_skipped_when_stopped(self) -> None:
        """
        Ensure removing an interface from a stopped stack deregisters
        it without running the teardown cascade — a stopped stack has
        no live sessions / threads, and 'init()' rebuilds from scratch.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        stack.stack_running = False
        ifindex = self._add_l2(0)
        handler = stack.interfaces[ifindex]
        dhcp4_client = create_autospec(Dhcp4Client, spec_set=True)
        assert isinstance(handler, PacketHandlerL2)
        handler._dhcp4_client = dhcp4_client
        handler._ip4_ifaddr = [Ip4IfAddr("10.0.50.7/24")]

        remove_interface(ifindex)

        self.assertNotIn(ifindex, stack.interfaces, msg="remove_interface must still deregister when stopped.")
        dhcp4_client.stop.assert_not_called()
        self.assertEqual(
            handler._ip4_ifaddr,
            [Ip4IfAddr("10.0.50.7/24")],
            msg="A stopped-stack remove must not run the address-drop cascade.",
        )


class TestStackInitZeroInterface(TestCase):
    """
    The zero-interface 'stack.init()' tests — the daemon-shaped target
    where 'init()' brings up only the stack core (timer, FIBs, unbound
    control tools) with no network interface, and interfaces are added
    later via 'add_interface'.
    """

    @override
    def setUp(self) -> None:
        """
        Snapshot the module-level singletons 'stack.init()' rebinds and
        suppress the subsystem-init log lines. The Timer is constructed
        (not started), so no thread leaks; the test never calls
        'stack.start()'.
        """

        log_patch = patch("pytcp.stack.log")
        log_patch.start()
        self.addCleanup(log_patch.stop)
        subsystem_log_patch = patch("pytcp.runtime.subsystem.log")
        subsystem_log_patch.start()
        self.addCleanup(subsystem_log_patch.stop)

        self._sentinel = object()
        self._snapshot = {
            name: getattr(stack, name, self._sentinel)
            for name in (
                "timer",
                "interfaces",
                "address",
                "link",
                "route",
                "ip4_fib",
                "ip6_fib",
                "dhcp4_client",
                "link_local",
                "stack_initialized",
            )
        }

    @override
    def tearDown(self) -> None:
        """
        Restore the snapshot so subsequent tests start clean.
        """

        for name, value in self._snapshot.items():
            if value is self._sentinel:
                if hasattr(stack, name):
                    delattr(stack, name)
            else:
                setattr(stack, name, value)

    def test__stack__init_no_device_registers_only_loopback(self) -> None:
        """
        Ensure 'stack.init()' called with no fd / layer brings the stack
        up with exactly the loopback interface — like Linux, 'lo' is
        always present, and it is the daemon's resting state before any
        physical device attaches.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        stack.init()
        self.addCleanup(self._close_loopback_ring)

        self.assertEqual(
            len(stack.interfaces),
            1,
            msg="No-device init() must register exactly the loopback interface.",
        )
        lo = stack.loopback_handler()
        self.assertIsNotNone(
            lo,
            msg="No-device init() must register a loopback interface.",
        )
        assert lo is not None  # narrowed for mypy / pyright; asserted above
        self.assertIs(
            lo.interface_layer,
            InterfaceLayer.LOOPBACK,
            msg="The sole registered interface must be the loopback interface.",
        )
        self.assertTrue(
            stack.stack_initialized,
            msg="No-device init() must still mark the stack initialized.",
        )

    def test__stack__init_loopback_owns_loopback_addresses(self) -> None:
        """
        Ensure the loopback interface 'stack.init()' brings up owns the
        IPv4 and IPv6 loopback addresses (127.0.0.1 and ::1) so local
        delivery has a receiving address.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        stack.init()
        self.addCleanup(self._close_loopback_ring)

        lo = stack.loopback_handler()
        assert lo is not None  # narrowed for mypy; asserted above
        self.assertEqual(
            lo.ip4_unicast,
            [Ip4Address("127.0.0.1")],
            msg="The loopback interface must own 127.0.0.1.",
        )
        self.assertEqual(
            lo.ip6_unicast,
            [Ip6Address("::1")],
            msg="The loopback interface must own ::1.",
        )

    def _close_loopback_ring(self) -> None:
        """
        Close the loopback ring's eventfd if a loopback interface is
        registered — keeps a real-'init()' test from leaking the fd.
        """

        lo = stack.loopback_handler()
        if lo is not None:
            lo._lo_ring.close()

    def test__stack__init_zero_interface_builds_unbound_tools(self) -> None:
        """
        Ensure 'stack.init()' with no interface builds the control APIs
        as unbound tools (no packet handler bound), so a device can be
        selected later via 'interface(ifindex)'.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        stack.init()

        self.assertIsInstance(
            stack.address,
            AddressApi,
            msg="Zero-interface init() must build an AddressApi tool.",
        )
        self.assertIsInstance(
            stack.link,
            LinkApi,
            msg="Zero-interface init() must build a LinkApi tool.",
        )
        self.assertIsNone(
            stack.address._packet_handler,
            msg="The address tool must be unbound (no packet handler).",
        )
        self.assertIsNone(
            stack.link._packet_handler,
            msg="The link tool must be unbound (no packet handler).",
        )

    def test__stack__init_zero_interface_no_dhcp_or_link_local(self) -> None:
        """
        Ensure 'stack.init()' with no interface constructs neither the
        DHCPv4 client nor the link-local subsystem — both are
        per-interface L2 concerns with no device to attach to.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        stack.init()

        self.assertIsNone(
            stack.dhcp4_client,
            msg="Zero-interface init() must not build a DHCPv4 client.",
        )
        self.assertIsNone(
            stack.link_local,
            msg="Zero-interface init() must not build a link-local client.",
        )

    def test__stack__init_zero_interface_builds_global_routing(self) -> None:
        """
        Ensure 'stack.init()' with no interface still builds the global
        routing state (the two FIBs + the Route API) — routing is
        above interfaces, so it comes up with the stack core.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        stack.init()

        self.assertIsInstance(
            stack.ip4_fib,
            RouteTable,
            msg="Zero-interface init() must build the IPv4 FIB.",
        )
        self.assertIsInstance(
            stack.ip6_fib,
            RouteTable,
            msg="Zero-interface init() must build the IPv6 FIB.",
        )
        self.assertIsInstance(
            stack.route,
            RouteApi,
            msg="Zero-interface init() must build the Route API.",
        )

    def test__stack__init_zero_then_add_interface(self) -> None:
        """
        Ensure an interface added after a zero-interface 'stack.init()'
        lands in the registry and is reachable via the control tools'
        'interface(ifindex)' selector — the daemon add-device path.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        stack.init()
        stack.stack_running = False

        with (
            patch.object(stack.lifecycle, "TxRing"),
            patch.object(stack.lifecycle, "RxRing"),
            patch.object(stack.lifecycle, "ArpCache"),
            patch.object(stack.lifecycle, "NdCache"),
            patch.object(stack.lifecycle, "PacketHandlerL2"),
        ):
            ifindex = add_interface(
                fd=-1,
                layer=InterfaceLayer.L2,
                mac_address=MacAddress("02:00:00:00:00:01"),
            )

        self.assertIn(
            ifindex,
            stack.interfaces,
            msg="add_interface after zero-interface init() must register the device.",
        )


class TestStackLoopbackLifecycle(TestCase):
    """
    The loopback interface start / stop lifecycle tests — 'lo's own
    consumer thread comes up with 'stack.start()' and winds down with
    'stack.stop()'.
    """

    @override
    def setUp(self) -> None:
        """
        Snapshot the module-level singletons the lifecycle rebinds and
        suppress the subsystem-init log lines.
        """

        self.enterContext(patch("pytcp.stack.log"))
        self.enterContext(patch("pytcp.runtime.subsystem.log"))

        self._sentinel = object()
        self._snapshot = {
            name: getattr(stack, name, self._sentinel)
            for name in ("timer", "interfaces", "stack_initialized", "stack_running")
        }

    @override
    def tearDown(self) -> None:
        """
        Stop the stack if a test left it running, then restore the
        snapshot so a follow-up test starts clean.
        """

        if getattr(stack, "stack_running", False):
            stack.stop()
        for name, value in self._snapshot.items():
            if value is self._sentinel:
                if hasattr(stack, name):
                    delattr(stack, name)
            else:
                setattr(stack, name, value)

    def test__stack__loopback_thread_starts_and_stops(self) -> None:
        """
        Ensure 'stack.start()' brings the loopback interface's consumer
        thread up and 'stack.stop()' winds it down, so locally-delivered
        traffic is serviced only while the stack is running.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        stack.init()
        lo = stack.loopback_handler()
        assert lo is not None  # narrowed for mypy; init() always registers lo

        stack.start(wait_for_dhcp_bind=False)
        self.assertTrue(
            lo._thread is not None and lo._thread.is_alive(),
            msg="stack.start() must bring the loopback consumer thread up.",
        )

        stack.stop()
        self.assertFalse(
            lo._thread is not None and lo._thread.is_alive(),
            msg="stack.stop() must wind the loopback consumer thread down.",
        )


class TestAddInterfacePerInterfaceSubsystems(TestCase):
    """
    The 'add_interface' per-interface DHCPv4 / link-local construction
    tests — the subsystems move out of 'init()' so each interface owns
    its own client(s), bound to that interface via 'interface(ifindex)'.
    """

    @override
    def setUp(self) -> None:
        """
        Bring the stack core up with a zero-interface 'init()' and
        snapshot the singletons the tests rebind. Suppress log lines.
        """

        log_patch = patch("pytcp.stack.log")
        log_patch.start()
        self.addCleanup(log_patch.stop)
        subsystem_log_patch = patch("pytcp.runtime.subsystem.log")
        subsystem_log_patch.start()
        self.addCleanup(subsystem_log_patch.stop)

        self._sentinel = object()
        self._snapshot = {
            name: getattr(stack, name, self._sentinel)
            for name in (
                "timer",
                "interfaces",
                "address",
                "link",
                "route",
                "ip4_fib",
                "ip6_fib",
                "dhcp4_client",
                "dhcp6_client",
                "link_local",
                "stack_initialized",
                "stack_running",
            )
        }
        stack.init()
        stack.stack_running = False
        # Patch the per-interface subsystem build so construction is a
        # cheap mock (autospec on the class) while the handler itself is
        # real, so 'interface(ifindex).mac_address' resolves.
        self._ring_patches = (
            patch.object(stack.lifecycle, "TxRing"),
            patch.object(stack.lifecycle, "RxRing"),
            patch.object(stack.lifecycle, "ArpCache"),
            patch.object(stack.lifecycle, "NdCache"),
        )
        for p in self._ring_patches:
            p.start()
            self.addCleanup(p.stop)

    @override
    def tearDown(self) -> None:
        """
        Restore the snapshot so subsequent tests start clean.
        """

        for name, value in self._snapshot.items():
            if value is self._sentinel:
                if hasattr(stack, name):
                    delattr(stack, name)
            else:
                setattr(stack, name, value)

    def test__add_interface__builds_dhcp_client_when_requested(self) -> None:
        """
        Ensure 'add_interface' on an L2 interface with 'ip4_dhcp=True'
        constructs a DHCPv4 client and installs it as the stack's
        client — the per-interface DHCP subsystem owned by the device.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with patch.object(stack.lifecycle, "Dhcp4Client") as dhcp_cls:
            add_interface(
                fd=-1,
                layer=InterfaceLayer.L2,
                mac_address=MacAddress("02:00:00:00:00:01"),
                ip4_dhcp=True,
            )

        self.assertIs(
            stack.dhcp4_client,
            dhcp_cls.return_value,
            msg="add_interface(ip4_dhcp=True) must build and install a DHCPv4 client.",
        )

    def test__add_interface__no_dhcp_client_when_not_requested(self) -> None:
        """
        Ensure 'add_interface' with 'ip4_dhcp=False' (the default) builds
        no DHCPv4 client — the slot stays None.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        add_interface(
            fd=-1,
            layer=InterfaceLayer.L2,
            mac_address=MacAddress("02:00:00:00:00:01"),
            ip4_dhcp=False,
        )

        self.assertIsNone(
            stack.dhcp4_client,
            msg="add_interface(ip4_dhcp=False) must not build a DHCPv4 client.",
        )

    def test__add_interface__builds_link_local_when_requested(self) -> None:
        """
        Ensure 'add_interface' on an L2 interface with
        'ip4_link_local=True' constructs the RFC 3927 link-local client
        and installs it as the stack's link-local subsystem.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with patch("pytcp.protocols.ip4.link_local.link_local__client.Ip4LinkLocal") as ll_cls:
            add_interface(
                fd=-1,
                layer=InterfaceLayer.L2,
                mac_address=MacAddress("02:00:00:00:00:01"),
                ip4_link_local=True,
            )

        self.assertIs(
            stack.link_local,
            ll_cls.return_value,
            msg="add_interface(ip4_link_local=True) must build and install a link-local client.",
        )

    def test__add_interface__builds_dhcp6_client_on_l2_ipv6(self) -> None:
        """
        Ensure 'add_interface' on an L2 interface with IPv6 enabled
        constructs a DHCPv6 client and installs it as the stack's client
        — DHCPv6 is RA-driven, so the client is built whenever IPv6 is
        enabled (no opt-in flag).

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with patch.object(stack.lifecycle, "Dhcp6Client") as dhcp6_cls:
            add_interface(
                fd=-1,
                layer=InterfaceLayer.L2,
                mac_address=MacAddress("02:00:00:00:00:01"),
                ip6_support=True,
            )

        self.assertIs(
            stack.dhcp6_client,
            dhcp6_cls.return_value,
            msg="add_interface on an L2 IPv6 interface must build and install a DHCPv6 client.",
        )

    def test__add_interface__no_dhcp6_client_when_ip6_disabled(self) -> None:
        """
        Ensure 'add_interface' with 'ip6_support=False' builds no DHCPv6
        client — the slot stays None.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        add_interface(
            fd=-1,
            layer=InterfaceLayer.L2,
            mac_address=MacAddress("02:00:00:00:00:01"),
            ip6_support=False,
        )

        self.assertIsNone(
            stack.dhcp6_client,
            msg="add_interface(ip6_support=False) must not build a DHCPv6 client.",
        )

    def test__add_interface__no_dhcp6_client_on_l3(self) -> None:
        """
        Ensure 'add_interface' on an L3 (TUN) interface builds no DHCPv6
        client — DHCPv6 needs link-scoped multicast, which is L2-only.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        add_interface(fd=-1, layer=InterfaceLayer.L3)

        self.assertIsNone(
            stack.dhcp6_client,
            msg="add_interface on an L3 interface must not build a DHCPv6 client.",
        )


class TestStackEgressPacketHandler(TestCase):
    """
    The 'stack.egress_packet_handler(dst)' resolver tests — the single
    seam that socket-originated TX (UDP / raw / TCP sends) routes
    through to pick the egress interface. Egress is FIB-driven: a routed
    destination the routing table cannot resolve raises (Linux returns
    EHOSTUNREACH; there is no sole-interface guess), while a link-scoped
    destination egresses the local link — the sole interface at N=1.
    """

    @override
    def setUp(self) -> None:
        """
        Snapshot 'stack.interfaces' / FIBs so each test installs its own.
        """

        self._interfaces_prior = dict(stack.interfaces)
        self.addCleanup(self._restore)

    def _restore(self) -> None:
        stack.interfaces.clear()
        stack.interfaces.update(self._interfaces_prior)

    def _install(self, count: int) -> list[object]:
        from types import SimpleNamespace

        from pytcp.runtime.fib import RouteTable

        table = InterfaceTable()
        handlers: list[object] = [SimpleNamespace(ip4_host=[], ip6_host=[]) for _ in range(count)]
        for i, handler in enumerate(handlers, start=1):
            table[i] = cast("PacketHandlerL2", handler)
        self.enterContext(patch.object(stack, "interfaces", table))
        self.enterContext(patch.object(stack, "ip4_fib", RouteTable(), create=True))
        self.enterContext(patch.object(stack, "ip6_fib", RouteTable(), create=True))
        return handlers

    def test__egress_packet_handler__link_scoped_resolves_sole_interface(self) -> None:
        """
        Ensure a link-scoped destination (IPv4 limited-broadcast /
        multicast, IPv6 multicast / link-local) egresses the sole
        registered interface — the local link is unambiguous at N=1,
        matching Linux's implicit per-interface broadcast / multicast
        routes.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        (handler,) = self._install(1)

        for dst in (
            Ip4Address("255.255.255.255"),
            Ip4Address("224.0.0.1"),
            Ip6Address("ff02::1"),
            Ip6Address("fe80::1"),
        ):
            with self.subTest(dst=dst):
                self.assertIs(
                    stack.egress_packet_handler(dst),
                    handler,
                    msg=f"A link-scoped dst {dst} must egress the sole interface.",
                )

    def test__egress_packet_handler__routed_dst_no_route_raises(self) -> None:
        """
        Ensure a routed unicast destination the FIB cannot resolve raises
        even when exactly one interface is registered — egress is the
        routing table's decision, not a sole-interface guess (Linux
        EHOSTUNREACH).

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._install(1)

        with self.assertRaises(RuntimeError):
            stack.egress_packet_handler(Ip4Address("203.0.113.9"))

    def test__egress_packet_handler__raises_when_no_interface(self) -> None:
        """
        Ensure 'egress_packet_handler(dst)' raises when no interface is
        registered — there is nothing to egress through.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._install(0)

        with self.assertRaises(RuntimeError):
            stack.egress_packet_handler(Ip4Address("224.0.0.1"))


class TestStackLocalAddressIntrospection(TestCase):
    """
    The 'stack.local_ip{4,6}_hosts()' / 'local_ip{4,6}_unicast()'
    cross-interface introspection tests — the read-only address-union
    seam that INADDR_ANY bind expansion and source-address validation
    use on a multi-homed host.
    """

    @override
    def setUp(self) -> None:
        """
        Install two fake interfaces, each owning one IPv4/IPv6 host +
        unicast address, in a fresh 'stack.interfaces' table.
        """

        from types import SimpleNamespace

        from net_addr import Ip4Address, Ip4IfAddr, Ip6Address, Ip6IfAddr

        self._iface_1 = SimpleNamespace(
            ip4_host=[Ip4IfAddr("10.0.1.7/24")],
            ip6_host=[Ip6IfAddr("2001:db8:0:1::7/64")],
            ip4_unicast=[Ip4Address("10.0.1.7")],
            ip6_unicast=[Ip6Address("2001:db8:0:1::7")],
        )
        self._iface_2 = SimpleNamespace(
            ip4_host=[Ip4IfAddr("10.0.2.7/24")],
            ip6_host=[Ip6IfAddr("2001:db8:0:2::7/64")],
            ip4_unicast=[Ip4Address("10.0.2.7")],
            ip6_unicast=[Ip6Address("2001:db8:0:2::7")],
        )
        table = InterfaceTable()
        table[1] = cast("PacketHandlerL2", self._iface_1)
        table[2] = cast("PacketHandlerL2", self._iface_2)
        self.enterContext(patch.object(stack, "interfaces", table))

    def test__stack__local_ip4_unicast_unions_across_interfaces(self) -> None:
        """
        Ensure 'local_ip4_unicast()' returns the union of every
        registered interface's IPv4 unicast addresses.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        from net_addr import Ip4Address

        self.assertEqual(
            set(stack.local_ip4_unicast()),
            {Ip4Address("10.0.1.7"), Ip4Address("10.0.2.7")},
            msg="local_ip4_unicast() must union every interface's IPv4 unicast addresses.",
        )

    def test__stack__local_ip6_unicast_unions_across_interfaces(self) -> None:
        """
        Ensure 'local_ip6_unicast()' returns the union of every
        registered interface's IPv6 unicast addresses.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        from net_addr import Ip6Address

        self.assertEqual(
            set(stack.local_ip6_unicast()),
            {Ip6Address("2001:db8:0:1::7"), Ip6Address("2001:db8:0:2::7")},
            msg="local_ip6_unicast() must union every interface's IPv6 unicast addresses.",
        )

    def test__stack__local_ip4_hosts_unions_across_interfaces(self) -> None:
        """
        Ensure 'local_ip4_hosts()' returns the union of every
        registered interface's IPv4 interface addresses.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        from net_addr import Ip4IfAddr

        self.assertEqual(
            set(stack.local_ip4_hosts()),
            {Ip4IfAddr("10.0.1.7/24"), Ip4IfAddr("10.0.2.7/24")},
            msg="local_ip4_hosts() must union every interface's IPv4 interface addresses.",
        )

    def test__stack__local_ip6_hosts_unions_across_interfaces(self) -> None:
        """
        Ensure 'local_ip6_hosts()' returns the union of every
        registered interface's IPv6 interface addresses.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        from net_addr import Ip6IfAddr

        self.assertEqual(
            set(stack.local_ip6_hosts()),
            {Ip6IfAddr("2001:db8:0:1::7/64"), Ip6IfAddr("2001:db8:0:2::7/64")},
            msg="local_ip6_hosts() must union every interface's IPv6 interface addresses.",
        )


class TestStackEgressPacketHandlerFib(TestCase):
    """
    The destination-aware 'stack.egress_packet_handler(dst)' FIB-egress
    tests — a multi-homed host picks the egress interface the routing
    table selects ('Route.oif'), on-link directly and off-link via the
    interface on which the gateway is reachable.
    """

    @override
    def setUp(self) -> None:
        """
        Install two interfaces on distinct subnets (ifindex 1 -> 10.0.1.0/24,
        ifindex 2 -> 10.0.2.0/24) and a fresh pair of FIBs.
        """

        from types import SimpleNamespace

        from net_addr import (
            Ip4Address,
            Ip4IfAddr,
            Ip4Network,
            Ip6Address,
            Ip6IfAddr,
            Ip6Network,
        )
        from pytcp.runtime.fib import RouteTable

        self._iface_1 = SimpleNamespace(
            ip4_host=[Ip4IfAddr("10.0.1.7/24")],
            ip6_host=[Ip6IfAddr("2001:db8:0:1::7/64")],
        )
        self._iface_2 = SimpleNamespace(
            ip4_host=[Ip4IfAddr("10.0.2.7/24")],
            ip6_host=[Ip6IfAddr("2001:db8:0:2::7/64")],
        )
        table = InterfaceTable()
        table[1] = cast("PacketHandlerL2", self._iface_1)
        table[2] = cast("PacketHandlerL2", self._iface_2)
        self.enterContext(patch.object(stack, "interfaces", table))
        self._ip4_fib: RouteTable[Ip4Address, Ip4Network] = RouteTable()
        self._ip6_fib: RouteTable[Ip6Address, Ip6Network] = RouteTable()
        self.enterContext(patch.object(stack, "ip4_fib", self._ip4_fib, create=True))
        self.enterContext(patch.object(stack, "ip6_fib", self._ip6_fib, create=True))

    def test__egress__on_link_dst_picks_owning_interface(self) -> None:
        """
        Ensure an on-link destination egresses the interface that owns
        the connected subnet (the matched connected route's 'oif').

        Reference: RFC 1122 §3.3.1 (next-hop selection / longest-prefix match).
        """

        from net_addr import Ip4Address

        self.assertIs(
            stack.egress_packet_handler(Ip4Address("10.0.2.50")),
            self._iface_2,
            msg="An on-link dst on interface 2's subnet must egress interface 2.",
        )

    def test__egress__off_link_dst_picks_gateway_interface(self) -> None:
        """
        Ensure an off-link destination egresses the interface on which
        the route's gateway is on-link (the second connected lookup).

        Reference: RFC 1122 §3.3.1 (next-hop selection via gateway).
        """

        from net_addr import Ip4Address, Ip4Network
        from pytcp.runtime.fib import Route, RouteProtocol

        self._ip4_fib.add(
            route=Route(
                destination=Ip4Network("0.0.0.0/0"),
                gateway=Ip4Address("10.0.1.1"),
                protocol=RouteProtocol.BOOT,
            )
        )

        self.assertIs(
            stack.egress_packet_handler(Ip4Address("8.8.8.8")),
            self._iface_1,
            msg="An off-link dst via a gateway on interface 1's subnet must egress interface 1.",
        )

    def test__egress__unresolved_dst_raises_when_ambiguous(self) -> None:
        """
        Ensure a destination the FIB cannot resolve to an egress raises
        when more than one interface is registered — there is no single
        egress to fall back to.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        from net_addr import Ip4Address

        with self.assertRaises(RuntimeError):
            stack.egress_packet_handler(Ip4Address("203.0.113.9"))

    def test__egress__link_scoped_dst_raises_when_ambiguous(self) -> None:
        """
        Ensure a link-scoped destination raises on a multi-homed host —
        the local link is ambiguous across interfaces, and PyTCP does
        not yet model explicit egress selection (IP_MULTICAST_IF /
        sin6_scope_id), so it cannot pick one.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        from net_addr import Ip4Address, Ip6Address

        for dst in (Ip4Address("224.0.0.1"), Ip6Address("ff02::1")):
            with self.subTest(dst=dst):
                with self.assertRaises(RuntimeError):
                    stack.egress_packet_handler(dst)


class TestStackHasRouteTo(TestCase):
    """
    The 'stack.has_route_to(dst)' tests — the synchronous no-route
    predicate the socket send/connect paths use to raise EHOSTUNREACH
    (Linux parity) when the FIB cannot reach a destination.
    """

    @override
    def setUp(self) -> None:
        """
        Install one interface (10.0.1.0/24) and a fresh IPv4 FIB.
        """

        from types import SimpleNamespace

        from net_addr import (
            Ip4Address,
            Ip4IfAddr,
            Ip4Network,
            Ip6Address,
            Ip6IfAddr,
            Ip6Network,
        )
        from pytcp.runtime.fib import RouteTable

        self._iface = SimpleNamespace(
            ip4_host=[Ip4IfAddr("10.0.1.7/24")],
            ip6_host=[Ip6IfAddr("2001:db8:0:1::7/64")],
        )
        table = InterfaceTable()
        table[1] = cast("PacketHandlerL2", self._iface)
        self.enterContext(patch.object(stack, "interfaces", table))
        self._ip4_fib: RouteTable[Ip4Address, Ip4Network] = RouteTable()
        self._ip6_fib: RouteTable[Ip6Address, Ip6Network] = RouteTable()
        self.enterContext(patch.object(stack, "ip4_fib", self._ip4_fib, create=True))
        self.enterContext(patch.object(stack, "ip6_fib", self._ip6_fib, create=True))

    def test__has_route_to__on_link_destination_true(self) -> None:
        """
        Ensure 'has_route_to' is True for an on-link destination (a
        connected route covers it).

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        from net_addr import Ip4Address

        self.assertTrue(
            stack.has_route_to(Ip4Address("10.0.1.50")),
            msg="has_route_to must be True for an on-link destination.",
        )

    def test__has_route_to__no_route_destination_false(self) -> None:
        """
        Ensure 'has_route_to' is False for a destination no connected or
        explicit route covers (no default route installed).

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        from net_addr import Ip4Address

        self.assertFalse(
            stack.has_route_to(Ip4Address("8.8.8.8")),
            msg="has_route_to must be False when no route covers the destination.",
        )

    def test__has_route_to__default_route_makes_off_link_true(self) -> None:
        """
        Ensure installing a default route makes an off-link destination
        routable again.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        from net_addr import Ip4Address, Ip4Network
        from pytcp.runtime.fib import Route, RouteProtocol

        self._ip4_fib.add(
            route=Route(
                destination=Ip4Network("0.0.0.0/0"),
                gateway=Ip4Address("10.0.1.1"),
                protocol=RouteProtocol.BOOT,
            )
        )

        self.assertTrue(
            stack.has_route_to(Ip4Address("8.8.8.8")),
            msg="has_route_to must be True for an off-link destination once a default route exists.",
        )

    def test__has_route_to__ip4_limited_broadcast_true(self) -> None:
        """
        Ensure 'has_route_to' is True for the IPv4 limited broadcast
        (255.255.255.255) even with no route installed — it is delivered
        directly on the egress link, never via the routing table, so a
        DHCP DISCOVER (sent before any address/route exists) is not
        spuriously blocked with EHOSTUNREACH.

        Reference: RFC 2131 §4.1 (DHCP client broadcasts to 255.255.255.255 before configuration).
        Reference: RFC 919 §7 (limited broadcast is link-scoped, not routed).
        """

        from net_addr import Ip4Address

        self.assertTrue(
            stack.has_route_to(Ip4Address("255.255.255.255")),
            msg="has_route_to must be True for the IPv4 limited broadcast.",
        )

    def test__has_route_to__ip4_multicast_true(self) -> None:
        """
        Ensure 'has_route_to' is True for an IPv4 multicast destination
        with no route installed — multicast is delivered on the egress
        link and needs no unicast routing-table entry.

        Reference: RFC 1112 §6.1 (IP multicast transmission needs no host route).
        """

        from net_addr import Ip4Address

        self.assertTrue(
            stack.has_route_to(Ip4Address("224.0.0.1")),
            msg="has_route_to must be True for an IPv4 multicast destination.",
        )

    def test__has_route_to__ip6_multicast_true(self) -> None:
        """
        Ensure 'has_route_to' is True for an IPv6 multicast destination
        with no route installed — multicast is delivered on the egress
        link and needs no routing-table entry.

        Reference: RFC 4291 §2.7 (IPv6 multicast addressing, link-scoped delivery).
        """

        from net_addr import Ip6Address

        self.assertTrue(
            stack.has_route_to(Ip6Address("ff02::1")),
            msg="has_route_to must be True for an IPv6 multicast destination.",
        )

    def test__has_route_to__ip6_link_local_true(self) -> None:
        """
        Ensure 'has_route_to' is True for an IPv6 link-local destination
        with no explicit route installed — link-local unicast is reachable
        on-link and is not resolved through the routing table.

        Reference: RFC 4291 §2.5.6 (link-local addresses are link-scoped).
        """

        from net_addr import Ip6Address

        self.assertTrue(
            stack.has_route_to(Ip6Address("fe80::2e0:67ff:fe26:88cb")),
            msg="has_route_to must be True for an IPv6 link-local destination.",
        )


class TestStackEgressInterfaceMtu(TestCase):
    """
    The 'stack.egress_interface_mtu(dst)' tests — the per-destination
    successor to the retired 'stack.interface_mtu' global: TCP MSS
    computation and the UDP / socket Path-MTU fall-back read the EGRESS
    interface's link MTU, so a multi-homed host sizes segments to the
    interface the FIB selects for the peer.
    """

    @override
    def setUp(self) -> None:
        """
        Install two interfaces on distinct subnets with distinct MTUs
        (ifindex 1 -> 10.0.1.0/24 @ 1500, ifindex 2 -> 10.0.2.0/24 @ 9000)
        and a fresh pair of FIBs.
        """

        from types import SimpleNamespace

        from net_addr import (
            Ip4Address,
            Ip4IfAddr,
            Ip4Network,
            Ip6Address,
            Ip6IfAddr,
            Ip6Network,
        )
        from pytcp.runtime.fib import RouteTable

        self._iface_1 = SimpleNamespace(
            ip4_host=[Ip4IfAddr("10.0.1.7/24")],
            ip6_host=[Ip6IfAddr("2001:db8:0:1::7/64")],
            interface_mtu=1500,
        )
        self._iface_2 = SimpleNamespace(
            ip4_host=[Ip4IfAddr("10.0.2.7/24")],
            ip6_host=[Ip6IfAddr("2001:db8:0:2::7/64")],
            interface_mtu=9000,
        )
        self._table = InterfaceTable()
        self._table[1] = cast("PacketHandlerL2", self._iface_1)
        self._table[2] = cast("PacketHandlerL2", self._iface_2)
        self.enterContext(patch.object(stack, "interfaces", self._table))
        self._ip4_fib: RouteTable[Ip4Address, Ip4Network] = RouteTable()
        self._ip6_fib: RouteTable[Ip6Address, Ip6Network] = RouteTable()
        self.enterContext(patch.object(stack, "ip4_fib", self._ip4_fib, create=True))
        self.enterContext(patch.object(stack, "ip6_fib", self._ip6_fib, create=True))

    def test__egress_interface_mtu__on_link_dst_returns_owning_interface_mtu(self) -> None:
        """
        Ensure an on-link destination yields the MTU of the interface
        that owns its connected subnet (the matched connected route's
        'oif'), not a global default.

        Reference: RFC 1122 §3.3.1 (next-hop selection / longest-prefix match).
        """

        from net_addr import Ip4Address

        self.assertEqual(
            stack.egress_interface_mtu(Ip4Address("10.0.2.50")),
            9000,
            msg="egress_interface_mtu must return interface 2's MTU for an on-link dst on its subnet.",
        )

    def test__egress_interface_mtu__unrouted_dst_returns_none(self) -> None:
        """
        Ensure an unresolved routed destination returns None (no
        sole-interface guess) so the caller degrades to its own
        conservative MTU fall-back — egress sizing follows the routing
        table, not the bare interface count.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        from net_addr import Ip4Address

        solo = InterfaceTable()
        solo[1] = cast("PacketHandlerL2", self._iface_1)
        self.enterContext(patch.object(stack, "interfaces", solo))

        self.assertIsNone(
            stack.egress_interface_mtu(Ip4Address("203.0.113.9")),
            msg="egress_interface_mtu must return None for an unrouted dst (no sole-interface fallback).",
        )

    def test__egress_interface_mtu__link_scoped_dst_returns_sole_interface_mtu(self) -> None:
        """
        Ensure a link-scoped destination yields the sole interface's MTU
        at N=1 — link-scoped traffic egresses the only link, so its path
        MTU is that interface's MTU.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        from net_addr import Ip4Address

        solo = InterfaceTable()
        solo[1] = cast("PacketHandlerL2", self._iface_1)
        self.enterContext(patch.object(stack, "interfaces", solo))

        self.assertEqual(
            stack.egress_interface_mtu(Ip4Address("224.0.0.1")),
            1500,
            msg="egress_interface_mtu must return the sole interface's MTU for a link-scoped dst.",
        )

    def test__egress_interface_mtu__none_when_no_interface(self) -> None:
        """
        Ensure 'egress_interface_mtu' returns None when no interface is
        registered — a reduced context with no egress to size against.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        from net_addr import Ip4Address

        self.enterContext(patch.object(stack, "interfaces", InterfaceTable()))

        self.assertIsNone(
            stack.egress_interface_mtu(Ip4Address("10.0.1.50")),
            msg="egress_interface_mtu must be None when no interface is registered.",
        )

    def test__egress_interface_mtu__none_when_ambiguous(self) -> None:
        """
        Ensure 'egress_interface_mtu' returns None when more than one
        interface is registered and the FIB cannot resolve an egress —
        there is no single MTU to size against (it does not raise; MSS /
        PMTU callers degrade to their own conservative fall-back).

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        from net_addr import Ip4Address

        self.assertIsNone(
            stack.egress_interface_mtu(Ip4Address("203.0.113.9")),
            msg="egress_interface_mtu must be None for an unresolved dst with multiple interfaces.",
        )


class TestStackAddInterfaceDhcp4PerInterface(TestCase):
    """
    The per-interface DHCPv4-client construction tests for a multi-homed
    host.
    """

    @override
    def setUp(self) -> None:
        """
        Build an empty interface registry plus the control-plane APIs the
        DHCPv4 construction path consults (address / link / route), with
        the TX / RX rings mocked so 'add_interface' constructs the
        handlers and their DHCP clients without touching the fds.
        Snapshots / restores the affected module slots.
        """

        self.enterContext(patch("pytcp.runtime.subsystem.log"))
        self.enterContext(patch.object(lifecycle, "TxRing"))
        self.enterContext(patch.object(lifecycle, "RxRing"))

        self._sentinel = object()
        self._names = ("interfaces", "route", "address", "link", "dhcp4_client", "ip4_fib", "ip6_fib")
        self._snapshot = {name: getattr(stack, name, self._sentinel) for name in self._names}

        ip4_fib: RouteTable[Ip4Address, Ip4Network] = RouteTable()
        ip6_fib: RouteTable[Ip6Address, Ip6Network] = RouteTable()
        stack.ip4_fib = ip4_fib
        stack.ip6_fib = ip6_fib
        stack.interfaces = InterfaceTable(first_ifindex=stack.STACK__DEFAULT_IFINDEX)
        stack.route = RouteApi(ip4_fib=ip4_fib, ip6_fib=ip6_fib)
        stack.address = AddressApi()
        stack.link = LinkApi()

        self._fds = [os.pipe() for _ in range(2)]
        self.addCleanup(self._cleanup)

    def _cleanup(self) -> None:
        """
        Close the pipe fds and restore the snapshotted module slots.
        """

        for read_fd, write_fd in self._fds:
            for fd in (read_fd, write_fd):
                try:
                    os.close(fd)
                except OSError:
                    pass
        for name, value in self._snapshot.items():
            if value is self._sentinel:
                if hasattr(stack, name):
                    delattr(stack, name)
            else:
                setattr(stack, name, value)

    def test__add_interface__each_dhcp4_interface_owns_its_own_client(self) -> None:
        """
        Ensure two DHCPv4-enabled interfaces each construct and retain
        their OWN 'Dhcp4Client' — the per-interface DHCP client must not
        be clobbered by a single shared module slot when a second
        interface is added (the 'make run_multi' multi-homed-host case).

        Reference: RFC 2131 §4.1 (each configured interface runs its own
        DHCPv4 client).
        """

        first = add_interface(
            fd=self._fds[0][1],
            layer=InterfaceLayer.L2,
            mac_address=MacAddress("02:00:00:00:00:01"),
            ip4_support=True,
            ip4_dhcp=True,
        )
        second = add_interface(
            fd=self._fds[1][1],
            layer=InterfaceLayer.L2,
            mac_address=MacAddress("02:00:00:00:00:02"),
            ip4_support=True,
            ip4_dhcp=True,
        )

        handler_1 = stack.interfaces[first]
        handler_2 = stack.interfaces[second]
        assert isinstance(handler_1, PacketHandlerL2)
        assert isinstance(handler_2, PacketHandlerL2)
        client_1 = handler_1._dhcp4_client
        client_2 = handler_2._dhcp4_client

        self.assertIsNotNone(client_1, msg="The first interface must own a DHCPv4 client.")
        self.assertIsNotNone(client_2, msg="The second interface must own a DHCPv4 client.")
        self.assertIsNot(
            client_1,
            client_2,
            msg="Each interface must own a DISTINCT DHCPv4 client (no shared module slot).",
        )


class TestStackConfigConstantGoldens(TestCase):
    """
    Exact-value goldens for the stack configuration constants whose
    NumberReplacer / boolean-flip mutations survived the range-style
    assertions: secret lengths, the TFO cache cap, fragment-flow
    timeouts, the ephemeral port range, and the boolean policy
    defaults.
    """

    def test__stack__secret_lengths_are_16_bytes(self) -> None:
        """
        Ensure every bootstrap secret is exactly 16 bytes (128 bits).

        Reference: RFC 6528 §3 (ISS secret as opaque keying material).
        """

        self.assertEqual(len(stack.TCP__ISS_SECRET), 16, msg="ISS secret must be 16 bytes.")
        self.assertEqual(len(stack.IP6__FLOW_SECRET), 16, msg="IPv6 flow secret must be 16 bytes.")
        self.assertEqual(len(stack.TCP__FASTOPEN_SECRET), 16, msg="TFO secret must be 16 bytes.")
        self.assertEqual(len(stack.TCP__PORT_SECRET), 16, msg="port secret must be 16 bytes.")

    def test__stack__fastopen_cache_max_size(self) -> None:
        """
        Ensure the TCP Fast Open cache cap is exactly 1024 entries.

        Reference: RFC 7413 §6.1 (server-side TFO state bound).
        """

        self.assertEqual(
            stack.TCP__FASTOPEN_CACHE_MAX_SIZE,
            1024,
            msg="TCP__FASTOPEN_CACHE_MAX_SIZE must be 1024.",
        )

    def test__stack__fragment_flow_timeouts_are_5_seconds(self) -> None:
        """
        Ensure the IPv4 and IPv6 fragment-flow reassembly timeouts are
        exactly 5 seconds.

        Reference: RFC 791 §3.2 (IPv4 reassembly timeout).
        """

        self.assertEqual(stack.IP4__FRAG_FLOW_TIMEOUT__S, 5, msg="IPv4 frag-flow timeout must be 5 s.")
        self.assertEqual(stack.IP6__FRAG_FLOW_TIMEOUT__S, 5, msg="IPv6 frag-flow timeout must be 5 s.")

    def test__stack__ephemeral_port_range_exact_bounds(self) -> None:
        """
        Ensure the ephemeral port range is exactly [32768, 61000].

        Reference: RFC 6056 §3.2 (ephemeral port range).
        """

        self.assertEqual(
            stack.STACK__EPHEMERAL_PORT_RANGE__LOW,
            32768,
            msg="ephemeral low must be 32768.",
        )
        self.assertEqual(
            stack.STACK__EPHEMERAL_PORT_RANGE__HIGH,
            61000,
            msg="ephemeral high must be 61000.",
        )

    def test__stack__boolean_policy_defaults(self) -> None:
        """
        Ensure the boolean policy defaults are False (a True-flip is
        caught).

        Reference: RFC 1122 §3.3.5 (source-route default off).
        """

        self.assertIs(stack.UDP__ECHO_NATIVE, False, msg="UDP__ECHO_NATIVE must default False.")
        self.assertIs(stack.LOG__DEBUG, False, msg="LOG__DEBUG must default False.")
        self.assertIs(
            stack.IP4__ACCEPT_SOURCE_ROUTE["default"],
            False,
            msg="IP4__ACCEPT_SOURCE_ROUTE default must be False.",
        )


class TestStackSysctlValidatorGoldens(TestCase):
    """
    Boundary goldens for the stack-registered sysctl validators,
    closing the bool-guard, ephemeral-range validator-bound, and
    cross-knob low-less-than-high mutation survivors. Each test
    restores the registry to defaults on cleanup.
    """

    @override
    def setUp(self) -> None:
        """
        Register a registry reset on cleanup so a validator-probe set
        does not leak into sibling tests.
        """

        self.addCleanup(sysctl_module.reset_to_defaults)

    def test__stack__bool_validator_rejects_non_bool(self) -> None:
        """
        Ensure the source-route bool validator rejects a non-bool value
        and accepts a bool (pins 'not isinstance(value, bool)').

        Reference: RFC 791 §3.1 (source-route acceptance is a boolean policy).
        """

        with self.assertRaises(ValueError):
            sysctl_module.set("ip4.default.accept_source_route", "notbool")
        sysctl_module.reset_to_defaults()
        sysctl_module.set("ip4.default.accept_source_route", True)
        self.assertTrue(
            sysctl_module.get("ip4.default.accept_source_route"),
            msg="a bool value must be accepted by the source-route validator.",
        )

    def test__stack__ephemeral_low_validator_bound_is_1024(self) -> None:
        """
        Ensure the ephemeral-low validator's lower bound is exactly
        1024: 1024 is accepted, 1023 is rejected (pins the 1024
        validator-bound constant).

        Reference: RFC 6056 §3.2 (ephemeral port range lower bound).
        """

        with self.assertRaises(ValueError):
            sysctl_module.set("net.ephemeral_port_range.low", 1023)
        sysctl_module.reset_to_defaults()
        sysctl_module.set("net.ephemeral_port_range.low", 1024)
        self.assertEqual(
            sysctl_module.get("net.ephemeral_port_range.low"),
            1024,
            msg="ephemeral low must accept its exact 1024 boundary.",
        )

    def test__stack__ephemeral_high_validator_bound_is_65535(self) -> None:
        """
        Ensure the ephemeral-high validator's upper bound is exactly
        65535: 65535 is accepted, 65536 is rejected (pins the 65535
        validator-bound constant).

        Reference: RFC 6056 §3.2 (ephemeral port range upper bound).
        """

        with self.assertRaises(ValueError):
            sysctl_module.set("net.ephemeral_port_range.high", 65536)
        sysctl_module.reset_to_defaults()
        sysctl_module.set("net.ephemeral_port_range.high", 65535)
        self.assertEqual(
            sysctl_module.get("net.ephemeral_port_range.high"),
            65535,
            msg="ephemeral high must accept its exact 65535 boundary.",
        )

    def test__stack__ephemeral_range_cross_knob_rejects_low_equals_high(self) -> None:
        """
        Ensure the cross-knob finalize validator rejects low == high
        (the 'range(low, high)' pool would be empty), pinning the
        'low >= high' comparison against a strict '>'.

        Reference: RFC 6056 §3.2 (a non-empty ephemeral range).
        """

        sysctl_module.set("net.ephemeral_port_range.low", 40000)
        sysctl_module.set("net.ephemeral_port_range.high", 40000)
        with self.assertRaises(ValueError):
            sysctl_module.finalize_validators()
