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
Per-interface 'arp.*' sysctl overrides — the multi-interface
runtime that shipped with commit e5dc77f5 (2026-05-23) gains
its operator-facing knob namespace here. Phase 1 of the
plan at 'docs/refactor/sysctl_per_interface.md'.

pytcp/tests/integration/protocols/arp/test__arp__sysctl_per_interface.py

ver 3.0.9
"""

from typing import override
from unittest.mock import Mock

from net_addr import Ip4Address, Ip4IfAddr, MacAddress
from net_proto import ArpOperation
from net_proto.lib.packet_rx import PacketRx
from pytcp.stack import sysctl as sysctl_module
from pytcp.tests.lib.arp_testcase import (
    HOST_A__IP4_ADDRESS,
    HOST_A__MAC_ADDRESS,
    MAC__BROADCAST,
    STACK__IP4_HOST,
    STACK__MAC_ADDRESS,
    ArpTestCase,
)

# Names assigned to the two test interfaces. Picked
# distinctively so a missing per-iface read can't accidentally
# pass via the 'default' template.
_IFNAME_A = "ptap_a"
_IFNAME_B = "ptap_b"

# Second-interface addressing — uses a DIFFERENT subnet so the
# 'arp.accept' off-subnet check distinguishes the two
# interfaces.
_HANDLER_B__MAC = MacAddress("02:00:00:00:00:08")
_HANDLER_B__IP4_HOST = Ip4IfAddr("172.16.5.8/24")
_HANDLER_B__IP4_ADDRESS = _HANDLER_B__IP4_HOST.address
# A peer on tap_b's local subnet.
_PEER_B__MAC = MacAddress("02:00:00:00:00:51")
_PEER_B__IP4 = Ip4Address("172.16.5.51")


class TestArpSysctlPerInterface(ArpTestCase):
    """
    The 'arp.<ifname>.<field>' per-interface override surface.
    Two L2 interfaces — 'ptap_a' (the boot interface) and
    'ptap_b' (added via '_add_interface') — exercise the
    runtime read path on each side.
    """

    @override
    def setUp(self) -> None:
        """
        Build the two-interface fixture and pin each handler's
        '_interface_name' so the per-iface sysctl reads can
        address them.
        """

        super().setUp()
        # Name the boot interface.
        self._packet_handler._interface_name = _IFNAME_A
        # Install a second L2 interface with its own subnet and
        # cache, then name it.
        self._added = self._add_interface(
            mac_address=_HANDLER_B__MAC,
            ip4_host=_HANDLER_B__IP4_HOST,
            arp_entries={},
        )
        self._added.handler._interface_name = _IFNAME_B

    def _drive_boot_rx(self, frame: bytes, /) -> list[bytes]:
        """
        Feed 'frame' into the boot interface and return only
        the frames it produced in response — mirrors what
        'AddedInterface.drive_rx' does for the added one.
        """

        before = len(self._frames_tx)
        self._packet_handler._phrx_ethernet(PacketRx(frame))
        return list(self._frames_tx[before:])

    def test__arp__sysctl__ignore_kill_switch_scoped_to_one_iface(self) -> None:
        """
        Ensure setting 'arp.<ifname_a>.ignore = 8' suppresses
        the ARP Reply on interface A only — interface B
        continues to honour the 'default' template (mode 1)
        and emits its Reply. Pins the per-interface read path
        for the 'arp.ignore' kill-switch.

        Reference: Linux net.ipv4.conf.<iface>.arp_ignore (mode 8 kill-switch).
        """

        sysctl_module.set(f"arp.{_IFNAME_A}.ignore", 8)
        try:
            request_a = ArpTestCase._build_arp_frame(
                ethernet_dst=MAC__BROADCAST,
                ethernet_src=HOST_A__MAC_ADDRESS,
                arp_oper=ArpOperation.REQUEST,
                arp_sha=HOST_A__MAC_ADDRESS,
                arp_spa=HOST_A__IP4_ADDRESS,
                arp_tpa=STACK__IP4_HOST.address,
            )
            tx_a = self._drive_boot_rx(request_a)
            self.assertEqual(
                tx_a,
                [],
                msg=(
                    "Interface A has 'arp.ptap_a.ignore=8' set; the kill switch "
                    "must suppress the ARP Reply on this interface."
                ),
            )

            request_b = ArpTestCase._build_arp_frame(
                ethernet_dst=MAC__BROADCAST,
                ethernet_src=_PEER_B__MAC,
                arp_oper=ArpOperation.REQUEST,
                arp_sha=_PEER_B__MAC,
                arp_spa=_PEER_B__IP4,
                arp_tpa=_HANDLER_B__IP4_ADDRESS,
            )
            tx_b = self._added.drive_rx(frame=request_b)
            self.assertEqual(
                len(tx_b),
                1,
                msg=(
                    "Interface B inherits the 'arp.default.ignore=1' template; "
                    "an inbound Request for its IPv4 must elicit one Reply."
                ),
            )
        finally:
            sysctl_module.reset_to_defaults()

    def test__arp__sysctl__accept_off_subnet_scoped_to_one_iface(self) -> None:
        """
        Ensure 'arp.<ifname_b>.accept = 1' admits an
        off-subnet sender's cache learn on interface B
        without affecting interface A. Pins the per-interface
        read path for 'arp.accept'.

        Reference: Linux net.ipv4.conf.<iface>.arp_accept (mode 1 admits off-subnet).
        """

        # Off-subnet relative to BOTH interfaces' subnets.
        off_subnet_ip = Ip4Address("203.0.113.42")
        off_subnet_mac = MacAddress("02:00:00:00:00:cc")

        sysctl_module.set(f"arp.{_IFNAME_B}.accept", 1)
        try:
            # Off-subnet ARP Reply addressed at tap_a's MAC —
            # default 'arp.accept=0' must reject the cache
            # learn even though the Ethernet dst is unicast
            # to us.
            reply_a = ArpTestCase._build_arp_frame(
                ethernet_dst=STACK__MAC_ADDRESS,
                ethernet_src=off_subnet_mac,
                arp_oper=ArpOperation.REPLY,
                arp_sha=off_subnet_mac,
                arp_spa=off_subnet_ip,
                arp_tha=STACK__MAC_ADDRESS,
                arp_tpa=STACK__IP4_HOST.address,
            )
            self._drive_boot_rx(reply_a)
            assert self._packet_handler._arp_cache is not None
            add_entry_a = self._packet_handler._arp_cache.add_entry
            assert isinstance(add_entry_a, Mock)
            add_entry_a.assert_not_called()

            # Same off-subnet Reply addressed at tap_b's MAC —
            # the per-iface 'accept=1' must admit the learn.
            reply_b = ArpTestCase._build_arp_frame(
                ethernet_dst=_HANDLER_B__MAC,
                ethernet_src=off_subnet_mac,
                arp_oper=ArpOperation.REPLY,
                arp_sha=off_subnet_mac,
                arp_spa=off_subnet_ip,
                arp_tha=_HANDLER_B__MAC,
                arp_tpa=_HANDLER_B__IP4_ADDRESS,
            )
            self._added.drive_rx(frame=reply_b)
            assert self._added.handler._arp_cache is not None
            add_entry_b = self._added.handler._arp_cache.add_entry
            assert isinstance(add_entry_b, Mock)
            add_entry_b.assert_called_once_with(
                ip4_address=off_subnet_ip,
                mac_address=off_subnet_mac,
            )
        finally:
            sysctl_module.reset_to_defaults()

    def test__arp__sysctl__default_slot_is_template_for_unnamed_iface(self) -> None:
        """
        Ensure writing 'arp.default.ignore = 8' affects every
        interface that has no per-iface override — both
        interfaces in the fixture observe the template
        change. The 'default' slot is the operator's
        "apply to every interface that hasn't opted out"
        knob (Linux 'net.ipv4.conf.default.<knob>' parity).

        Reference: Linux net.ipv4.conf.default.arp_ignore (template for new ifaces).
        """

        sysctl_module.set("arp.default.ignore", 8)
        try:
            request_a = ArpTestCase._build_arp_frame(
                ethernet_dst=MAC__BROADCAST,
                ethernet_src=HOST_A__MAC_ADDRESS,
                arp_oper=ArpOperation.REQUEST,
                arp_sha=HOST_A__MAC_ADDRESS,
                arp_spa=HOST_A__IP4_ADDRESS,
                arp_tpa=STACK__IP4_HOST.address,
            )
            request_b = ArpTestCase._build_arp_frame(
                ethernet_dst=MAC__BROADCAST,
                ethernet_src=_PEER_B__MAC,
                arp_oper=ArpOperation.REQUEST,
                arp_sha=_PEER_B__MAC,
                arp_spa=_PEER_B__IP4,
                arp_tpa=_HANDLER_B__IP4_ADDRESS,
            )
            tx_a = self._drive_boot_rx(request_a)
            tx_b = self._added.drive_rx(frame=request_b)
            self.assertEqual(
                tx_a,
                [],
                msg="Default-slot 'ignore=8' must apply to interface A (no per-iface override).",
            )
            self.assertEqual(
                tx_b,
                [],
                msg="Default-slot 'ignore=8' must apply to interface B (no per-iface override).",
            )
        finally:
            sysctl_module.reset_to_defaults()

    def test__arp__sysctl__base_key_write_is_rejected(self) -> None:
        """
        Ensure writing the bare base key 'arp.ignore' (no
        '<ifname>' segment) is rejected after the
        interface-scope migration — operators MUST address a
        specific interface or the '"default"' template. Pins
        the §4.4 contract that the bare key alone is no longer
        ambiguous-write surface.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(KeyError) as ctx:
            sysctl_module.set("arp.ignore", 2)
        self.assertIn(
            "arp.ignore",
            str(ctx.exception),
            msg="The bare-base-key rejection must surface the offending key.",
        )

    def test__arp__sysctl__unused_per_iface_slot_persists_across_reset_only(self) -> None:
        """
        Ensure setting a per-iface slot for an interface name
        that doesn't currently exist persists (pre-attach
        config; matches Linux), and 'reset_to_defaults'
        clears it. The plan's §8 Q1 decision codified.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        sysctl_module.set("arp.future_iface.ignore", 8)
        try:
            self.assertEqual(
                sysctl_module.get("arp.future_iface.ignore"),
                8,
                msg="Pre-attach config must persist on a non-existent ifname slot.",
            )
        finally:
            sysctl_module.reset_to_defaults()
        # After reset, the slot is gone — the read falls back
        # to the 'default' template (mode 1).
        self.assertEqual(
            sysctl_module.get("arp.future_iface.ignore"),
            1,
            msg="reset_to_defaults must clear every per-iface slot.",
        )
