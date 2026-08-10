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
This module contains tests for the DHCP DUID / IAID / Client
Identifier helpers in 'pytcp/protocols/dhcp4/dhcp4__uid.py'.

pytcp/tests/unit/protocols/dhcp4/test__dhcp4__uid.py

ver 3.0.10
"""

from typing import override
from unittest import TestCase

from net_addr import MacAddress
from pytcp.protocols.dhcp4.dhcp4__uid import build_client_id, build_duid_ll, get_duid, get_iaid
from pytcp.stack import sysctl


class TestBuildDuidLl(TestCase):
    """
    The 'build_duid_ll' helper produces the canonical DUID-LL byte
    sequence: 2-byte type=0x0003 + 2-byte hardware-type=0x0001
    (Ethernet) + 6-byte MAC.
    """

    def test__build_duid_ll__produces_10_bytes_for_ethernet(self) -> None:
        """
        Ensure the DUID-LL wire form is exactly 10 bytes long for
        an Ethernet 6-byte hardware address (2-byte type +
        2-byte hardware-type + 6-byte MAC).

        Reference: RFC 3315 §9.4 (DUID-LL = 2+2+L bytes where L = hardware-address length).
        """

        duid = build_duid_ll(MacAddress("02:00:00:00:00:01"))

        self.assertEqual(
            len(duid),
            10,
            msg="DUID-LL must be 10 bytes for an Ethernet MAC (2+2+6).",
        )

    def test__build_duid_ll__type_field_is_3(self) -> None:
        """
        Ensure the first two bytes carry DUID-Type = 3
        (DUID-LL) big-endian.

        Reference: RFC 3315 §9.1 (DUID-Type 3 = Link-layer address).
        """

        duid = build_duid_ll(MacAddress("02:00:00:00:00:01"))

        self.assertEqual(
            duid[0:2],
            b"\x00\x03",
            msg="DUID-LL type field MUST be 3 (big-endian uint16).",
        )

    def test__build_duid_ll__hardware_type_is_ethernet(self) -> None:
        """
        Ensure bytes 2-3 carry hardware-type = 1 (IANA "Ethernet")
        big-endian.

        Reference: RFC 3315 §9.4 (hardware-type uses IANA Hardware Types registry).
        """

        duid = build_duid_ll(MacAddress("02:00:00:00:00:01"))

        self.assertEqual(
            duid[2:4],
            b"\x00\x01",
            msg="DUID-LL hardware-type field MUST be 1 (Ethernet, IANA Hardware Types).",
        )

    def test__build_duid_ll__embeds_mac_bytes_verbatim(self) -> None:
        """
        Ensure bytes 4-9 (six bytes after the 4-byte type +
        hardware-type prefix) carry the MAC address verbatim, in
        network order.

        Reference: RFC 3315 §9.4 (DUID-LL embeds the link-layer address as-is).
        """

        mac = MacAddress("02:de:ad:be:ef:01")
        duid = build_duid_ll(mac)

        self.assertEqual(
            duid[4:],
            bytes(mac),
            msg="DUID-LL bytes 4-9 must equal the MAC address bytes.",
        )

    def test__build_duid_ll__different_macs_yield_different_duids(self) -> None:
        """
        Ensure two different MACs produce two distinct DUID-LL byte
        sequences — required for client-identity uniqueness on a
        shared subnet.

        Reference: RFC 4361 §6.1 (Client Identifier must be unique within a network).
        """

        duid_a = build_duid_ll(MacAddress("02:00:00:00:00:aa"))
        duid_b = build_duid_ll(MacAddress("02:00:00:00:00:bb"))

        self.assertNotEqual(
            duid_a,
            duid_b,
            msg="DUID-LL derived from distinct MACs must be distinct.",
        )


class TestGetIaid(TestCase):
    """
    The 'get_iaid' helper produces the 4-byte IAID — the
    Identity-Association Identifier per RFC 3315 §10.
    """

    def test__get_iaid__default_is_4_zero_bytes(self) -> None:
        """
        Ensure the default interface_idx=0 IAID is four zero bytes
        — the canonical "first interface" identifier.

        Reference: RFC 3315 §10 (IAID is a 4-octet identifier chosen by the client).
        """

        self.assertEqual(
            get_iaid(),
            b"\x00\x00\x00\x00",
            msg="IAID for interface_idx=0 must be four zero bytes.",
        )

    def test__get_iaid__custom_interface_idx_is_big_endian(self) -> None:
        """
        Ensure 'interface_idx' is encoded big-endian into the 4-byte
        IAID so multi-interface hosts can disambiguate addresses.

        Reference: RFC 3315 §10 (IAID is 4 octets; encoding is locally significant but stable).
        """

        self.assertEqual(
            get_iaid(interface_idx=0x12345678),
            b"\x12\x34\x56\x78",
            msg="IAID must encode interface_idx as big-endian uint32.",
        )


class TestBuildClientId(TestCase):
    """
    The 'build_client_id' helper produces the RFC 4361 §6.1 wire
    form: 1-byte type=0xff + 4-byte IAID + 4361 DUID.
    """

    @override
    def tearDown(self) -> None:
        """
        Restore every registered knob to its default so a knob mutated
        by a sibling test does not leak into the next test.
        """

        sysctl.reset_to_defaults()
        super().tearDown()

    def test__build_client_id__rfc4361_layout(self) -> None:
        """
        Ensure the Client Identifier is 15 bytes: 1-byte type=0xff
        prefix + 4-byte IAID + 10-byte DUID-LL (Ethernet).

        Reference: RFC 4361 §6.1 (Client Identifier — type=0xff + IAID + DUID).
        """

        cid = build_client_id(MacAddress("02:00:00:00:00:01"))

        self.assertEqual(
            len(cid),
            15,
            msg="RFC 4361 Client Identifier with DUID-LL/Ethernet must be 15 bytes (1+4+10).",
        )
        self.assertEqual(
            cid[0:1],
            b"\xff",
            msg="RFC 4361 Client Identifier type prefix MUST be 0xff.",
        )
        self.assertEqual(
            cid[1:5],
            b"\x00\x00\x00\x00",
            msg="Bytes 1-4 must carry the IAID (interface_idx=0 default).",
        )
        self.assertEqual(
            cid[5:],
            b"\x00\x03\x00\x01" + bytes(MacAddress("02:00:00:00:00:01")),
            msg="Bytes 5-14 must carry the DUID-LL (10 bytes) for the supplied MAC.",
        )


class TestGetDuid(TestCase):
    """
    The 'get_duid' helper consults the 'dhcp.duid' sysctl — an
    operator override of the auto-derived DUID-LL.
    """

    @override
    def tearDown(self) -> None:
        """
        Restore every registered knob to its default after each test
        so a sibling test does not see the leaked override.
        """

        sysctl.reset_to_defaults()
        super().tearDown()

    def test__get_duid__empty_sysctl_derives_from_mac(self) -> None:
        """
        Ensure 'get_duid' falls back to 'build_duid_ll(mac)' when
        the 'dhcp.duid' sysctl is empty (the default).

        Reference: RFC 4361 §6.1 (client SHOULD derive DUID from a stable identifier).
        """

        mac = MacAddress("02:00:00:00:00:01")

        self.assertEqual(
            get_duid(mac),
            build_duid_ll(mac),
            msg="Empty 'dhcp.duid' sysctl must fall back to MAC-derived DUID-LL.",
        )

    def test__get_duid__nonempty_sysctl_overrides_derived(self) -> None:
        """
        Ensure an operator-supplied 'dhcp.duid' takes precedence
        over the MAC-derived default.

        Reference: RFC 4361 §6.1 (client MAY use an externally-configured DUID).
        """

        sysctl.set("dhcp.duid", "0001000118b95918525400123456")
        derived = build_duid_ll(MacAddress("02:00:00:00:00:01"))

        self.assertNotEqual(
            get_duid(MacAddress("02:00:00:00:00:01")),
            derived,
            msg="Non-empty 'dhcp.duid' must override the MAC-derived DUID-LL.",
        )
        self.assertEqual(
            get_duid(MacAddress("02:00:00:00:00:01")),
            bytes.fromhex("0001000118b95918525400123456"),
            msg="Override must decode the hex string into the raw DUID bytes.",
        )

    def test__get_duid__sysctl_with_colons_normalised(self) -> None:
        """
        Ensure 'dhcp.duid' accepts the canonical colon-separated
        hex form (00:01:00:01:...) for operator-friendly
        configuration.

        Reference: RFC 4361 §6.1 (DUID representation is opaque bytes; ASCII form is a UX concern).
        """

        sysctl.set("dhcp.duid", "00:03:00:01:02:00:00:00:00:01")

        self.assertEqual(
            get_duid(MacAddress("02:00:00:00:00:42")),
            bytes.fromhex("000300010200000000 01".replace(" ", "")),
            msg="Colon-separated hex must be accepted and parsed identically to compact hex.",
        )

    def test__get_duid__sysctl_override_is_consistent_across_calls(self) -> None:
        """
        Ensure successive 'get_duid' calls with the same sysctl
        configuration produce identical bytes — required for the
        RFC 4361 stable-identity contract.

        Reference: RFC 4361 §6.1 (DUID must be stable across the client's life).
        """

        mac = MacAddress("02:00:00:00:00:01")
        first = get_duid(mac)
        second = get_duid(mac)
        third = get_duid(mac)

        self.assertEqual(
            first,
            second,
            msg="Successive get_duid calls must return identical bytes.",
        )
        self.assertEqual(
            second,
            third,
            msg="DUID must remain stable across the process's lifetime.",
        )
