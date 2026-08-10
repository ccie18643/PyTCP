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
This module contains tests for the DHCPv6 DUID / IAID helpers in
'pytcp/protocols/dhcp6/dhcp6__uid.py'.

pytcp/tests/unit/protocols/dhcp6/test__dhcp6__uid.py

ver 3.0.10
"""

from typing import override
from unittest import TestCase

from net_addr import MacAddress
from pytcp.protocols.dhcp4.dhcp4__uid import build_duid_ll
from pytcp.protocols.dhcp6.dhcp6__uid import get_client_duid, get_iaid
from pytcp.stack import sysctl


class TestGetClientDuid(TestCase):
    """
    The DHCPv6 'get_client_duid' helper returns the bare host DUID for
    the Client Identifier option.
    """

    @override
    def tearDown(self) -> None:
        """
        Restore every registered knob to its default so a sysctl mutated
        by a sibling test does not leak into the next test.
        """

        sysctl.reset_to_defaults()
        super().tearDown()

    def test__get_client_duid__empty_sysctl_derives_duid_ll(self) -> None:
        """
        Ensure the bare DUID falls back to the MAC-derived DUID-LL when the
        'dhcp.duid' sysctl is empty.

        Reference: RFC 8415 §11 (DUID; client SHOULD derive from a stable identifier).
        """

        mac = MacAddress("02:00:00:00:00:07")

        self.assertEqual(
            get_client_duid(mac),
            build_duid_ll(mac),
            msg="Empty 'dhcp.duid' must fall back to the MAC-derived DUID-LL.",
        )

    def test__get_client_duid__is_bare_duid_not_rfc4361_wrapper(self) -> None:
        """
        Ensure the Client Identifier DUID is the bare DUID (no RFC 4361
        type=0xff + IAID prefix that the DHCPv4 client emits).

        Reference: RFC 8415 §21.2 (Client Identifier carries the bare DUID).
        """

        duid = get_client_duid(MacAddress("02:00:00:00:00:07"))

        self.assertEqual(duid[0:2], b"\x00\x03", msg="A DUID-LL must begin with DUID-Type 3.")
        self.assertNotEqual(duid[0:1], b"\xff", msg="The DHCPv6 Client Identifier must not be RFC 4361-wrapped.")

    def test__get_client_duid__honours_sysctl_override(self) -> None:
        """
        Ensure an operator-supplied 'dhcp.duid' override is used verbatim,
        shared with the DHCPv4 client's DUID.

        Reference: RFC 8415 §11 (client MAY use an externally-configured DUID).
        """

        sysctl.set("dhcp.duid", "00:03:00:01:02:00:00:00:00:09")

        self.assertEqual(
            get_client_duid(MacAddress("02:00:00:00:00:07")),
            bytes.fromhex("000300010200000000 09".replace(" ", "")),
            msg="A non-empty 'dhcp.duid' override must be used verbatim.",
        )


class TestGetIaid(TestCase):
    """
    The DHCPv6 'get_iaid' helper returns the IAID as a 32-bit integer for
    the IA_NA option.
    """

    def test__get_iaid__default_is_zero(self) -> None:
        """
        Ensure the default interface_idx=0 IAID is the integer 0.

        Reference: RFC 8415 §21.4 (IA_NA IAID is a 4-octet identifier).
        """

        self.assertEqual(get_iaid(), 0, msg="IAID for interface_idx=0 must be 0.")

    def test__get_iaid__custom_interface_idx(self) -> None:
        """
        Ensure a custom interface index is returned as its integer value.

        Reference: RFC 8415 §21.4 (IA_NA IAID is locally significant but stable).
        """

        self.assertEqual(get_iaid(interface_idx=0x12345678), 0x12345678, msg="IAID must equal the interface index.")
