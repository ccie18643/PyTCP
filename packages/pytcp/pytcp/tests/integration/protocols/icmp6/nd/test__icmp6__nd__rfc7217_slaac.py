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
Integration tests for the SLAAC consumer wiring of RFC 7217
stable opaque IIDs — nd_linux_parity §17.

The host's '_derive_ip6_host()' helper picks between the
RFC 7217 cryptographic IID and the legacy EUI-64 form based
on the 'icmp6.use_rfc7217' sysctl. Default 1 means the host
generates stable opaque IIDs that are unlinkable across
networks — the modern Linux 'addr_gen_mode = 2' equivalent.

pytcp/tests/integration/protocols/icmp6/nd/test__icmp6__nd__rfc7217_slaac.py

ver 3.0.8
"""

from typing import override

from net_addr import Ip6IfAddr, Ip6Network
from pytcp.stack import sysctl as sysctl_module
from pytcp.tests.lib.nd_testcase import NdTestCase


class TestIcmp6Nd__Rfc7217Slaac__DefaultUsesRfc7217(NdTestCase):
    """
    With 'icmp6.use_rfc7217' at the registered default (1),
    '_derive_ip6_host' returns an RFC 7217 address — not the
    EUI-64 form.
    """

    @override
    def tearDown(self) -> None:
        """
        Restore sysctl defaults so per-test overrides don't leak.
        """

        sysctl_module.reset_to_defaults()
        super().tearDown()

    def test__icmp6__nd__rfc7217__default_derives_opaque_iid(self) -> None:
        """
        Ensure '_derive_ip6_host' with the default sysctl value
        produces an address matching 'Ip6IfAddr.from_rfc7217' and
        NOT the EUI-64 form.

        Reference: RFC 7217 §5 (Algorithm Specification).
        """

        prefix = Ip6Network("2001:db8::/64")
        derived = self._packet_handler._derive_ip6_host(ip6_network=prefix)

        # Compute the EUI-64 form that the host WOULD have used
        # under the legacy default — derived address must NOT
        # equal it.
        eui64 = Ip6IfAddr.from_eui64(
            mac_address=self._packet_handler._mac_unicast,
            ip6_network=prefix,
        )

        # And it MUST equal the RFC 7217 form computed against
        # the host's secret_key.
        rfc7217 = Ip6IfAddr.from_rfc7217(
            ip6_network=prefix,
            mac_address=self._packet_handler._mac_unicast,
            secret_key=self._packet_handler._icmp6_slaac__secret_key,
        )

        self.assertNotEqual(
            derived.address,
            eui64.address,
            msg=("Default-sysctl _derive_ip6_host must NOT return the " f"EUI-64 form. Got: {derived!r}"),
        )
        self.assertEqual(
            derived.address,
            rfc7217.address,
            msg=(
                "Default-sysctl _derive_ip6_host must return the "
                f"RFC 7217 form. Got: {derived!r}, expected RFC 7217: {rfc7217!r}"
            ),
        )


class TestIcmp6Nd__Rfc7217Slaac__SysctlZeroFallsBackToEui64(NdTestCase):
    """
    With 'icmp6.use_rfc7217=0' the host reverts to legacy
    EUI-64 IID derivation (the RFC 4291 §2.5.1 form).
    """

    @override
    def tearDown(self) -> None:
        """
        Restore sysctl defaults so per-test overrides don't leak.
        """

        sysctl_module.reset_to_defaults()
        super().tearDown()

    def test__icmp6__nd__rfc7217__sysctl_zero_uses_eui64(self) -> None:
        """
        Ensure '_derive_ip6_host' with 'icmp6.use_rfc7217=0'
        returns the legacy EUI-64 form.

        Reference: RFC 4291 §2.5.1 (Modified EUI-64 IID).
        """

        prefix = Ip6Network("2001:db8::/64")

        with sysctl_module.override("icmp6.default.use_rfc7217", 0):
            derived = self._packet_handler._derive_ip6_host(ip6_network=prefix)

        eui64 = Ip6IfAddr.from_eui64(
            mac_address=self._packet_handler._mac_unicast,
            ip6_network=prefix,
        )

        self.assertEqual(
            derived.address,
            eui64.address,
            msg=("use_rfc7217=0 must return the EUI-64 form. " f"Got: {derived!r}, expected EUI-64: {eui64!r}"),
        )


class TestIcmp6Nd__Rfc7217Slaac__SecretKeyExists(NdTestCase):
    """
    Every PacketHandlerL2 instance has a 16-byte (128-bit)
    secret_key generated at init — RFC 7217 §5 requires
    ≥ 128 bits of secret.
    """

    def test__icmp6__nd__rfc7217__secret_key_initialised_to_16_bytes(self) -> None:
        """
        Ensure the packet handler's '_icmp6_slaac__secret_key'
        is exactly 16 bytes (128 bits).

        Reference: RFC 7217 §5 (secret_key SHOULD be ≥ 128 bits).
        """

        self.assertEqual(
            len(self._packet_handler._icmp6_slaac__secret_key),
            16,
            msg=(
                "PacketHandler must initialise _icmp6_slaac__secret_key to "
                f"exactly 16 bytes. Got: {len(self._packet_handler._icmp6_slaac__secret_key)}"
            ),
        )
