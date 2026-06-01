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
This module contains integration tests for the ICMP-shared policy
sysctls ('icmp.error.rate_pps' and 'icmp.error.burst') that drive
the outbound-error token-bucket limiter used by both ICMPv4 and
ICMPv6.

pytcp/tests/integration/protocols/icmp/test__icmp__sysctls.py

ver 3.0.8
"""

from pytcp.protocols.icmp import icmp__constants
from pytcp.protocols.icmp.icmp__error_emitter import IcmpErrorRateLimiter
from pytcp.stack import sysctl
from pytcp.tests.lib.network_testcase import NetworkTestCase


class TestIcmpErrorSysctlDefaults(NetworkTestCase):
    """
    The ICMP-error rate-limiter sysctl default-registration tests.
    """

    def test__icmp__sysctl__error_rate_pps_default_registered(self) -> None:
        """
        Ensure 'icmp.error.rate_pps' registers with the canonical
        100 pps default used for outbound ICMP-error origination
        on both v4 and v6.

        Reference: RFC 1812 §4.3.2.8 (ICMP message rate limiting).
        Reference: RFC 4443 §2.4(f) (analogous IPv6 requirement).
        """

        self.assertEqual(
            sysctl.get("icmp.error.rate_pps"),
            100,
            msg="icmp.error.rate_pps must default to 100 pps.",
        )

    def test__icmp__sysctl__error_burst_default_registered(self) -> None:
        """
        Ensure 'icmp.error.burst' registers with the canonical
        50-token bucket size.

        Reference: RFC 1812 §4.3.2.8 (token-bucket burst cap).
        """

        self.assertEqual(
            sysctl.get("icmp.error.burst"),
            50,
            msg="icmp.error.burst must default to 50 tokens.",
        )


class TestIcmpErrorSysctlOverrides(NetworkTestCase):
    """
    The ICMP-error rate-limiter sysctl runtime-override
    write-through tests.
    """

    def test__icmp__sysctl__error_rate_pps_override_updates_attr(self) -> None:
        """
        Ensure overriding 'icmp.error.rate_pps' writes through to
        the backing 'ICMP__ERROR__RATE_PPS' module attribute that
        the rate-limiter constructor reads via qualified module
        access for the default value.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with sysctl.override("icmp.error.rate_pps", 25):
            self.assertEqual(
                icmp__constants.ICMP__ERROR__RATE_PPS,
                25,
                msg="Override must write through to ICMP__ERROR__RATE_PPS.",
            )

        self.assertEqual(
            icmp__constants.ICMP__ERROR__RATE_PPS,
            100,
            msg="Override exit must restore the registered default.",
        )

    def test__icmp__sysctl__error_burst_override_updates_attr(self) -> None:
        """
        Ensure overriding 'icmp.error.burst' writes through to the
        backing 'ICMP__ERROR__BURST' module attribute.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with sysctl.override("icmp.error.burst", 12):
            self.assertEqual(
                icmp__constants.ICMP__ERROR__BURST,
                12,
                msg="Override must write through to ICMP__ERROR__BURST.",
            )

    def test__icmp__sysctl__rate_limiter_default_construction_reads_live_value(self) -> None:
        """
        Ensure a default-constructed 'IcmpErrorRateLimiter' (no
        explicit rate_pps / burst kwargs) reads the LIVE sysctl
        values at construction time — operators configuring the
        sysctl BEFORE the limiter is built MUST see the override
        take effect on the resulting limiter instance.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with sysctl.override("icmp.error.rate_pps", 7):
            with sysctl.override("icmp.error.burst", 13):
                limiter = IcmpErrorRateLimiter()
                self.assertEqual(
                    limiter.rate_pps,
                    7,
                    msg="Limiter built under override must observe overridden rate_pps.",
                )
                self.assertEqual(
                    limiter.burst,
                    13,
                    msg="Limiter built under override must observe overridden burst.",
                )


class TestIcmpErrorSysctlValidators(NetworkTestCase):
    """
    The ICMP-error rate-limiter sysctl validator-rejection tests.
    """

    def test__icmp__sysctl__error_rate_pps_rejects_zero(self) -> None:
        """
        Ensure 'icmp.error.rate_pps' rejects zero — a zero rate
        would freeze outbound ICMP-error origination forever.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(ValueError):
            sysctl.set("icmp.error.rate_pps", 0)

    def test__icmp__sysctl__error_rate_pps_rejects_negative(self) -> None:
        """
        Ensure 'icmp.error.rate_pps' rejects a negative value.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(ValueError):
            sysctl.set("icmp.error.rate_pps", -1)

    def test__icmp__sysctl__error_burst_rejects_zero(self) -> None:
        """
        Ensure 'icmp.error.burst' rejects zero — a zero bucket
        size would block every outbound ICMP error.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(ValueError):
            sysctl.set("icmp.error.burst", 0)

    def test__icmp__sysctl__error_burst_rejects_non_int(self) -> None:
        """
        Ensure 'icmp.error.burst' rejects non-int types
        (strings, floats, booleans).

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        for bad in ("5", 5.0, True):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    sysctl.set("icmp.error.burst", bad)
