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
Module contains tests for the DHCPv4 protocol error classes.

net_proto/tests/unit/protocols/dhcp4/test__dhcp4__errors.py

ver 3.0.9
"""

from unittest import TestCase

from net_proto.lib.errors import PacketIntegrityError, PacketSanityError
from net_proto.protocols.dhcp4.dhcp4__errors import (
    Dhcp4IntegrityError,
    Dhcp4SanityError,
)


class TestDhcp4Errors(TestCase):
    """
    The DHCPv4 protocol error-class hierarchy and message-prefix tests.
    """

    def test__dhcp4__integrity_error__derives_from_packet_integrity_error(self) -> None:
        """
        Ensure 'Dhcp4IntegrityError' subclasses the generic
        'PacketIntegrityError' base class.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertTrue(
            issubclass(Dhcp4IntegrityError, PacketIntegrityError),
            msg="Dhcp4IntegrityError must derive from PacketIntegrityError.",
        )

    def test__dhcp4__integrity_error__prepends_dhcpv4_prefix(self) -> None:
        """
        Ensure 'Dhcp4IntegrityError' prepends the '[DHCPv4] ' protocol tag
        to the error message.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        error = Dhcp4IntegrityError("Bad option length.")
        self.assertEqual(
            str(error),
            "[INTEGRITY ERROR][DHCPv4] Bad option length.",
            msg="Dhcp4IntegrityError must prepend '[DHCPv4] ' to the message.",
        )

    def test__dhcp4__sanity_error__derives_from_packet_sanity_error(self) -> None:
        """
        Ensure 'Dhcp4SanityError' subclasses the generic 'PacketSanityError'
        base class.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertTrue(
            issubclass(Dhcp4SanityError, PacketSanityError),
            msg="Dhcp4SanityError must derive from PacketSanityError.",
        )

    def test__dhcp4__sanity_error__prepends_dhcpv4_prefix(self) -> None:
        """
        Ensure 'Dhcp4SanityError' prepends the '[DHCPv4] ' protocol tag
        to the error message.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        error = Dhcp4SanityError("Unexpected field value.")
        self.assertEqual(
            str(error),
            "[SANITY ERROR][DHCPv4] Unexpected field value.",
            msg="Dhcp4SanityError must prepend '[DHCPv4] ' to the message.",
        )
