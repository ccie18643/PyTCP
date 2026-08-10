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
This module contains tests for the IGMP protocol error classes.

net_proto/tests/unit/protocols/igmp/test__igmp__errors.py

ver 3.0.9
"""

from unittest import TestCase

from net_proto.lib.errors import PacketIntegrityError, PacketSanityError
from net_proto.protocols.igmp.igmp__errors import (
    IgmpIntegrityError,
    IgmpSanityError,
)


class TestIgmpErrors(TestCase):
    """
    The IGMP protocol error-class tests.
    """

    def test__igmp__integrity_error__prefix(self) -> None:
        """
        Ensure IgmpIntegrityError renders the canonical
        '[INTEGRITY ERROR][IGMP] <message>' prefix and subclasses
        the shared PacketIntegrityError so existing drop-path catches
        keep working.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        error = IgmpIntegrityError("bad frame")

        self.assertIsInstance(error, PacketIntegrityError)
        self.assertEqual(str(error), "[INTEGRITY ERROR][IGMP] bad frame")

    def test__igmp__sanity_error__prefix(self) -> None:
        """
        Ensure IgmpSanityError renders the canonical
        '[SANITY ERROR][IGMP] <message>' prefix and subclasses the
        shared PacketSanityError.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        error = IgmpSanityError("bad field")

        self.assertIsInstance(error, PacketSanityError)
        self.assertEqual(str(error), "[SANITY ERROR][IGMP] bad field")
