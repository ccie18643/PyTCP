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
This module contains tests pinning the lazy 'click' import contract of the
NetAddr package: importing 'net_addr' must not pull in 'click', yet the
'ClickType*' names must still resolve on first access.

net_addr/tests/unit/test__lazy_click.py

ver 3.0.8
"""

import os
import subprocess
import sys
from unittest import TestCase


def _run(script: str, /) -> subprocess.CompletedProcess[str]:
    """
    Run a one-shot Python snippet in a fresh interpreter so the
    import-side-effect observation is not polluted by modules an
    earlier test in the suite already imported.
    """

    env = {
        **os.environ,
        "PYTHONPATH": os.getcwd() + os.pathsep + os.environ.get("PYTHONPATH", ""),
    }
    return subprocess.run(
        [sys.executable, "-c", script],
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )


class TestNetAddrLazyClick(TestCase):
    """
    The NetAddr package lazy-'click' import-contract tests.
    """

    def test__net_addr__import_does_not_pull_click(self) -> None:
        """
        Ensure 'import net_addr' does not import 'click' nor the
        'net_addr.click_types' module, so the base install stays
        stdlib-only.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        result = _run("import sys, net_addr; print('click' in sys.modules, 'net_addr.click_types' in sys.modules)")

        self.assertEqual(
            result.returncode,
            0,
            msg=f"Probe interpreter must exit cleanly. stderr: {result.stderr!r}",
        )
        self.assertEqual(
            result.stdout.strip(),
            "False False",
            msg="'import net_addr' must not pull in 'click' or 'net_addr.click_types'.",
        )

    def test__net_addr__click_type_resolves_to_real_class(self) -> None:
        """
        Ensure a lazily-exposed 'ClickType*' name resolves to the
        exact class defined in 'net_addr.click_types'.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        result = _run(
            "import net_addr\n"
            "from net_addr.click_types import ClickTypeIp4Address as Real\n"
            "print(net_addr.ClickTypeIp4Address is Real)"
        )

        self.assertEqual(
            result.returncode,
            0,
            msg=f"Probe interpreter must exit cleanly. stderr: {result.stderr!r}",
        )
        self.assertEqual(
            result.stdout.strip(),
            "True",
            msg="net_addr.ClickTypeIp4Address must be the class from net_addr.click_types.",
        )

    def test__net_addr__click_type_access_triggers_click_import(self) -> None:
        """
        Ensure accessing a 'ClickType*' name imports 'click' on
        first access (not before), proving the import is deferred
        rather than dropped.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        result = _run(
            "import sys, net_addr\n"
            "before = 'click' in sys.modules\n"
            "net_addr.ClickTypeIp4Address\n"
            "after = 'click' in sys.modules\n"
            "print(before, after)"
        )

        self.assertEqual(
            result.returncode,
            0,
            msg=f"Probe interpreter must exit cleanly. stderr: {result.stderr!r}",
        )
        self.assertEqual(
            result.stdout.strip(),
            "False True",
            msg="'click' must be absent until a ClickType* name is accessed, then present.",
        )

    def test__net_addr__unknown_attribute_raises_attribute_error(self) -> None:
        """
        Ensure the lazy module '__getattr__' still raises
        'AttributeError' for an unknown name rather than masking
        the typo.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        result = _run(
            "import net_addr\n"
            "try:\n"
            "    net_addr.NoSuchSymbol\n"
            "    print('NO_ERROR')\n"
            "except AttributeError:\n"
            "    print('ATTRIBUTE_ERROR')"
        )

        self.assertEqual(
            result.returncode,
            0,
            msg=f"Probe interpreter must exit cleanly. stderr: {result.stderr!r}",
        )
        self.assertEqual(
            result.stdout.strip(),
            "ATTRIBUTE_ERROR",
            msg="Accessing an unknown net_addr attribute must raise AttributeError.",
        )
