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
This module contains packaging tests asserting the built PyTCP-net_proto
and PyTCP-net_addr wheels ship their full package payload — in particular
that net_proto's subpackages (every protocol family + options) are
included. The original defect this test pins was a stale namespace-only
discovery glob; PyTCP migrated to regular packages (empty
`__init__.py` everywhere) but the test still gates the wheel-discovery
glob.

pytcp/tests/unit/test__packaging__dist_wheels.py

ver 3.0.8
"""

import shutil
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path
from typing import ClassVar, override
from unittest import TestCase

_REPO_ROOT = Path(__file__).resolve().parents[5]
_PKG_NET_PROTO = _REPO_ROOT / "packages" / "net_proto"
_PKG_NET_ADDR = _REPO_ROOT / "packages" / "net_addr"
_PKG_PYTCP = _REPO_ROOT / "packages" / "pytcp"


def _build_wheel_payload(project_dir: Path, /) -> set[str]:
    """
    Build the project's wheel offline and return the set of
    package '.py' paths it contains (excluding '*.dist-info/').
    Offline + deterministic: '--no-isolation' uses the venv's
    already-installed setuptools/wheel, so no network is touched.
    """

    # setuptools' bdist_wheel reuses a stale 'build/lib' tree; wipe
    # it BEFORE building so every call is a fresh, faithful build
    # (without this the test passes vacuously). 'build/' is pure
    # scratch — the editable install resolves via a site-packages
    # '.pth', never the in-tree build/ or *.egg-info.
    shutil.rmtree(project_dir / "build", ignore_errors=True)
    egg_info_before = {p for p in project_dir.glob("*.egg-info")}

    with tempfile.TemporaryDirectory() as outdir:
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "build",
                "--wheel",
                "--no-isolation",
                "--outdir",
                outdir,
                str(project_dir),
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode != 0:
            raise AssertionError(f"wheel build failed for {project_dir}:\n{result.stdout}\n{result.stderr}")

        wheels = list(Path(outdir).glob("*.whl"))
        if len(wheels) != 1:
            raise AssertionError(f"expected exactly one wheel for {project_dir}; got {wheels}")

        with zipfile.ZipFile(wheels[0]) as zf:
            payload = {
                name
                for name in zf.namelist()
                if name.endswith(".py") and not name.split("/", 1)[0].endswith(".dist-info")
            }
            has_py_typed = any(name.endswith("/py.typed") for name in zf.namelist())

    # Self-clean: tests must not mutate the working tree
    # (unit_testing.md §10a). Remove the scratch build/ and only
    # the *.egg-info this build newly created (a pre-existing one
    # belongs to the editable install — leave it).
    shutil.rmtree(project_dir / "build", ignore_errors=True)
    for egg in set(project_dir.glob("*.egg-info")) - egg_info_before:
        shutil.rmtree(egg, ignore_errors=True)

    payload.add("@py.typed" if has_py_typed else "@no-py.typed")
    return payload


class TestPackagingNetProtoWheel(TestCase):
    """
    The PyTCP-net_proto wheel-payload packaging tests.
    """

    _payload: ClassVar[set[str]]

    @classmethod
    @override
    def setUpClass(cls) -> None:
        """
        Build the net_proto wheel once for the whole class
        (read-only fixture; building is the expensive part).
        """

        cls._payload = _build_wheel_payload(_PKG_NET_PROTO)

    def test__net_proto__ships_subpackages(self) -> None:
        """
        Ensure the net_proto wheel ships every protocol-family
        subpackage (net_proto.protocols.*), not just the
        top-level package — the exact failure mode that left
        the umbrella PyTCP wheel non-functional before the
        package layout was reorganised.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        for prefix in (
            "net_proto/protocols/tcp/",
            "net_proto/protocols/ip6/",
            "net_proto/protocols/icmp6/",
            "net_proto/protocols/arp/",
            "net_proto/protocols/udp/",
            "net_proto/lib/",
        ):
            with self.subTest(prefix=prefix):
                self.assertTrue(
                    any(p.startswith(prefix) for p in self._payload),
                    msg=f"net_proto wheel must ship the {prefix!r} subpackage; payload is missing it.",
                )

    def test__net_proto__excludes_tests_and_ships_py_typed(self) -> None:
        """
        Ensure the net_proto wheel excludes the test tree and
        ships the PEP 561 'py.typed' marker.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertNotIn(
            True,
            {p.startswith("net_proto/tests/") for p in self._payload},
            msg="net_proto wheel must NOT ship the test tree.",
        )
        self.assertIn(
            "@py.typed",
            self._payload,
            msg="net_proto wheel must ship 'py.typed' (PEP 561).",
        )


class TestPackagingNetAddrWheel(TestCase):
    """
    The PyTCP-net_addr wheel-payload regression tests.
    """

    _payload: ClassVar[set[str]]

    @classmethod
    @override
    def setUpClass(cls) -> None:
        """
        Build the net_addr wheel once for the whole class.
        """

        cls._payload = _build_wheel_payload(_PKG_NET_ADDR)

    def test__net_addr__ships_modules_excludes_tests_with_py_typed(self) -> None:
        """
        Ensure the net_addr wheel still ships its modules, omits
        the test tree, and carries 'py.typed' — locks the
        already-shipped PyTCP-net_addr layout against regression.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertIn(
            "net_addr/ip4_address.py",
            self._payload,
            msg="net_addr wheel must ship its value-type modules.",
        )
        self.assertNotIn(
            True,
            {p.startswith("net_addr/tests/") for p in self._payload},
            msg="net_addr wheel must NOT ship the test tree.",
        )
        self.assertIn(
            "@py.typed",
            self._payload,
            msg="net_addr wheel must ship 'py.typed' (PEP 561).",
        )


class TestPackagingPytcpWheel(TestCase):
    """
    The PyTCP (umbrella -> pytcp) wheel-payload packaging tests.
    """

    _payload: ClassVar[set[str]]

    @classmethod
    @override
    def setUpClass(cls) -> None:
        """
        Build the pytcp wheel once for the whole class.
        """

        cls._payload = _build_wheel_payload(_PKG_PYTCP)

    def test__pytcp__ships_subpackages(self) -> None:
        """
        Ensure the PyTCP wheel ships every runtime / protocol
        subpackage (pytcp.runtime.*, pytcp.protocols.*) — the
        exact defect that left the historical umbrella wheel
        non-functional; this is the umbrella fix realised by
        dissolving it into the per-package pytcp dist.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        for prefix in (
            "pytcp/runtime/packet_handler/",
            "pytcp/protocols/tcp/",
            "pytcp/protocols/ip6/",
            "pytcp/socket/",
            "pytcp/stack/",
            "pytcp/lib/",
        ):
            with self.subTest(prefix=prefix):
                self.assertTrue(
                    any(p.startswith(prefix) for p in self._payload),
                    msg=f"PyTCP wheel must ship the {prefix!r} subpackage; payload is missing it.",
                )

    def test__pytcp__excludes_tests_and_ships_py_typed(self) -> None:
        """
        Ensure the PyTCP wheel excludes the test tree and ships
        the PEP 561 'py.typed' marker.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertNotIn(
            True,
            {p.startswith("pytcp/tests/") for p in self._payload},
            msg="PyTCP wheel must NOT ship the test tree.",
        )
        self.assertIn(
            "@py.typed",
            self._payload,
            msg="PyTCP wheel must ship 'py.typed' (PEP 561).",
        )
