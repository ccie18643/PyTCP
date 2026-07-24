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
This module contains tests for the DHCPv4 lease cache —
the RFC 2131 §3.2 / §4.4.2 cached-lease persistence layer
that feeds the INIT-REBOOT fast-path on the next boot.

pytcp/tests/unit/protocols/dhcp4/test__dhcp4__lease_cache.py

ver 3.0.9
"""

import json
import os
import tempfile
import time
from typing import override
from unittest import TestCase
from unittest.mock import patch

from net_addr import Ip4Address, Ip4IfAddr, Ip4Mask, Ip4Network, MacAddress
from pytcp.protocols.dhcp4.dhcp4__client import Dhcp4Lease
from pytcp.protocols.dhcp4.dhcp4__lease_cache import (
    delete_cached_lease,
    read_cached_lease,
    write_cached_lease,
)


def _make_lease(
    *,
    address: str = "192.168.1.145",
    mask: str = "255.255.255.0",
    gateway: str | None = "192.168.1.1",
    gateway_mac: str | None = None,
    server_id: str = "192.168.1.1",
    lease_time__sec: int = 3600,
    acquired_at_monotonic: float = 100.0,
    t1_override: int | None = None,
    t2_override: int | None = None,
) -> Dhcp4Lease:
    """
    Build a canonical Dhcp4Lease for the cache round-trip tests.
    Defaults match a typical residential DHCP scenario.
    """

    ip4_host = Ip4IfAddr((Ip4Address(address), Ip4Mask(mask)))
    return Dhcp4Lease(
        ip4_host=ip4_host,
        gateway=Ip4Address(gateway) if gateway is not None else None,
        lease_time__sec=lease_time__sec,
        server_id=Ip4Address(server_id),
        acquired_at_monotonic=acquired_at_monotonic,
        gateway_mac=MacAddress(gateway_mac) if gateway_mac is not None else None,
        t1_override=t1_override,
        t2_override=t2_override,
    )


class _CacheFixture(TestCase):
    """
    Shared fixture — temp directory + canonical cache path.
    """

    @override
    def setUp(self) -> None:
        """
        Stand up a fresh 'tempfile.TemporaryDirectory' and a
        '<dir>/dhcp4_lease' path for each test; silence the
        'log' channel inside the cache module so warning lines
        do not leak to stdout.
        """

        self._tmpdir = self.enterContext(tempfile.TemporaryDirectory())
        self._path = os.path.join(self._tmpdir, "dhcp4_lease")
        self.enterContext(patch("pytcp.protocols.dhcp4.dhcp4__lease_cache.log"))


class TestDhcp4LeaseCacheRoundTrip(_CacheFixture):
    """
    The DHCPv4 lease cache round-trip tests.
    """

    def test__cache__write_then_read_returns_equal_lease(self) -> None:
        """
        Ensure 'write_cached_lease' followed by
        'read_cached_lease' returns a Dhcp4Lease with the same
        address, mask, gateway, server-id, and lease-time as
        the original. The 'acquired_at_monotonic' is anchored
        against the cache's wall-clock age rather than copied,
        so it is verified separately via the
        'lease_time - age = remaining' invariant.

        Reference: RFC 2131 §3.2 (cached lease reuse).
        """

        original = _make_lease()
        write_cached_lease(self._path, original)
        read = read_cached_lease(self._path)

        self.assertIsNotNone(read, msg="Cache round-trip must return a Dhcp4Lease, not None.")
        assert read is not None  # mypy narrow
        self.assertEqual(
            read.ip4_host.address,
            original.ip4_host.address,
            msg="Round-trip address must equal the original.",
        )
        self.assertEqual(
            read.ip4_host.network.mask,
            original.ip4_host.network.mask,
            msg="Round-trip subnet mask must equal the original.",
        )
        self.assertEqual(
            read.gateway,
            original.gateway,
            msg="Round-trip gateway must equal the original.",
        )
        self.assertEqual(
            read.server_id,
            original.server_id,
            msg="Round-trip server_id must equal the original.",
        )
        self.assertEqual(
            read.lease_time__sec,
            original.lease_time__sec,
            msg="Round-trip lease_time__sec must equal the original.",
        )

    def test__cache__round_trip_with_no_gateway(self) -> None:
        """
        Ensure a lease with no gateway round-trips cleanly — the
        cache must serialise 'gateway: null' and the reader must
        construct an Ip4IfAddr whose 'gateway' attribute is None.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        original = _make_lease(gateway=None)
        write_cached_lease(self._path, original)
        read = read_cached_lease(self._path)

        assert read is not None
        self.assertIsNone(
            read.gateway,
            msg="Round-trip gateway-less lease must read back with gateway=None.",
        )

    def test__cache__round_trip_persists_gateway_mac(self) -> None:
        """
        Ensure a lease whose 'gateway_mac' is explicitly set
        round-trips the MAC across the JSON serialisation. The
        RFC 4436 DNAv4 fast-path depends on this field being
        present on the next-boot reader.

        Reference: RFC 4436 §4 (DNAv4 unicast-ARP probe target).
        """

        original = _make_lease(gateway_mac="02:00:00:00:00:01")
        write_cached_lease(self._path, original)
        read = read_cached_lease(self._path)

        assert read is not None
        self.assertEqual(
            read.gateway_mac,
            MacAddress("02:00:00:00:00:01"),
            msg="Round-trip gateway_mac must equal the explicit value passed to the writer.",
        )

    def test__cache__round_trip_with_no_gateway_mac(self) -> None:
        """
        Ensure a lease whose 'gateway_mac' is None (e.g. first
        boot, gateway not yet resolved by ARP) serialises as
        'gateway_mac: null' and reads back as None. DNAv4 is
        gated on a non-None 'gateway_mac' so the fast-path
        simply does not engage in this case.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        original = _make_lease(gateway_mac=None)
        with patch(
            "pytcp.protocols.dhcp4.dhcp4__lease_cache._resolve_gateway_mac",
            return_value=None,
        ):
            write_cached_lease(self._path, original)
        read = read_cached_lease(self._path)

        assert read is not None
        self.assertIsNone(
            read.gateway_mac,
            msg="Lease with no gateway_mac must read back with gateway_mac=None.",
        )

    def test__cache__round_trip_persists_classless_static_routes(self) -> None:
        """
        Ensure the lease's Classless Static Routes (option 121)
        survive a write / read round-trip.

        Reference: RFC 3442 (Classless Static Route option).
        """

        original = Dhcp4Lease(
            ip4_host=Ip4IfAddr((Ip4Address("10.0.21.17"), Ip4Mask("255.255.255.0"))),
            lease_time__sec=3600,
            server_id=Ip4Address("10.0.21.1"),
            acquired_at_monotonic=100.0,
            classless_static_routes=[
                (Ip4Network("0.0.0.0/0"), Ip4Address("10.0.21.1")),
                (Ip4Network("192.168.0.0/24"), Ip4Address("10.0.21.2")),
            ],
        )
        write_cached_lease(self._path, original)
        read = read_cached_lease(self._path)

        assert read is not None
        self.assertEqual(
            read.classless_static_routes,
            [
                (Ip4Network("0.0.0.0/0"), Ip4Address("10.0.21.1")),
                (Ip4Network("192.168.0.0/24"), Ip4Address("10.0.21.2")),
            ],
            msg="Classless static routes must survive the cache round-trip.",
        )

    def test__cache__round_trip_with_no_classless_static_routes(self) -> None:
        """
        Ensure a lease without Classless Static Routes reads back with
        classless_static_routes=None (pre-Phase-7 cache compatibility).

        Reference: RFC 3442 (Classless Static Route option).
        """

        original = _make_lease()
        write_cached_lease(self._path, original)
        read = read_cached_lease(self._path)

        assert read is not None
        self.assertIsNone(
            read.classless_static_routes,
            msg="A lease with no option-121 routes must read back as None.",
        )


class TestDhcp4LeaseCacheReadFailures(_CacheFixture):
    """
    The DHCPv4 lease cache defensive-read tests — every failure
    mode that should return None rather than raise.
    """

    def test__cache__missing_file_returns_none(self) -> None:
        """
        Ensure 'read_cached_lease' on a path that does not exist
        returns None silently. The caller (Dhcp4Client.__init__)
        treats None as "no usable cache; start in INIT".

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertIsNone(
            read_cached_lease(self._path),
            msg="Missing cache file must read as None, not raise FileNotFoundError.",
        )

    def test__cache__empty_path_returns_none(self) -> None:
        """
        Ensure 'read_cached_lease' on the empty string returns
        None without touching the filesystem. The sysctl default
        is empty = "in-memory only; never persist"; the read path
        is the gate that enforces this.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertIsNone(
            read_cached_lease(""),
            msg="Empty path must short-circuit to None.",
        )

    def test__cache__malformed_json_returns_none(self) -> None:
        """
        Ensure a cache file containing invalid JSON reads as
        None rather than raising — a corrupted cache from a
        prior crash must not block boot.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with open(self._path, "w") as fh:
            fh.write("{not valid json")

        self.assertIsNone(
            read_cached_lease(self._path),
            msg="Malformed cache file must read as None.",
        )

    def test__cache__unknown_version_returns_none(self) -> None:
        """
        Ensure a cache file with a 'version' the reader does not
        know rejects cleanly — an older PyTCP binary must not
        try to consume a cache written by a newer version.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with open(self._path, "w") as fh:
            json.dump({"version": 999, "address": "1.2.3.4"}, fh)

        self.assertIsNone(
            read_cached_lease(self._path),
            msg="Cache file with unknown version must read as None.",
        )

    def test__cache__expired_lease_returns_none(self) -> None:
        """
        Ensure a cache whose lease has expired by wall-clock time
        reads as None. INIT-REBOOT applies only to a "previously
        allocated network address" that is still within its
        lease duration.

        Reference: RFC 2131 §4.4.2 (INIT-REBOOT requires unexpired lease).
        """

        # Write a lease then rewrite the file with an
        # 'acquired_at_wall' from before the lease started.
        original = _make_lease(lease_time__sec=3600)
        write_cached_lease(self._path, original)
        with open(self._path, "r") as fh:
            payload = json.load(fh)
        payload["acquired_at_wall"] = time.time() - 7200  # 2 hours ago
        with open(self._path, "w") as fh:
            json.dump(payload, fh)

        self.assertIsNone(
            read_cached_lease(self._path),
            msg="Cache whose lease has expired by wall-clock time must read as None.",
        )

    def test__cache__missing_field_returns_none(self) -> None:
        """
        Ensure a cache file missing a mandatory field
        (e.g. 'server_id') reads as None. Structural defects in
        the cache must not propagate to the FSM.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with open(self._path, "w") as fh:
            json.dump(
                {
                    "version": 1,
                    "address": "10.0.0.1",
                    "mask": "255.255.255.0",
                    "gateway": None,
                    # Missing 'server_id', 'lease_time__sec', 'acquired_at_wall'.
                },
                fh,
            )

        self.assertIsNone(
            read_cached_lease(self._path),
            msg="Cache with missing fields must read as None.",
        )

    def test__cache__non_object_root_returns_none(self) -> None:
        """
        Ensure a JSON file whose root is a list / scalar rather
        than an object reads as None — defensive against
        accidental corruption from operator tinkering.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with open(self._path, "w") as fh:
            json.dump([1, 2, 3], fh)

        self.assertIsNone(
            read_cached_lease(self._path),
            msg="Cache whose root is not an object must read as None.",
        )


class TestDhcp4LeaseCacheWriteSemantics(_CacheFixture):
    """
    The DHCPv4 lease cache write-side semantic tests.
    """

    def test__cache__empty_path_write_is_noop(self) -> None:
        """
        Ensure 'write_cached_lease' on the empty string is a
        no-op — the sysctl default is empty = "in-memory only;
        never persist".

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        write_cached_lease("", _make_lease())
        # Test fixture's tempdir is still empty; the canonical
        # cache filename was never created.
        self.assertFalse(
            os.path.exists(self._path),
            msg="Empty path must short-circuit write_cached_lease without touching the filesystem.",
        )

    def test__cache__write_overwrites_prior_cache(self) -> None:
        """
        Ensure a second write to the same path replaces the
        prior content. The reader sees the most recent lease,
        not a concatenation or a stale value.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        write_cached_lease(self._path, _make_lease(address="192.168.1.10"))
        write_cached_lease(self._path, _make_lease(address="192.168.1.20"))
        read = read_cached_lease(self._path)

        assert read is not None
        self.assertEqual(
            read.ip4_host.address,
            Ip4Address("192.168.1.20"),
            msg="Second write must replace the prior cache.",
        )


class TestDhcp4LeaseCacheDelete(_CacheFixture):
    """
    The DHCPv4 lease cache delete-side semantic tests.
    """

    def test__cache__delete_removes_existing_file(self) -> None:
        """
        Ensure 'delete_cached_lease' removes an existing cache
        file. The NAK / lease-expiry paths use it to invalidate
        the cache so the next boot starts in INIT, not in
        INIT-REBOOT.

        Reference: RFC 2131 §4.4.2 (NAK invalidates the remembered address).
        """

        write_cached_lease(self._path, _make_lease())
        self.assertTrue(
            os.path.exists(self._path),
            msg="Pre-condition: cache file must exist after write.",
        )

        delete_cached_lease(self._path)

        self.assertFalse(
            os.path.exists(self._path),
            msg="delete_cached_lease must remove the cache file.",
        )

    def test__cache__delete_missing_file_is_noop(self) -> None:
        """
        Ensure 'delete_cached_lease' on a missing path is a
        silent no-op — a NAK on a fresh boot (no cache file
        yet) must not raise FileNotFoundError.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        # No write — file does not exist.
        delete_cached_lease(self._path)  # must not raise.

    def test__cache__delete_empty_path_is_noop(self) -> None:
        """
        Ensure 'delete_cached_lease' on the empty string is a
        silent no-op — the sysctl default disables caching,
        and invalidation paths should never touch the filesystem
        in that mode.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        delete_cached_lease("")  # must not raise.


class TestDhcp4LeaseCacheT1T2Overrides(_CacheFixture):
    """
    Phase #2.E — cache format v3 round-trips the server-supplied
    Renewal (option 58) and Rebinding (option 59) Time values
    so the next-boot lifecycle can honour them without
    re-asking the server.
    """

    def test__cache__round_trip_persists_t1_and_t2_overrides(self) -> None:
        """
        Ensure a lease whose 't1_override' / 't2_override' are
        set round-trips both values across the JSON
        serialisation. The next-boot INIT-REBOOT / DNAv4 path
        depends on these being present on the reader's lease.

        Reference: RFC 2132 §9.7 / §9.8 (T1 / T2 carried in ACK options).
        """

        original = _make_lease(t1_override=1200, t2_override=2100)
        write_cached_lease(self._path, original)
        read = read_cached_lease(self._path)

        assert read is not None
        self.assertEqual(
            read.t1_override,
            1200,
            msg="Round-trip t1_override must equal the explicit value.",
        )
        self.assertEqual(
            read.t2_override,
            2100,
            msg="Round-trip t2_override must equal the explicit value.",
        )

    def test__cache__round_trip_with_no_overrides(self) -> None:
        """
        Ensure a lease whose 't1_override' / 't2_override' are
        None (server omitted options 58 / 59) serialises as JSON
        null and reads back as None on both fields. The
        DHCPv4 client then falls back to the factor-based T1 / T2
        defaults.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        original = _make_lease(t1_override=None, t2_override=None)
        write_cached_lease(self._path, original)
        read = read_cached_lease(self._path)

        assert read is not None
        self.assertIsNone(
            read.t1_override,
            msg="Lease without T1 override must read back as None.",
        )
        self.assertIsNone(
            read.t2_override,
            msg="Lease without T2 override must read back as None.",
        )
