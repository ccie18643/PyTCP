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
Integration tests for the 'pytcp' CLI multitool.

These run the CLI's 'main' against the live IPC server (pointed at the
harness daemon via '--ipc-socket'), capturing stdout, to verify the
dispatch + connect + render path end to end for the observation
subcommands.

pytcp/tests/integration/ipc/test__ipc__cli.py

ver 3.0.10
"""

import contextlib
import io
import os
import tempfile
from typing import cast, override

from net_addr import Ip4Address, MacAddress
from pytcp.cli.__main__ import main
from pytcp.cli.cli__format import format_route_table
from pytcp.client import ClientTcpSocket
from pytcp.protocols.arp.arp__cache import ArpCache
from pytcp.protocols.icmp6.nd.nd__cache import NdCache
from pytcp.runtime.socket import AddressFamily, SocketType
from pytcp.tests.lib.ipc_control_testcase import IpcControlTestCase


class TestIpcCli(IpcControlTestCase):
    """
    The 'pytcp' CLI multitool integration tests.
    """

    @override
    def setUp(self) -> None:
        """
        Stand up the IPC fixture, then replace the harness's mocked ARP /
        ND caches with real (unstarted) caches so the 'neighbor' subcommand
        has a real entry store to read.
        """

        super().setUp()

        self._packet_handler._arp_cache = ArpCache()
        self._packet_handler._nd_cache = NdCache()

    def _run(self, *argv: str) -> str:
        """
        Run the CLI with the given args against the harness server,
        returning the captured stdout. '--ipc-socket' is a top-level
        option, so it precedes the subcommand.
        """

        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            exit_code = main(["--ipc-socket", self._socket_path, *argv])
        self.assertEqual(exit_code, 0, msg="The CLI command must exit successfully.")
        return buffer.getvalue()

    def test__cli__ss_lists_listening_socket(self) -> None:
        """
        Ensure 'pytcp ss -t -l' renders a listening TCP socket opened on
        the daemon.

        Reference: RFC 9293 §3.3.2 (LISTEN state).
        """

        sock = cast(ClientTcpSocket, self._connect().socket(AddressFamily.INET4, SocketType.STREAM))
        self.addCleanup(sock.close)
        sock.bind(("0.0.0.0", 18030))
        sock.listen(backlog=8)

        output = self._run("ss", "-t", "-l")

        self.assertIn(
            "PyTCP Socket Table",
            output,
            msg="The ss output must show the overall table header (route-style).",
        )
        self.assertIn("IPv4", output, msg="The ss output must show the IPv4 section.")
        self.assertIn(
            "tcp",
            output,
            msg="The ss output must include the TCP netid for a listening socket.",
        )
        self.assertIn(
            "0.0.0.0:18030",
            output,
            msg="The ss output must include the listening socket's local endpoint.",
        )

    def test__cli__route_minus4_matches_formatter(self) -> None:
        """
        Ensure 'pytcp route -4' renders the daemon's IPv4 routing table
        identically to the net-tools route formatter applied to the live
        IPv4 route list.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        client = self._connect()
        names = {
            ifindex: (client.link.interface(ifindex).name or f"if{ifindex}")
            for ifindex in client.link.list_interfaces()
        }
        expected = format_route_table(
            client.route.list_routes(family=AddressFamily.INET4),
            family=AddressFamily.INET4,
            interface_names=names,
        )

        output = self._run("route", "-4")

        self.assertIn(
            expected,
            output,
            msg="'route -4' output must contain the formatter's IPv4 table body verbatim.",
        )

    def test__cli__route_default_shows_both_families(self) -> None:
        """
        Ensure a bare 'pytcp route' (no family flag) shows the single
        'PyTCP Routing Table' header with both the IPv4 and IPv6 sections,
        while '-4' / '-6' narrow to one section.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        both = self._run("route")
        self.assertIn("PyTCP Routing Table", both, msg="Bare 'route' must show the overall table header.")
        self.assertIn("IPv4", both, msg="Bare 'route' must show the IPv4 section.")
        self.assertIn("IPv6", both, msg="Bare 'route' must show the IPv6 section.")

        only_ipv4 = self._run("route", "-4")
        self.assertIn("IPv4", only_ipv4, msg="'route -4' must show the IPv4 section.")
        self.assertNotIn("IPv6", only_ipv4, msg="'route -4' must not show the IPv6 section.")

        only_ipv6 = self._run("route", "-6")
        self.assertIn("IPv6", only_ipv6, msg="'route -6' must show the IPv6 section.")
        self.assertNotIn("IPv4", only_ipv6, msg="'route -6' must not show the IPv4 section.")

    def test__cli__route_add_then_list_shows_route(self) -> None:
        """
        Ensure 'pytcp route add DEST --via G --dev IF' installs the route
        into the daemon's FIB and a subsequent 'pytcp route' lists it
        with its gateway and egress interface.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        client = self._connect()
        dev = client.link.interface(self._ifindex).name or f"if{self._ifindex}"

        self._run("route", "add", "10.9.0.0/24", "--via", "10.0.1.254", "--dev", dev)

        output = self._run("route")

        self.assertIn(
            "10.9.0.0",
            output,
            msg="The added route's destination must appear in the listing.",
        )
        self.assertIn(
            "10.0.1.254",
            output,
            msg="The added route's gateway must appear in the listing.",
        )

    def test__cli__route_del_removes_route(self) -> None:
        """
        Ensure 'pytcp route del DEST' removes a previously added route from
        the daemon's FIB.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._run("route", "add", "10.9.0.0/24", "--via", "10.0.1.254")
        self.assertIn("10.9.0.0", self._run("route"), msg="Route must be present after add.")

        self._run("route", "del", "10.9.0.0/24")

        self.assertNotIn(
            "10.9.0.0",
            self._run("route"),
            msg="The deleted route must no longer appear in the listing.",
        )

    def test__cli__route_add_host_route(self) -> None:
        """
        Ensure 'pytcp route add HOST --via G' (a bare address with no
        prefix) installs a /32 host route.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._run("route", "add", "10.0.0.5", "--via", "10.0.1.1")

        output = self._run("route")

        self.assertIn(
            "10.0.0.5/32",
            output,
            msg="A bare host address must install a /32 host route (CIDR destination).",
        )
        self.assertIn("UGH", output, msg="A gateway'd host route must carry the U, G and H flags.")

    def test__cli__route_add_default_via_gateway(self) -> None:
        """
        Ensure 'pytcp route add default --via G' installs the IPv4 default
        route and 'pytcp route' lists it as the default via that gateway.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._run("route", "add", "default", "--via", "10.0.1.9")

        output = self._run("route")

        self.assertIn(
            "0.0.0.0/0",
            output,
            msg="The default route's destination must render as the prefix 0.0.0.0/0.",
        )
        self.assertIn("10.0.1.9", output, msg="The default route must be listed via the supplied gateway.")

    def test__cli__route_add_ipv6_family_inferred_from_dest(self) -> None:
        """
        Ensure 'pytcp route add P/L --via G' installs an IPv6 route with no
        explicit family flag — the family is inferred from the IPv6
        destination — and 'pytcp route -6' lists it.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._run("route", "add", "2001:db8:9::/64", "--via", "fe80::9")

        output = self._run("route", "-6")

        self.assertIn(
            "2001:db8:9::/64",
            output,
            msg="The added IPv6 route's prefix must appear in the IPv6 listing.",
        )

    def test__cli__route_add_default_without_gateway_errors(self) -> None:
        """
        Ensure 'pytcp route add default' with no '--via' is reported as an
        error rather than installing a gateway-less default.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(SystemExit) as raised:
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                main(["--ipc-socket", self._socket_path, "route", "add", "default"])

        self.assertNotEqual(
            raised.exception.code,
            0,
            msg="'add default' without --via must exit non-zero.",
        )

    def test__cli__route_add_bad_destination_errors(self) -> None:
        """
        Ensure a malformed destination is reported as an error.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(SystemExit) as raised:
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                main(["--ipc-socket", self._socket_path, "route", "add", "not-an-address", "--via", "10.0.1.1"])

        self.assertNotEqual(
            raised.exception.code,
            0,
            msg="A malformed destination must exit non-zero.",
        )

    def test__cli__output_padded_with_blank_lines(self) -> None:
        """
        Ensure command output is set off with a blank line before and
        after.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        output = self._run("route")

        self.assertTrue(output.startswith("\n"), msg="Output must start with a blank line.")
        self.assertTrue(output.endswith("\n\n"), msg="Output must end with a blank line.")

    def test__cli__sysctl_lists_entries(self) -> None:
        """
        Ensure 'pytcp sysctl' with no key lists the tunables as 'key =
        value' lines.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        output = self._run("sysctl")

        self.assertIn(
            " = ",
            output,
            msg="The sysctl listing must render 'key = value' lines.",
        )

    def test__cli__sysctl_describe_prints_description(self) -> None:
        """
        Ensure 'pytcp sysctl -d KEY' prints the knob's registered
        description, addressable by its base key or a slot-qualified
        per-interface form.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        expected = self._connect().sysctl.describe("arp.accept")
        self.assertNotEqual(
            expected,
            "",
            msg="The chosen knob must carry a description for this test to be meaningful.",
        )

        base = self._run("sysctl", "-d", "arp.accept")
        self.assertIn(expected, base, msg="'sysctl -d' must print the knob's description.")
        self.assertIn("arp.accept", base, msg="'sysctl -d' must echo the addressed key.")

        slot = self._run("sysctl", "-d", "arp.default.accept")
        self.assertIn(
            expected,
            slot,
            msg="'sysctl -d' must accept a slot-qualified key for an interface-scope knob.",
        )

    def test__cli__sysctl_describe_without_key_errors(self) -> None:
        """
        Ensure 'pytcp sysctl -d' with no key is reported as an error and
        exits non-zero rather than dumping every entry.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(SystemExit) as raised:
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                main(["--ipc-socket", self._socket_path, "sysctl", "-d"])
        self.assertNotEqual(
            raised.exception.code,
            0,
            msg="'sysctl -d' with no key must exit non-zero.",
        )

    def test__cli__sysctl_prefix_lists_namespace_subtree(self) -> None:
        """
        Ensure 'pytcp sysctl <namespace>' lists only that namespace's
        subtree and excludes unrelated namespaces.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        output = self._run("sysctl", "arp")

        self.assertIn("arp.", output, msg="The 'arp' subtree must be listed.")
        self.assertNotIn("icmp6", output, msg="An unrelated namespace must be excluded.")
        self.assertNotIn("tcp.", output, msg="An unrelated namespace must be excluded.")

    def test__cli__sysctl_interface_scope_base_lists_slots(self) -> None:
        """
        Ensure 'pytcp sysctl <interface-scope base key>' lists every
        per-interface slot of that knob rather than erroring on the
        unreadable base key.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        output = self._run("sysctl", "arp.accept")

        self.assertIn(
            "arp.default.accept = ",
            output,
            msg="An interface-scope base key must list its 'default' slot.",
        )

    def test__cli__sysctl_reads_single_flat_leaf(self) -> None:
        """
        Ensure 'pytcp sysctl <flat key>' reads exactly that key as a
        single 'key = value' line, not the surrounding subtree.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        output = self._run("sysctl", "arp.probe_num")

        self.assertIn(
            "arp.probe_num = ",
            output,
            msg="A flat leaf must read as a single 'key = value' line.",
        )
        self.assertNotIn(
            "arp.defend_interval",
            output,
            msg="A single-leaf read must not list the rest of the subtree.",
        )

    def test__cli__sysctl_unknown_key_errors(self) -> None:
        """
        Ensure 'pytcp sysctl <unknown>' that matches no registered key
        exits non-zero with a clean diagnostic rather than listing every
        entry.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(SystemExit) as raised:
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                main(["--ipc-socket", self._socket_path, "sysctl", "nope.nonexistent"])
        self.assertNotEqual(
            raised.exception.code,
            0,
            msg="An unknown sysctl key must exit non-zero.",
        )

    def test__cli__neighbor_lists_added_neighbor(self) -> None:
        """
        Ensure 'pytcp neighbor' lists a neighbour added to the interface
        cache.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._connect().neighbor.interface(self._ifindex).add(
            ip=Ip4Address("10.0.1.50"),
            mac=MacAddress("02:00:00:00:00:50"),
        )

        output = self._run("neighbor")
        dev = self._connect().link.interface(self._ifindex).name or f"if{self._ifindex}"

        self.assertIn("PyTCP Neighbor Table", output, msg="The neighbor output must show the overall header.")
        self.assertIn("10.0.1.50", output, msg="The neighbor output must list the added neighbour's address.")
        self.assertIn(
            "02:00:00:00:00:50",
            output,
            msg="The neighbor output must list the added neighbour's link-layer address.",
        )
        self.assertIn(dev, output, msg="The neighbor output must show the entry's Device (interface).")

    def test__cli__neighbor_minus4_shows_only_ipv4(self) -> None:
        """
        Ensure 'pytcp neighbor -4' shows only the IPv4 (ARP) section.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        output = self._run("neighbor", "-4")

        self.assertIn("IPv4", output, msg="'neighbor -4' must show the IPv4 section.")
        self.assertNotIn("IPv6", output, msg="'neighbor -4' must not show the IPv6 section.")

    def test__cli__neighbor_add_then_del(self) -> None:
        """
        Ensure 'pytcp neighbor add ADDR --lladdr MAC --dev IF' installs a
        static entry that 'pytcp neighbor' lists, and 'pytcp neighbor del'
        removes it.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        dev = self._connect().link.interface(self._ifindex).name or f"if{self._ifindex}"

        self._run("neighbor", "add", "10.0.1.60", "--lladdr", "02:00:00:00:00:60", "--dev", dev)

        listing = self._run("neighbor")
        self.assertIn("10.0.1.60", listing, msg="The added entry must appear in the listing.")
        self.assertIn("02:00:00:00:00:60", listing, msg="The added entry's MAC must appear.")

        self._run("neighbor", "del", "10.0.1.60", "--dev", dev)

        self.assertNotIn(
            "10.0.1.60",
            self._run("neighbor"),
            msg="The deleted entry must no longer appear.",
        )

    def test__cli__neighbor_add_bad_mac_errors(self) -> None:
        """
        Ensure a malformed link-layer address is reported as an error.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        dev = self._connect().link.interface(self._ifindex).name or f"if{self._ifindex}"
        with self.assertRaises(SystemExit) as raised:
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                main(
                    [
                        "--ipc-socket",
                        self._socket_path,
                        "neighbor",
                        "add",
                        "10.0.1.60",
                        "--lladdr",
                        "nope",
                        "--dev",
                        dev,
                    ]
                )
        self.assertNotEqual(raised.exception.code, 0, msg="A bad MAC must exit non-zero.")

    def test__cli__neighbor_flush_clears_entries(self) -> None:
        """
        Ensure 'pytcp neighbor flush' drops the neighbour entries so a
        subsequent 'pytcp neighbor' no longer lists them.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._connect().neighbor.interface(self._ifindex).add(
            ip=Ip4Address("10.0.1.50"),
            mac=MacAddress("02:00:00:00:00:50"),
        )
        self.assertIn("10.0.1.50", self._run("neighbor"), msg="The entry must be present before the flush.")

        self.assertEqual(self._run("neighbor", "flush"), "", msg="'neighbor flush' must be quiet on success.")

        self.assertNotIn(
            "10.0.1.50",
            self._run("neighbor"),
            msg="The flushed entry must no longer appear in the listing.",
        )

    def test__cli__address_shows_interface_with_addresses(self) -> None:
        """
        Ensure 'pytcp address' renders the interface header, its link-layer
        address, and at least one assigned address.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        output = self._run("address")

        self.assertIn(
            "link/ether",
            output,
            msg="The address output must include the interface's link-layer address.",
        )
        self.assertIn(
            "inet ",
            output,
            msg="The address output must include at least one assigned IPv4 address.",
        )

    def test__cli__stack_status_running_shows_stack(self) -> None:
        """
        Ensure 'pytcp stack status' against a live, reachable daemon
        reports the running pid, the control socket, and a summary of the
        stack's interface addressing state.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        tmp_dir = self.enterContext(tempfile.TemporaryDirectory())
        pidfile = os.path.join(tmp_dir, "pytcp.pid")
        with open(pidfile, "w", encoding="ascii") as handle:
            handle.write(f"{os.getpid()}\n")

        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            exit_code = main(
                ["--ipc-socket", self._socket_path, "stack", "status", "--pidfile", pidfile],
            )
        output = buffer.getvalue()

        self.assertEqual(exit_code, 0, msg="stack status must exit 0 for a running, reachable daemon.")
        self.assertIn(
            f"running (pid {os.getpid()})",
            output,
            msg="stack status must report the running pid.",
        )
        self.assertIn(
            "link/ether",
            output,
            msg="stack status must render the stack's interface addressing summary.",
        )

    def test__cli__address_add_then_del_ipv4(self) -> None:
        """
        Ensure 'pytcp address add ADDR/PREFIX --dev IF' installs an IPv4
        address through the Address API (so 'pytcp address' lists it) and
        'pytcp address del' removes it.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        dev = self._connect().link.interface(self._ifindex).name or f"if{self._ifindex}"

        self._run("address", "add", "10.0.1.80/24", "--dev", dev)
        self.assertIn("10.0.1.80", self._run("address"), msg="The added IPv4 address must appear in 'address'.")

        self._run("address", "del", "10.0.1.80", "--dev", dev)
        self.assertNotIn("10.0.1.80", self._run("address"), msg="The deleted IPv4 address must be gone.")

    def test__cli__address_add_bad_address_errors(self) -> None:
        """
        Ensure a malformed interface address is reported as an error.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        dev = self._connect().link.interface(self._ifindex).name or f"if{self._ifindex}"
        with self.assertRaises(SystemExit) as raised:
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                main(["--ipc-socket", self._socket_path, "address", "add", "not-an-address", "--dev", dev])
        self.assertNotEqual(raised.exception.code, 0, msg="A malformed address must exit non-zero.")

    def test__cli__link_shows_interface_without_addresses(self) -> None:
        """
        Ensure 'pytcp link' renders the interface header and link-layer
        address but no assigned addresses.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        output = self._run("link")

        self.assertIn(
            "link/ether",
            output,
            msg="The link output must include the interface's link-layer address.",
        )
        self.assertNotIn(
            "inet ",
            output,
            msg="The link output must not include assigned addresses.",
        )

    def test__cli__link_set_mtu(self) -> None:
        """
        Ensure 'pytcp link set --dev IF --mtu N' changes the interface MTU
        and a subsequent 'pytcp link' shows the new value.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        dev = self._connect().link.interface(self._ifindex).name or f"if{self._ifindex}"

        self._run("link", "set", "--dev", dev, "--mtu", "1400")

        self.assertIn("mtu 1400", self._run("link"), msg="The MTU change must appear in 'link'.")

    def test__cli__link_set_requires_an_attribute(self) -> None:
        """
        Ensure 'pytcp link set --dev IF' with no attribute is reported as
        an error.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        dev = self._connect().link.interface(self._ifindex).name or f"if{self._ifindex}"
        with self.assertRaises(SystemExit) as raised:
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                main(["--ipc-socket", self._socket_path, "link", "set", "--dev", dev])
        self.assertNotEqual(raised.exception.code, 0, msg="'link set' with no attribute must exit non-zero.")

    def test__cli__link_set_invalid_mtu_reports_remote_error_cleanly(self) -> None:
        """
        Ensure a daemon-rejected control op (an MTU below the RFC 791
        floor) is reported cleanly and exits non-zero, rather than letting
        the remote-error traceback escape.

        Reference: RFC 791 §3.2 (minimum MTU floor).
        """

        dev = self._connect().link.interface(self._ifindex).name or f"if{self._ifindex}"
        stderr = io.StringIO()
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(stderr):
            exit_code = main(["--ipc-socket", self._socket_path, "link", "set", "--dev", dev, "--mtu", "10"])

        self.assertEqual(exit_code, 1, msg="A rejected control op must exit 1, not raise.")
        self.assertTrue(stderr.getvalue().startswith("pytcp:"), msg="The error must be a clean 'pytcp:' diagnostic.")
