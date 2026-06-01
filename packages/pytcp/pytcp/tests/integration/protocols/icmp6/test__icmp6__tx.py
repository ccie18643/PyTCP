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
Fluent integration tests for the IPv6/ICMPv6 TX path. Mirrors every
parametrized + standalone case in
'pytcp/tests/integration/packet_handler/test__packet_handler__icmp6__tx.py' onto
the 'IcmpTestCase' harness.

pytcp/tests/integration/protocols/icmp6/test__icmp6__tx.py

ver 3.0.8
"""

from typing import cast

from net_addr import Ip6Address
from net_proto import (
    Icmp6MessageDestinationUnreachable,
    Icmp6MessageEchoReply,
    Icmp6MessageEchoRequest,
    Icmp6NdMessageNeighborAdvertisement,
    Icmp6NdMessageNeighborSolicitation,
    Icmp6NdMessageRouterAdvertisement,
    Icmp6NdMessageRouterSolicitation,
    Icmp6NdOptionPi,
    Icmp6NdOptions,
    Icmp6NdOptionSlla,
    Icmp6NdOptionTlla,
    Icmp6Type,
)
from net_proto.protocols.icmp6.message.icmp6__message__destination_unreachable import (
    Icmp6DestinationUnreachableCode,
)
from net_proto.protocols.icmp6.message.mld2.icmp6__mld2__message__report import (
    Icmp6Mld2MessageReport,
)
from net_proto.protocols.icmp6.message.mld2.icmp6__mld2__multicast_address_record import (
    Icmp6Mld2MulticastAddressRecord,
    Icmp6Mld2MulticastAddressRecordType,
)
from pytcp.lib.tx_status import TxStatus
from pytcp.tests.lib.icmp_testcase import IcmpTestCase
from pytcp.tests.lib.network_testcase import (
    HOST_A__IP6_ADDRESS,
    IP6__MULTICAST__ALL_NODES,
    IP6__MULTICAST__ALL_ROUTERS,
    IP6__MULTICAST__MLD2_ROUTERS,
    IP6__UNSPECIFIED,
    STACK__IP6_HOST,
    STACK__MAC_ADDRESS,
)

_ECHO_PAYLOAD: bytes = b"0123456789ABCDEF" * 20
_DST_UNREACH_PAYLOAD: bytes = b"0123456789ABCDEF" * 100
# RFC 4443 §3.1 / 8200 §5: ICMPv6 error truncates 'data' to fit
# IP6__MIN_MTU(1280) - IP6__HEADER__LEN(40) -
# ICMP6__DESTINATION_UNREACHABLE__LEN(8) = 1232 bytes.
_DST_UNREACH_PAYLOAD__TRUNCATED: bytes = _DST_UNREACH_PAYLOAD[:1232]

_DAD_CANDIDATE__IP6 = Ip6Address("2001:db8:0:1::5")


class TestIcmp6Tx__EchoRequest(IcmpTestCase):
    """
    Outbound ICMPv6 Echo Request via '_phtx_icmp6'.
    """

    def _drive(self) -> TxStatus:
        return self._packet_handler._phtx_icmp6(
            ip6__src=STACK__IP6_HOST.address,
            ip6__dst=HOST_A__IP6_ADDRESS,
            icmp6__message=Icmp6MessageEchoRequest(
                id=12345,
                seq=54320,
                data=_ECHO_PAYLOAD,
            ),
        )

    def test__icmp6__tx__echo_request__tx_status(self) -> None:
        """
        Ensure '_phtx_icmp6' returns PASSED__ETHERNET__TO_TX_RING for
        a normal Echo Request.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            self._drive(),
            TxStatus.PASSED__ETHERNET__TO_TX_RING,
            msg="Expected PASSED__ETHERNET__TO_TX_RING for a normal Echo Request emission.",
        )

    def test__icmp6__tx__echo_request__message_fields(self) -> None:
        """
        Ensure the outbound Echo Request carries id=12345, seq=54320,
        data=_ECHO_PAYLOAD with type=128 / code=0.

        Reference: RFC 4443 §4.1 (Echo Request).
        """

        self._drive()
        probe = self._parse_tx_icmp6(self._frames_tx[0])

        self._assert_icmp6_message(
            probe,
            type=int(Icmp6Type.ECHO_REQUEST),
            code=0,
            id=12345,
            seq=54320,
            data=_ECHO_PAYLOAD,
        )

    def test__icmp6__tx__echo_request__ip_layer(self) -> None:
        """
        Ensure the outbound Echo Request IPv6 src/dst match the
        supplied addressing and hop limit defaults to 64.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._drive()
        probe = self._parse_tx_icmp6(self._frames_tx[0])

        self._assert_icmp6_message(
            probe,
            ip_src=STACK__IP6_HOST.address,
            ip_dst=HOST_A__IP6_ADDRESS,
            ip_hop=64,
        )

    def test__icmp6__tx__echo_request__packet_stats_tx(self) -> None:
        """
        Ensure the Echo Request emission bumps the canonical TX
        counters.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._drive()

        self._assert_packet_stats_tx(
            icmp6__pre_assemble=1,
            icmp6__echo_request__send=1,
            ip6__pre_assemble=1,
            ip6__mtu_ok__send=1,
            ethernet__pre_assemble=1,
            ethernet__src_unspec__fill=1,
            ethernet__dst_unspec__ip6_lookup=1,
            ethernet__dst_unspec__ip6_lookup__locnet__nd_cache_hit__send=1,
        )


class TestIcmp6Tx__EchoReply(IcmpTestCase):
    """
    Outbound ICMPv6 Echo Reply via '_phtx_icmp6'.
    """

    def _drive(self) -> TxStatus:
        return self._packet_handler._phtx_icmp6(
            ip6__src=STACK__IP6_HOST.address,
            ip6__dst=HOST_A__IP6_ADDRESS,
            icmp6__message=Icmp6MessageEchoReply(
                id=12345,
                seq=54320,
                data=_ECHO_PAYLOAD,
            ),
        )

    def test__icmp6__tx__echo_reply__tx_status(self) -> None:
        """
        Ensure '_phtx_icmp6' returns PASSED__ETHERNET__TO_TX_RING for
        a normal Echo Reply emission.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            self._drive(),
            TxStatus.PASSED__ETHERNET__TO_TX_RING,
            msg="Expected PASSED__ETHERNET__TO_TX_RING for a normal Echo Reply emission.",
        )

    def test__icmp6__tx__echo_reply__message_fields(self) -> None:
        """
        Ensure the outbound Echo Reply carries id=12345, seq=54320,
        data=_ECHO_PAYLOAD with type=129 / code=0.

        Reference: RFC 4443 §4.2 (Echo Reply).
        """

        self._drive()
        probe = self._parse_tx_icmp6(self._frames_tx[0])

        self._assert_icmp6_message(
            probe,
            type=int(Icmp6Type.ECHO_REPLY),
            code=0,
            id=12345,
            seq=54320,
            data=_ECHO_PAYLOAD,
        )

    def test__icmp6__tx__echo_reply__packet_stats_tx(self) -> None:
        """
        Ensure the Echo Reply emission bumps the canonical TX
        counters.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._drive()

        self._assert_packet_stats_tx(
            icmp6__pre_assemble=1,
            icmp6__echo_reply__send=1,
            ip6__pre_assemble=1,
            ip6__mtu_ok__send=1,
            ethernet__pre_assemble=1,
            ethernet__src_unspec__fill=1,
            ethernet__dst_unspec__ip6_lookup=1,
            ethernet__dst_unspec__ip6_lookup__locnet__nd_cache_hit__send=1,
        )


class TestIcmp6Tx__DestUnreachablePort(IcmpTestCase):
    """
    Outbound ICMPv6 Destination Unreachable (Port).
    """

    def _drive(self) -> TxStatus:
        return self._packet_handler._phtx_icmp6(
            ip6__src=STACK__IP6_HOST.address,
            ip6__dst=HOST_A__IP6_ADDRESS,
            icmp6__message=Icmp6MessageDestinationUnreachable(
                code=Icmp6DestinationUnreachableCode.PORT,
                data=_DST_UNREACH_PAYLOAD,
            ),
        )

    def test__icmp6__tx__dst_unreach_port__tx_status(self) -> None:
        """
        Ensure '_phtx_icmp6' returns PASSED__ETHERNET__TO_TX_RING for
        a Destination Unreachable Port emission.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            self._drive(),
            TxStatus.PASSED__ETHERNET__TO_TX_RING,
            msg="Expected PASSED__ETHERNET__TO_TX_RING for a Destination Unreachable emission.",
        )

    def test__icmp6__tx__dst_unreach_port__message_fields(self) -> None:
        """
        Ensure the outbound Destination Unreachable carries
        type=1 / code=4 (Port) and the truncated 1232-byte payload
        per the IPv6 minimum MTU cap.

        Reference: RFC 4443 §3.1 (Destination Unreachable Message).
        """

        self._drive()
        probe = self._parse_tx_icmp6(self._frames_tx[0])

        self._assert_icmp6_message(
            probe,
            type=int(Icmp6Type.DESTINATION_UNREACHABLE),
            code=int(Icmp6DestinationUnreachableCode.PORT),
            data=_DST_UNREACH_PAYLOAD__TRUNCATED,
        )

    def test__icmp6__tx__dst_unreach_port__packet_stats_tx(self) -> None:
        """
        Ensure the Destination Unreachable Port emission bumps the
        port-specific TX counter alongside the assembly path.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._drive()

        self._assert_packet_stats_tx(
            icmp6__pre_assemble=1,
            icmp6__destination_unreachable__port__send=1,
            ip6__pre_assemble=1,
            ip6__mtu_ok__send=1,
            ethernet__pre_assemble=1,
            ethernet__src_unspec__fill=1,
            ethernet__dst_unspec__ip6_lookup=1,
            ethernet__dst_unspec__ip6_lookup__locnet__nd_cache_hit__send=1,
        )


class TestIcmp6Tx__RouterSolicitation(IcmpTestCase):
    """
    Outbound ICMPv6 ND Router Solicitation.
    """

    def _drive(self) -> TxStatus:
        return self._packet_handler._phtx_icmp6(
            ip6__src=STACK__IP6_HOST.address,
            ip6__dst=IP6__MULTICAST__ALL_ROUTERS,
            ip6__hop=255,
            icmp6__message=Icmp6NdMessageRouterSolicitation(
                options=Icmp6NdOptions(Icmp6NdOptionSlla(STACK__MAC_ADDRESS)),
            ),
        )

    def test__icmp6__tx__router_solicitation__tx_status(self) -> None:
        """
        Ensure '_phtx_icmp6' emits the Router Solicitation
        successfully.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            self._drive(),
            TxStatus.PASSED__ETHERNET__TO_TX_RING,
            msg="Expected PASSED__ETHERNET__TO_TX_RING for a Router Solicitation emission.",
        )

    def test__icmp6__tx__router_solicitation__message_fields(self) -> None:
        """
        Ensure the outbound RS carries type=133 / code=0 and is
        addressed to the all-routers multicast at hop limit 255.

        Reference: RFC 4861 §4.1 (Router Solicitation Message Format).
        """

        self._drive()
        probe = self._parse_tx_icmp6(self._frames_tx[0])

        self._assert_icmp6_message(
            probe,
            type=int(Icmp6Type.ND__ROUTER_SOLICITATION),
            code=0,
            ip_dst=IP6__MULTICAST__ALL_ROUTERS,
            ip_hop=255,
        )

    def test__icmp6__tx__router_solicitation__packet_stats_tx(self) -> None:
        """
        Ensure the RS emission bumps the canonical TX counters
        (multicast lookup path).

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._drive()

        self._assert_packet_stats_tx(
            icmp6__pre_assemble=1,
            icmp6__nd__router_solicitation__send=1,
            ip6__pre_assemble=1,
            ip6__mtu_ok__send=1,
            ethernet__pre_assemble=1,
            ethernet__src_unspec__fill=1,
            ethernet__dst_unspec__ip6_lookup=1,
            ethernet__dst_unspec__ip6_lookup__multicast__send=1,
        )


class TestIcmp6Tx__RouterAdvertisement(IcmpTestCase):
    """
    Outbound ICMPv6 ND Router Advertisement. The legacy parametrized
    test uses STACK__IP6_HOST.address as source, which technically
    violates the RX-side rule in RFC 4861 §6.1.2 (RA source must be
    link-local) but the IcmpTestCase harness deliberately suppresses
    that RX-only sanity check during TX-frame parsing so the
    integration tests still see the codebase's emitted shape.
    """

    def _drive(self) -> TxStatus:
        return self._packet_handler._phtx_icmp6(
            ip6__src=STACK__IP6_HOST.address,
            ip6__dst=IP6__MULTICAST__ALL_NODES,
            ip6__hop=255,
            icmp6__message=Icmp6NdMessageRouterAdvertisement(
                hop=64,
                flag_m=True,
                flag_o=True,
                router_lifetime=1800,
                reachable_time=900,
                retrans_timer=300,
                options=Icmp6NdOptions(
                    Icmp6NdOptionSlla(STACK__MAC_ADDRESS),
                    Icmp6NdOptionPi(
                        flag_l=True,
                        flag_a=False,
                        flag_r=True,
                        valid_lifetime=7200,
                        preferred_lifetime=3600,
                        prefix=STACK__IP6_HOST.network,
                    ),
                ),
            ),
        )

    def test__icmp6__tx__router_advertisement__tx_status(self) -> None:
        """
        Ensure '_phtx_icmp6' emits the Router Advertisement
        successfully.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            self._drive(),
            TxStatus.PASSED__ETHERNET__TO_TX_RING,
            msg="Expected PASSED__ETHERNET__TO_TX_RING for a Router Advertisement emission.",
        )

    def test__icmp6__tx__router_advertisement__message_fields(self) -> None:
        """
        Ensure the outbound RA carries type=134 / code=0 and is
        addressed to the all-nodes multicast at hop limit 255.

        Reference: RFC 4861 §4.2 (Router Advertisement Message Format).
        """

        self._drive()
        probe = self._parse_tx_icmp6(self._frames_tx[0])

        self._assert_icmp6_message(
            probe,
            type=int(Icmp6Type.ND__ROUTER_ADVERTISEMENT),
            code=0,
            ip_dst=IP6__MULTICAST__ALL_NODES,
            ip_hop=255,
        )

    def test__icmp6__tx__router_advertisement__packet_stats_tx(self) -> None:
        """
        Ensure the RA emission bumps the canonical TX counters.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._drive()

        self._assert_packet_stats_tx(
            icmp6__pre_assemble=1,
            icmp6__nd__router_advertisement__send=1,
            ip6__pre_assemble=1,
            ip6__mtu_ok__send=1,
            ethernet__pre_assemble=1,
            ethernet__src_unspec__fill=1,
            ethernet__dst_unspec__ip6_lookup=1,
            ethernet__dst_unspec__ip6_lookup__multicast__send=1,
        )


class TestIcmp6Tx__NeighborAdvertisement(IcmpTestCase):
    """
    Outbound ICMPv6 ND Neighbor Advertisement (S+O flags).
    """

    def _drive(self) -> TxStatus:
        return self._packet_handler._phtx_icmp6(
            ip6__src=STACK__IP6_HOST.address,
            ip6__dst=HOST_A__IP6_ADDRESS,
            ip6__hop=255,
            icmp6__message=Icmp6NdMessageNeighborAdvertisement(
                target_address=STACK__IP6_HOST.address,
                flag_r=False,
                flag_s=True,
                flag_o=True,
                options=Icmp6NdOptions(Icmp6NdOptionTlla(STACK__MAC_ADDRESS)),
            ),
        )

    def test__icmp6__tx__neighbor_advertisement__tx_status(self) -> None:
        """
        Ensure '_phtx_icmp6' emits the Neighbor Advertisement
        successfully.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            self._drive(),
            TxStatus.PASSED__ETHERNET__TO_TX_RING,
            msg="Expected PASSED__ETHERNET__TO_TX_RING for a Neighbor Advertisement emission.",
        )

    def test__icmp6__tx__neighbor_advertisement__message_fields(self) -> None:
        """
        Ensure the outbound NA carries type=136, code=0, target=stack
        IPv6 address, ip_hop=255.

        Reference: RFC 4861 §4.4 (Neighbor Advertisement Message Format).
        """

        self._drive()
        probe = self._parse_tx_icmp6(self._frames_tx[0])

        self._assert_icmp6_message(
            probe,
            type=int(Icmp6Type.ND__NEIGHBOR_ADVERTISEMENT),
            code=0,
            target=STACK__IP6_HOST.address,
            ip_hop=255,
        )

    def test__icmp6__tx__neighbor_advertisement__packet_stats_tx(self) -> None:
        """
        Ensure the NA emission bumps the canonical TX counters.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._drive()

        self._assert_packet_stats_tx(
            icmp6__pre_assemble=1,
            icmp6__nd__neighbor_advertisement__send=1,
            ip6__pre_assemble=1,
            ip6__mtu_ok__send=1,
            ethernet__pre_assemble=1,
            ethernet__src_unspec__fill=1,
            ethernet__dst_unspec__ip6_lookup=1,
            ethernet__dst_unspec__ip6_lookup__locnet__nd_cache_hit__send=1,
        )


class TestIcmp6Tx__NeighborSolicitation(IcmpTestCase):
    """
    Outbound ICMPv6 ND Neighbor Solicitation (regular, with SLLA).
    """

    def _drive(self) -> TxStatus:
        return self._packet_handler._phtx_icmp6(
            ip6__src=STACK__IP6_HOST.address,
            ip6__dst=HOST_A__IP6_ADDRESS.solicited_node_multicast,
            ip6__hop=255,
            icmp6__message=Icmp6NdMessageNeighborSolicitation(
                target_address=HOST_A__IP6_ADDRESS,
                options=Icmp6NdOptions(Icmp6NdOptionSlla(STACK__MAC_ADDRESS)),
            ),
        )

    def test__icmp6__tx__neighbor_solicitation__tx_status(self) -> None:
        """
        Ensure '_phtx_icmp6' emits the Neighbor Solicitation
        successfully.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            self._drive(),
            TxStatus.PASSED__ETHERNET__TO_TX_RING,
            msg="Expected PASSED__ETHERNET__TO_TX_RING for a Neighbor Solicitation emission.",
        )

    def test__icmp6__tx__neighbor_solicitation__message_fields(self) -> None:
        """
        Ensure the outbound NS carries type=135, code=0, target=host A,
        and is destined to the solicited-node multicast.

        Reference: RFC 4861 §4.3 (Neighbor Solicitation Message Format).
        """

        self._drive()
        probe = self._parse_tx_icmp6(self._frames_tx[0])

        self._assert_icmp6_message(
            probe,
            type=int(Icmp6Type.ND__NEIGHBOR_SOLICITATION),
            code=0,
            target=HOST_A__IP6_ADDRESS,
            ip_dst=HOST_A__IP6_ADDRESS.solicited_node_multicast,
            ip_hop=255,
        )

    def test__icmp6__tx__neighbor_solicitation__packet_stats_tx(self) -> None:
        """
        Ensure the NS emission bumps the canonical TX counters.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._drive()

        self._assert_packet_stats_tx(
            icmp6__pre_assemble=1,
            icmp6__nd__neighbor_solicitation__send=1,
            ip6__pre_assemble=1,
            ip6__mtu_ok__send=1,
            ethernet__pre_assemble=1,
            ethernet__src_unspec__fill=1,
            ethernet__dst_unspec__ip6_lookup=1,
            ethernet__dst_unspec__ip6_lookup__multicast__send=1,
        )


class TestIcmp6Tx__NeighborSolicitationDad(IcmpTestCase):
    """
    Outbound ICMPv6 ND Neighbor Solicitation, DAD variant
    (src=::, no SLLA).
    """

    def _drive(self) -> TxStatus:
        return self._packet_handler._phtx_icmp6(
            ip6__src=IP6__UNSPECIFIED,
            ip6__dst=STACK__IP6_HOST.address.solicited_node_multicast,
            ip6__hop=255,
            icmp6__message=Icmp6NdMessageNeighborSolicitation(
                target_address=STACK__IP6_HOST.address,
                options=Icmp6NdOptions(),
            ),
        )

    def test__icmp6__tx__neighbor_solicitation_dad__message_fields(self) -> None:
        """
        Ensure the DAD NS uses unspecified source and the stack's
        own solicited-node multicast as destination, with no SLLA
        option in the body.

        Reference: RFC 4862 §5.4.2 (Sending Neighbor Solicitation Messages).
        """

        self._drive()
        probe = self._parse_tx_icmp6(self._frames_tx[0])

        self._assert_icmp6_message(
            probe,
            type=int(Icmp6Type.ND__NEIGHBOR_SOLICITATION),
            target=STACK__IP6_HOST.address,
            ip_src=IP6__UNSPECIFIED,
            ip_dst=STACK__IP6_HOST.address.solicited_node_multicast,
            ip_hop=255,
        )

    def test__icmp6__tx__neighbor_solicitation_dad__packet_stats_tx(self) -> None:
        """
        Ensure the DAD NS bumps 'ip6__src_unspecified__send' alongside
        the regular assembly path counters.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._drive()

        self._assert_packet_stats_tx(
            icmp6__pre_assemble=1,
            icmp6__nd__neighbor_solicitation__send=1,
            ip6__pre_assemble=1,
            ip6__mtu_ok__send=1,
            ip6__src_unspecified__send=1,
            ethernet__pre_assemble=1,
            ethernet__src_unspec__fill=1,
            ethernet__dst_unspec__ip6_lookup=1,
            ethernet__dst_unspec__ip6_lookup__multicast__send=1,
        )


class TestIcmp6Tx__Mld2Report(IcmpTestCase):
    """
    Outbound ICMPv6 MLDv2 Report carrying multiple records.
    """

    def _drive(self) -> TxStatus:
        return self._packet_handler._phtx_icmp6(
            ip6__src=STACK__IP6_HOST.address,
            ip6__dst=IP6__MULTICAST__MLD2_ROUTERS,
            ip6__hop=1,
            icmp6__message=Icmp6Mld2MessageReport(
                records=[
                    Icmp6Mld2MulticastAddressRecord(
                        type=Icmp6Mld2MulticastAddressRecordType.CHANGE_TO_EXCLUDE,
                        multicast_address=Ip6Address("ff02::a"),
                    ),
                    Icmp6Mld2MulticastAddressRecord(
                        type=Icmp6Mld2MulticastAddressRecordType.CHANGE_TO_INCLUDE,
                        multicast_address=Ip6Address("ff02::b"),
                    ),
                    Icmp6Mld2MulticastAddressRecord(
                        type=Icmp6Mld2MulticastAddressRecordType.MODE_IS_EXCLUDE,
                        multicast_address=Ip6Address("ff02::c"),
                    ),
                    Icmp6Mld2MulticastAddressRecord(
                        type=Icmp6Mld2MulticastAddressRecordType.MODE_IS_INCLUDE,
                        multicast_address=Ip6Address("ff02::d"),
                    ),
                    Icmp6Mld2MulticastAddressRecord(
                        type=Icmp6Mld2MulticastAddressRecordType.ALLOW_NEW_SOURCES,
                        multicast_address=Ip6Address("ff02::e"),
                    ),
                    Icmp6Mld2MulticastAddressRecord(
                        type=Icmp6Mld2MulticastAddressRecordType.ALLOW_NEW_SOURCES,
                        multicast_address=Ip6Address("ff02::f"),
                    ),
                ],
            ),
        )

    def test__icmp6__tx__mld2_report__message_fields(self) -> None:
        """
        Ensure the MLDv2 Report carries type=143, ip_dst=ff02::16,
        ip_hop=1, and that the parsed message contains 6 records.

        Reference: RFC 3810 §5.2 (Sending MLDv2 Reports).
        """

        self._drive()
        probe = self._parse_tx_icmp6(self._frames_tx[0])

        self._assert_icmp6_message(
            probe,
            type=int(Icmp6Type.MLD2__REPORT),
            code=0,
            ip_dst=IP6__MULTICAST__MLD2_ROUTERS,
            ip_hop=1,
        )

        message = cast(Icmp6Mld2MessageReport, probe.message)
        self.assertEqual(
            len(message.records),
            6,
            msg=f"MLDv2 Report must carry 6 multicast-address records, got {len(message.records)}.",
        )

    def test__icmp6__tx__mld2_report__packet_stats_tx(self) -> None:
        """
        Ensure the MLDv2 Report emission bumps the MLDv2-specific
        TX counter alongside the assembly path counters.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._drive()

        self._assert_packet_stats_tx(
            icmp6__pre_assemble=1,
            icmp6__mld2__report__send=1,
            ip6__pre_assemble=1,
            ip6__mtu_ok__send=1,
            ethernet__pre_assemble=1,
            ethernet__src_unspec__fill=1,
            ethernet__dst_unspec__ip6_lookup=1,
            ethernet__dst_unspec__ip6_lookup__multicast__send=1,
        )


class TestIcmp6Tx__DestUnreachableUnsupportedCode(IcmpTestCase):
    """
    Outbound ICMPv6 Destination Unreachable with a non-PORT code.
    """

    def test__icmp6__tx__dst_unreach_non_port__drops(self) -> None:
        """
        Ensure '_phtx_icmp6' drops with TxStatus.DROPPED__ICMP6__UNKNOWN
        when asked to emit a Destination Unreachable with a code other
        than PORT — the TX path only supports the PORT subcase today,
        and the fall-through is a defensive drop with a counter bump
        rather than an exception.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        before = self._packet_handler._packet_stats_tx.icmp6__unknown__drop

        status = self._packet_handler._phtx_icmp6(
            ip6__src=STACK__IP6_HOST.address,
            ip6__dst=HOST_A__IP6_ADDRESS,
            icmp6__message=Icmp6MessageDestinationUnreachable(
                code=Icmp6DestinationUnreachableCode.NO_ROUTE,
            ),
        )

        self.assertIs(
            status,
            TxStatus.DROPPED__ICMP6__UNKNOWN,
            msg="Unsupported code must return DROPPED__ICMP6__UNKNOWN.",
        )
        self.assertEqual(
            self._packet_handler._packet_stats_tx.icmp6__unknown__drop,
            before + 1,
            msg="Unsupported code must bump 'icmp6__unknown__drop'.",
        )


class TestIcmp6Tx__SendDadMessage(IcmpTestCase):
    """
    The '_send_icmp6_nd_dad_message' helper.
    """

    def _drive(self) -> None:
        self._packet_handler._send_icmp6_nd_dad_message(ip6_unicast_candidate=_DAD_CANDIDATE__IP6)

    def test__icmp6__tx__send_dad_message__emits_one_frame(self) -> None:
        """
        Ensure the helper emits exactly one DAD probe NS frame.

        Reference: RFC 4862 §5.4.2 (Sending Neighbor Solicitation Messages).
        """

        self._drive()

        self.assertEqual(
            len(self._frames_tx),
            1,
            msg=f"_send_icmp6_nd_dad_message must emit exactly one frame, got {len(self._frames_tx)}.",
        )

    def test__icmp6__tx__send_dad_message__probe_shape(self) -> None:
        """
        Ensure the DAD probe has src=::, dst=solicited-node multicast
        for the candidate, and target=candidate.

        Reference: RFC 4862 §5.4.2 (Sending Neighbor Solicitation Messages).
        """

        self._drive()
        probe = self._parse_tx_icmp6(self._frames_tx[0])

        self._assert_icmp6_message(
            probe,
            type=int(Icmp6Type.ND__NEIGHBOR_SOLICITATION),
            target=_DAD_CANDIDATE__IP6,
            ip_src=IP6__UNSPECIFIED,
            ip_dst=_DAD_CANDIDATE__IP6.solicited_node_multicast,
            ip_hop=255,
        )

    def test__icmp6__tx__send_dad_message__packet_stats_tx(self) -> None:
        """
        Ensure the DAD helper bumps the unspecified-src and
        multicast-send counters on the IPv6 TX path.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._drive()

        self._assert_packet_stats_tx(
            icmp6__pre_assemble=1,
            icmp6__nd__neighbor_solicitation__send=1,
            ip6__pre_assemble=1,
            ip6__src_unspecified__send=1,
            ip6__mtu_ok__send=1,
            ethernet__pre_assemble=1,
            ethernet__src_unspec__fill=1,
            ethernet__dst_unspec__ip6_lookup=1,
            ethernet__dst_unspec__ip6_lookup__multicast__send=1,
        )


class TestIcmp6Tx__SendMulticastListenerReport(IcmpTestCase):
    """
    The '_send_icmp6_multicast_listener_report' helper, normal path.
    """

    def _drive(self) -> None:
        self._packet_handler._send_icmp6_multicast_listener_report()

    def test__icmp6__tx__send_mlr__emits_one_frame(self) -> None:
        """
        Ensure the helper emits exactly one MLDv2 Report frame when
        there is at least one filtered multicast group to report.

        Reference: RFC 3810 §5.2 (Sending MLDv2 Reports).
        """

        self._drive()

        self.assertEqual(
            len(self._frames_tx),
            1,
            msg=f"_send_icmp6_multicast_listener_report must emit one frame, got {len(self._frames_tx)}.",
        )

    def test__icmp6__tx__send_mlr__report_shape(self) -> None:
        """
        Ensure the MLR carries type=143 / code=0 destined to ff02::16
        with hop limit 1.

        Reference: RFC 3810 §5.2 (Sending MLDv2 Reports).
        """

        self._drive()
        probe = self._parse_tx_icmp6(self._frames_tx[0])

        self._assert_icmp6_message(
            probe,
            type=int(Icmp6Type.MLD2__REPORT),
            code=0,
            ip_dst=IP6__MULTICAST__MLD2_ROUTERS,
            ip_hop=1,
        )

    def test__icmp6__tx__send_mlr__packet_stats_tx(self) -> None:
        """
        Ensure the MLR helper bumps the canonical TX counters.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._drive()

        self._assert_packet_stats_tx(
            icmp6__pre_assemble=1,
            icmp6__mld2__report__send=1,
            ip6__pre_assemble=1,
            ip6__mtu_ok__send=1,
            ethernet__pre_assemble=1,
            ethernet__src_unspec__fill=1,
            ethernet__dst_unspec__ip6_lookup=1,
            ethernet__dst_unspec__ip6_lookup__multicast__send=1,
        )


class TestIcmp6Tx__SendMulticastListenerReportEmpty(IcmpTestCase):
    """
    The '_send_icmp6_multicast_listener_report' helper when the
    filter set is empty (no MLDv2 report sent).
    """

    def setUp(self) -> None:
        """
        Reset the stack's multicast list to only ff02::1 so the
        filter inside the helper drops everything.
        """

        super().setUp()
        self._packet_handler._ip6_multicast = [Ip6Address("ff02::1")]

    def test__icmp6__tx__send_mlr_empty__no_tx(self) -> None:
        """
        Ensure that when the filtered set is empty, no MLDv2 frame
        is emitted.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._packet_handler._send_icmp6_multicast_listener_report()

        self._assert_no_tx()

    def test__icmp6__tx__send_mlr_empty__packet_stats_tx(self) -> None:
        """
        Ensure no TX counters are bumped on the empty-filter path.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._packet_handler._send_icmp6_multicast_listener_report()

        self._assert_packet_stats_tx()


class TestIcmp6Tx__SendRouterSolicitation(IcmpTestCase):
    """
    The '_send_icmp6_nd_router_solicitation' helper.
    """

    def _drive(self) -> None:
        self._packet_handler._send_icmp6_nd_router_solicitation()

    def test__icmp6__tx__send_rs__emits_one_frame(self) -> None:
        """
        Ensure the helper emits exactly one Router Solicitation
        frame to the all-routers multicast.

        Reference: RFC 4861 §6.3.7 (Sending Router Solicitations).
        """

        self._drive()

        self.assertEqual(
            len(self._frames_tx),
            1,
            msg=f"_send_icmp6_nd_router_solicitation must emit one frame, got {len(self._frames_tx)}.",
        )

    def test__icmp6__tx__send_rs__probe_shape(self) -> None:
        """
        Ensure the RS carries type=133 / code=0, dst=ff02::2,
        hop limit 255.

        Reference: RFC 4861 §4.1 (Router Solicitation Message Format).
        """

        self._drive()
        probe = self._parse_tx_icmp6(self._frames_tx[0])

        self._assert_icmp6_message(
            probe,
            type=int(Icmp6Type.ND__ROUTER_SOLICITATION),
            code=0,
            ip_dst=IP6__MULTICAST__ALL_ROUTERS,
            ip_hop=255,
        )

    def test__icmp6__tx__send_rs__packet_stats_tx(self) -> None:
        """
        Ensure the RS helper bumps the canonical TX counters.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._drive()

        self._assert_packet_stats_tx(
            icmp6__pre_assemble=1,
            icmp6__nd__router_solicitation__send=1,
            ip6__pre_assemble=1,
            ip6__mtu_ok__send=1,
            ethernet__pre_assemble=1,
            ethernet__src_unspec__fill=1,
            ethernet__dst_unspec__ip6_lookup=1,
            ethernet__dst_unspec__ip6_lookup__multicast__send=1,
        )


class TestIcmp6Tx__SendNeighborSolicitationLocal(IcmpTestCase):
    """
    'send_icmp6_neighbor_solicitation' with target inside our network.
    """

    _TARGET = Ip6Address("2001:db8:0:1::99")

    def _drive(self) -> None:
        self._packet_handler.send_icmp6_neighbor_solicitation(icmp6_ns_target_address=self._TARGET)

    def test__icmp6__tx__send_ns_local__emits_one_frame(self) -> None:
        """
        Ensure the helper emits exactly one NS frame for an in-network
        target address.

        Reference: RFC 4861 §7.2 (Address Resolution).
        """

        self._drive()

        self.assertEqual(
            len(self._frames_tx),
            1,
            msg=f"send_icmp6_neighbor_solicitation must emit one frame, got {len(self._frames_tx)}.",
        )

    def test__icmp6__tx__send_ns_local__probe_shape(self) -> None:
        """
        Ensure the NS carries target=peer, src=our IPv6, dst=
        peer's solicited-node multicast at hop limit 255.

        Reference: RFC 4861 §4.3 (Neighbor Solicitation Message Format).
        """

        self._drive()
        probe = self._parse_tx_icmp6(self._frames_tx[0])

        self._assert_icmp6_message(
            probe,
            type=int(Icmp6Type.ND__NEIGHBOR_SOLICITATION),
            target=self._TARGET,
            ip_src=STACK__IP6_HOST.address,
            ip_dst=self._TARGET.solicited_node_multicast,
            ip_hop=255,
        )

    def test__icmp6__tx__send_ns_local__packet_stats_tx(self) -> None:
        """
        Ensure the NS helper bumps the canonical TX counters
        (multicast-send path because the destination is solicited-node).

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._drive()

        self._assert_packet_stats_tx(
            icmp6__pre_assemble=1,
            icmp6__nd__neighbor_solicitation__send=1,
            ip6__pre_assemble=1,
            ip6__mtu_ok__send=1,
            ethernet__pre_assemble=1,
            ethernet__src_unspec__fill=1,
            ethernet__dst_unspec__ip6_lookup=1,
            ethernet__dst_unspec__ip6_lookup__multicast__send=1,
        )


class TestIcmp6Tx__SendNeighborSolicitationOffNetwork(IcmpTestCase):
    """
    'send_icmp6_neighbor_solicitation' with target outside our
    networks. The IPv6 TX layer drops the resulting unspecified-source
    NS because non-DAD NS must carry an SLLA.
    """

    _TARGET = Ip6Address("2001:db8:99::1")

    def _drive(self) -> None:
        self._packet_handler.send_icmp6_neighbor_solicitation(icmp6_ns_target_address=self._TARGET)

    def test__icmp6__tx__send_ns_off_network__no_tx(self) -> None:
        """
        Ensure the off-network NS path produces no TX frames — the
        IPv6 layer drops the packet for unspecified source.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._drive()

        self._assert_no_tx()

    def test__icmp6__tx__send_ns_off_network__packet_stats_tx(self) -> None:
        """
        Ensure the helper still bumps the early-stage TX counters
        even though the IPv6 layer ultimately drops the packet.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._drive()

        self._assert_packet_stats_tx(
            icmp6__pre_assemble=1,
            icmp6__nd__neighbor_solicitation__send=1,
            ip6__pre_assemble=1,
            ip6__src_unspecified__drop=1,
        )


class TestIcmp6Tx__SendIcmp6Packet(IcmpTestCase):
    """
    Public 'send_icmp6_packet' wrapper that renames its kwargs into
    the form '_phtx_icmp6' expects.
    """

    def _drive(self) -> TxStatus:
        return self._packet_handler.send_icmp6_packet(
            ip6__local_address=STACK__IP6_HOST.address,
            ip6__remote_address=HOST_A__IP6_ADDRESS,
            icmp6__message=Icmp6MessageEchoRequest(id=1, seq=1, data=b""),
        )

    def test__icmp6__tx__send_packet__tx_status(self) -> None:
        """
        Ensure 'send_icmp6_packet' returns the same TxStatus as a
        direct '_phtx_icmp6' call would.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            self._drive(),
            TxStatus.PASSED__ETHERNET__TO_TX_RING,
            msg="send_icmp6_packet must propagate the underlying _phtx_icmp6 TxStatus.",
        )

    def test__icmp6__tx__send_packet__emits_one_frame(self) -> None:
        """
        Ensure 'send_icmp6_packet' emits exactly one frame for a
        well-formed Echo Request.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._drive()

        self.assertEqual(
            len(self._frames_tx),
            1,
            msg=f"send_icmp6_packet must emit exactly one frame, got {len(self._frames_tx)}.",
        )

    def test__icmp6__tx__send_packet__probe_shape(self) -> None:
        """
        Ensure the wrapper-emitted Echo Request is correctly addressed
        and carries id=1, seq=1, empty payload.

        Reference: RFC 4443 §4.1 (Echo Request).
        """

        self._drive()
        probe = self._parse_tx_icmp6(self._frames_tx[0])

        self._assert_icmp6_message(
            probe,
            type=int(Icmp6Type.ECHO_REQUEST),
            code=0,
            id=1,
            seq=1,
            data=b"",
            ip_src=STACK__IP6_HOST.address,
            ip_dst=HOST_A__IP6_ADDRESS,
        )

    def test__icmp6__tx__send_packet__packet_stats_tx(self) -> None:
        """
        Ensure 'send_icmp6_packet' produces the same per-protocol
        stats as a direct '_phtx_icmp6' call would.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._drive()

        self._assert_packet_stats_tx(
            icmp6__pre_assemble=1,
            icmp6__echo_request__send=1,
            ip6__pre_assemble=1,
            ip6__mtu_ok__send=1,
            ethernet__pre_assemble=1,
            ethernet__src_unspec__fill=1,
            ethernet__dst_unspec__ip6_lookup=1,
            ethernet__dst_unspec__ip6_lookup__locnet__nd_cache_hit__send=1,
        )
