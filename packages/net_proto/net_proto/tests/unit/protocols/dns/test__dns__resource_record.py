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
Module contains tests for the DNS resource-record 'address' accessor.

net_proto/tests/unit/protocols/dns/test__dns__resource_record.py

ver 3.0.8
"""

from unittest import TestCase

from net_addr import Ip4Address, Ip6Address
from net_proto.protocols.dns.dns__enums import DnsRecordClass, DnsRecordType
from net_proto.protocols.dns.dns__rdata import DnsRdataName
from net_proto.protocols.dns.dns__resource_record import DnsResourceRecord

# A 13-octet "example.com" name at offset 0, the compression target for
# the CNAME RDATA fixture below:
#   Bytes 0-12 : 0x07 'example' 0x03 'com' 0x00 -> example.com
_ANCHOR = b"\x07example\x03com\x00"


class TestDnsResourceRecordAddress(TestCase):
    """
    The DNS resource-record 'address' accessor tests.

    The 'address' property returns an Ip4Address for a correctly-sized A
    record, an Ip6Address for a correctly-sized AAAA record, and None for
    every other case — including a record whose 'rtype' matches but whose
    'rdata' length does NOT match the fixed A (4) / AAAA (16) octet count,
    so a malformed record never feeds an ill-sized buffer to the address
    constructor.
    """

    def _make(self, rtype: DnsRecordType, rdata: bytes) -> DnsResourceRecord:
        """
        Build a resource record fixing class/ttl/name so each test varies
        only the record type and the rdata payload.
        """

        return DnsResourceRecord(
            name="example.com",
            rtype=rtype,
            rclass=DnsRecordClass.IN,
            ttl=300,
            rdata=rdata,
        )

    def test__dns__resource_record__address__a_exact_len(self) -> None:
        """
        Ensure an A record with exactly 4 octets of rdata exposes the
        decoded IPv4 address.

        Reference: RFC 1035 §3.4.1 (A RDATA is a 32-bit Internet address).
        """

        record = self._make(DnsRecordType.A, b"\x5d\xb8\xd8\x22")

        self.assertEqual(
            record.address,
            Ip4Address("93.184.216.34"),
            msg="A record with 4-octet rdata must decode to the IPv4 address.",
        )

    def test__dns__resource_record__address__a_short_rdata_is_none(self) -> None:
        """
        Ensure an A record whose rdata is shorter than 4 octets yields no
        address instead of feeding an ill-sized buffer to Ip4Address.

        Reference: RFC 1035 §3.4.1 (A RDATA length is fixed at 4 octets).
        """

        record = self._make(DnsRecordType.A, b"\x5d\xb8\xd8")

        self.assertIsNone(
            record.address,
            msg="A record with under-length rdata must report no address.",
        )

    def test__dns__resource_record__address__a_long_rdata_is_none(self) -> None:
        """
        Ensure an A record whose rdata is longer than 4 octets yields no
        address instead of feeding an ill-sized buffer to Ip4Address.

        Reference: RFC 1035 §3.4.1 (A RDATA length is fixed at 4 octets).
        """

        record = self._make(DnsRecordType.A, b"\x5d\xb8\xd8\x22\x00")

        self.assertIsNone(
            record.address,
            msg="A record with over-length rdata must report no address.",
        )

    def test__dns__resource_record__address__aaaa_exact_len(self) -> None:
        """
        Ensure an AAAA record with exactly 16 octets of rdata exposes the
        decoded IPv6 address.

        Reference: RFC 3596 §2.2 (AAAA RDATA is a 128-bit IPv6 address).
        """

        record = self._make(
            DnsRecordType.AAAA,
            b"\x20\x01\x0d\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01",
        )

        self.assertEqual(
            record.address,
            Ip6Address("2001:db8::1"),
            msg="AAAA record with 16-octet rdata must decode to the IPv6 address.",
        )

    def test__dns__resource_record__address__aaaa_short_rdata_is_none(self) -> None:
        """
        Ensure an AAAA record whose rdata is shorter than 16 octets yields
        no address instead of feeding an ill-sized buffer to Ip6Address.

        Reference: RFC 3596 §2.2 (AAAA RDATA length is fixed at 16 octets).
        """

        record = self._make(DnsRecordType.AAAA, b"\x20\x01\x0d\xb8" + b"\x00" * 11)

        self.assertIsNone(
            record.address,
            msg="AAAA record with under-length rdata must report no address.",
        )

    def test__dns__resource_record__address__aaaa_long_rdata_is_none(self) -> None:
        """
        Ensure an AAAA record whose rdata is longer than 16 octets yields
        no address instead of feeding an ill-sized buffer to Ip6Address.

        Reference: RFC 3596 §2.2 (AAAA RDATA length is fixed at 16 octets).
        """

        record = self._make(DnsRecordType.AAAA, b"\x20\x01\x0d\xb8" + b"\x00" * 13)

        self.assertIsNone(
            record.address,
            msg="AAAA record with over-length rdata must report no address.",
        )

    def test__dns__resource_record__address__non_addr_type_is_none(self) -> None:
        """
        Ensure a record whose type is neither A nor AAAA reports no
        address regardless of rdata length.

        Reference: RFC 1035 §3.2.2 (only A / AAAA carry an address RDATA).
        """

        record = self._make(DnsRecordType.TXT, b"\x5d\xb8\xd8\x22")

        self.assertIsNone(
            record.address,
            msg="A non-A/AAAA record must report no address.",
        )


class TestDnsResourceRecordRdataDecoded(TestCase):
    """
    The DNS resource-record 'rdata_decoded' typed-RDATA wiring tests.
    """

    def test__dns__resource_record__from_frame_populates_rdata_decoded(self) -> None:
        """
        Ensure 'from_frame' decodes a name-bearing record's RDATA into a
        typed object exposed on 'rdata_decoded', resolving compression
        against the full message.

        Reference: RFC 1035 §3.3.1 (CNAME RDATA format).
        """

        # CNAME record at offset 13 over the example.com anchor:
        #   Bytes 13-28 : name ptr->0, CNAME, IN, ttl 300, rdlen 6,
        #                 0x03 'www' 0xc0 0x00 -> www.example.com
        frame = _ANCHOR + b"\xc0\x00\x00\x05\x00\x01\x00\x00\x01\x2c\x00\x06\x03www\xc0\x00"

        record, _offset = DnsResourceRecord.from_frame(frame, 13)

        self.assertEqual(
            record.rdata_decoded,
            DnsRdataName(name="www.example.com"),
            msg="from_frame must populate rdata_decoded with the typed CNAME RDATA.",
        )

    def test__dns__resource_record__direct_construction_defaults_rdata_decoded_none(self) -> None:
        """
        Ensure a directly-constructed record (the assembler path, which
        has no frame) defaults 'rdata_decoded' to None.

        Reference: RFC 1035 §4.1.3 (Resource record format).
        """

        record = DnsResourceRecord(
            name="example.com",
            rtype=DnsRecordType.A,
            rclass=DnsRecordClass.IN,
            ttl=300,
            rdata=b"\x5d\xb8\xd8\x22",
        )

        self.assertIsNone(
            record.rdata_decoded,
            msg="A directly-constructed record must default rdata_decoded to None.",
        )

    def test__dns__resource_record__rdata_decoded_excluded_from_equality(self) -> None:
        """
        Ensure 'rdata_decoded' is excluded from equality so a parse-built
        record compares equal to a hand-built one carrying the same raw
        rdata.

        Reference: RFC 1035 §4.1.3 (Resource record format).
        """

        decoded = DnsResourceRecord(
            name="example.com",
            rtype=DnsRecordType.PTR,
            rclass=DnsRecordClass.IN,
            ttl=300,
            rdata=b"\x04host\x07example\x03com\x00",
            rdata_decoded=DnsRdataName(name="host.example.com"),
        )
        bare = DnsResourceRecord(
            name="example.com",
            rtype=DnsRecordType.PTR,
            rclass=DnsRecordClass.IN,
            ttl=300,
            rdata=b"\x04host\x07example\x03com\x00",
        )

        self.assertEqual(
            decoded,
            bare,
            msg="Records with equal raw rdata must compare equal regardless of rdata_decoded.",
        )
