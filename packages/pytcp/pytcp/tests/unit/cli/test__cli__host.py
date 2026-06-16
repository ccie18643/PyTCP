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
This module contains unit tests for the daemon-independent parts of the
'pytcp host' DNS lookup engine — the pure wire helpers, the formatters,
and the 'run_host' generator driven against a faked UDP socket.

packages/pytcp/pytcp/tests/unit/cli/test__cli__host.py

ver 3.0.8
"""

from unittest import TestCase

from net_addr import Ip4Address, Ip6Address
from net_proto import (
    DnsHeader,
    DnsOpcode,
    DnsParser,
    DnsQuestion,
    DnsRdataMx,
    DnsRdataName,
    DnsRdataSoa,
    DnsRdataTxt,
    DnsRecordClass,
    DnsRecordType,
    DnsResourceRecord,
    DnsResponseCode,
    encode_name,
)
from pytcp.cli.cli__host import (
    HostError,
    HostQueryResult,
    HostQuestion,
    HostStatus,
    build_query,
    build_query_plan,
    format_answer,
    format_host_result,
    record_type_from_name,
    reverse_pointer,
    run_host,
)


def _record(rtype: DnsRecordType, name: str, rdata: bytes, rdata_decoded: object = None) -> DnsResourceRecord:
    """
    Build a resource record fixing class and TTL.
    """

    return DnsResourceRecord(
        name=name,
        rtype=rtype,
        rclass=DnsRecordClass.IN,
        ttl=300,
        rdata=rdata,
        rdata_decoded=rdata_decoded,  # type: ignore[arg-type]
    )


def _response_frame(
    *,
    query_id: int,
    qname: str,
    qtype: DnsRecordType,
    answers: tuple[DnsResourceRecord, ...],
    rcode: DnsResponseCode = DnsResponseCode.NOERROR,
) -> bytes:
    """
    Build an uncompressed DNS response frame the parser accepts.
    """

    header = DnsHeader(
        id=query_id,
        qr=True,
        opcode=DnsOpcode.QUERY,
        aa=False,
        tc=False,
        rd=True,
        ra=True,
        z=0,
        rcode=rcode,
        qdcount=1,
        ancount=len(answers),
        nscount=0,
        arcount=0,
    )
    question = DnsQuestion(qname=qname, qtype=qtype, qclass=DnsRecordClass.IN)
    frame = bytes(header) + bytes(question)
    for answer in answers:
        frame += bytes(answer)
    return frame


class _FakeDnsSocket:
    """
    A caller-supplied UDP socket double: records every datagram sent and
    replays a queued list of response frames (or raises TimeoutError when
    the queue is exhausted).
    """

    def __init__(self, responses: list[bytes], /) -> None:
        self._responses = responses
        self.sent: list[tuple[bytes, tuple[str, int]]] = []

    def settimeout(self, timeout: float, /) -> None:
        """Accept the per-recv timeout (ignored by the double)."""

    def sendto(self, data: bytes, address: tuple[str, int], /) -> int:
        """Record the sent datagram and its destination."""

        self.sent.append((data, address))
        return len(data)

    def recvfrom(self, bufsize: int, /) -> tuple[bytes, tuple[str, int]]:
        """Replay the next queued response, or time out when none remain."""

        if not self._responses:
            raise TimeoutError
        return self._responses.pop(0), ("9.9.9.9", 53)


class TestHostRecordTypeFromName(TestCase):
    """
    The '-t' record-type parser tests.
    """

    def test__cli__host__record_type_from_name_maps_known_types(self) -> None:
        """
        Ensure a known record-type name (case-insensitive) maps to its
        wire enum.

        Reference: RFC 1035 §3.2.2 (TYPE values).
        """

        self.assertEqual(
            record_type_from_name("mx"),
            DnsRecordType.MX,
            msg="A known record-type name must map to its wire enum.",
        )

    def test__cli__host__record_type_from_name_rejects_unknown(self) -> None:
        """
        Ensure an unsupported record-type name raises HostError.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(HostError):
            record_type_from_name("zzz")


class TestHostReversePointer(TestCase):
    """
    The reverse-lookup PTR-name builder tests.
    """

    def test__cli__host__reverse_pointer_ipv4(self) -> None:
        """
        Ensure an IPv4 address maps to its dotted-reverse in-addr.arpa
        name.

        Reference: RFC 1035 §3.5 (IN-ADDR.ARPA domain).
        """

        self.assertEqual(
            reverse_pointer(Ip4Address("1.2.3.4")),
            "4.3.2.1.in-addr.arpa",
            msg="An IPv4 address must reverse to its in-addr.arpa name.",
        )

    def test__cli__host__reverse_pointer_ipv6(self) -> None:
        """
        Ensure an IPv6 address maps to its nibble-reversed ip6.arpa name.

        Reference: RFC 3596 §2.5 (IP6.ARPA domain).
        """

        self.assertEqual(
            reverse_pointer(Ip6Address("2001:db8::1")),
            "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa",
            msg="An IPv6 address must reverse to its 32-nibble ip6.arpa name.",
        )


class TestHostBuildQueryPlan(TestCase):
    """
    The lookup-plan builder tests.
    """

    def test__cli__host__plan_name_default_is_a_aaaa_mx(self) -> None:
        """
        Ensure a bare name with no '-t' expands to the default A + AAAA +
        MX plan.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        plan = build_query_plan(target="example.com", record_type=None)

        self.assertEqual(
            tuple((question.qname, question.qtype) for question in plan),
            (
                ("example.com", DnsRecordType.A),
                ("example.com", DnsRecordType.AAAA),
                ("example.com", DnsRecordType.MX),
            ),
            msg="A bare name must expand to the A + AAAA + MX default plan.",
        )

    def test__cli__host__plan_name_explicit_type_is_single(self) -> None:
        """
        Ensure a name with an explicit '-t' yields a single question of
        that type.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        plan = build_query_plan(target="example.com", record_type=DnsRecordType.TXT)

        self.assertEqual(
            plan,
            (HostQuestion(qname="example.com", qtype=DnsRecordType.TXT, target="example.com"),),
            msg="A name with explicit -t must yield a single question of that type.",
        )

    def test__cli__host__plan_ip_literal_is_reverse_ptr(self) -> None:
        """
        Ensure an IP-literal target becomes a single reverse PTR question
        against its in-addr.arpa name.

        Reference: RFC 1035 §3.5 (IN-ADDR.ARPA domain).
        """

        plan = build_query_plan(target="8.8.8.8", record_type=None)

        self.assertEqual(
            plan,
            (HostQuestion(qname="8.8.8.8.in-addr.arpa", qtype=DnsRecordType.PTR, target="8.8.8.8"),),
            msg="An IP-literal target must become a single reverse PTR question.",
        )


class TestHostBuildQuery(TestCase):
    """
    The query-datagram builder tests.
    """

    def test__cli__host__build_query_round_trips_through_parser(self) -> None:
        """
        Ensure a built query carries the transaction id, the recursion
        flag, and the single question, recovered by the DNS parser.

        Reference: RFC 1035 §4.1.2 (Question section format).
        """

        query = build_query(query_id=0x1234, qname="example.com", qtype=DnsRecordType.A)
        parsed = DnsParser(memoryview(query))

        self.assertEqual(
            (parsed.id, parsed.qr, parsed.rd, parsed.questions),
            (
                0x1234,
                False,
                True,
                (DnsQuestion(qname="example.com", qtype=DnsRecordType.A, qclass=DnsRecordClass.IN),),
            ),
            msg="A built query must carry its id, RD flag, and question.",
        )


class TestHostFormatAnswer(TestCase):
    """
    The answer-record formatter tests.
    """

    def test__cli__host__format_answer_a(self) -> None:
        """
        Ensure an A record renders the 'has address' line.

        Reference: RFC 1035 §3.4.1 (A RDATA format).
        """

        record = _record(DnsRecordType.A, "example.com", bytes(Ip4Address("93.184.216.34")))

        self.assertEqual(
            format_answer(record),
            "example.com has address 93.184.216.34",
            msg="An A record must render the 'has address' line.",
        )

    def test__cli__host__format_answer_aaaa(self) -> None:
        """
        Ensure an AAAA record renders the 'has IPv6 address' line.

        Reference: RFC 3596 §2.2 (AAAA RDATA format).
        """

        record = _record(DnsRecordType.AAAA, "example.com", bytes(Ip6Address("2001:db8::1")))

        self.assertEqual(
            format_answer(record),
            "example.com has IPv6 address 2001:db8::1",
            msg="An AAAA record must render the 'has IPv6 address' line.",
        )

    def test__cli__host__format_answer_cname(self) -> None:
        """
        Ensure a CNAME record renders the 'is an alias for' line.

        Reference: RFC 1035 §3.3.1 (CNAME RDATA format).
        """

        record = _record(
            DnsRecordType.CNAME,
            "www.example.com",
            encode_name("example.com"),
            DnsRdataName(name="example.com"),
        )

        self.assertEqual(
            format_answer(record),
            "www.example.com is an alias for example.com",
            msg="A CNAME record must render the 'is an alias for' line.",
        )

    def test__cli__host__format_answer_ns(self) -> None:
        """
        Ensure an NS record renders the 'name server' line.

        Reference: RFC 1035 §3.3.11 (NS RDATA format).
        """

        record = _record(
            DnsRecordType.NS,
            "example.com",
            encode_name("ns.example.com"),
            DnsRdataName(name="ns.example.com"),
        )

        self.assertEqual(
            format_answer(record),
            "example.com name server ns.example.com",
            msg="An NS record must render the 'name server' line.",
        )

    def test__cli__host__format_answer_ptr(self) -> None:
        """
        Ensure a PTR record renders the 'domain name pointer' line.

        Reference: RFC 1035 §3.3.12 (PTR RDATA format).
        """

        record = _record(
            DnsRecordType.PTR,
            "4.3.2.1.in-addr.arpa",
            encode_name("host.example.com"),
            DnsRdataName(name="host.example.com"),
        )

        self.assertEqual(
            format_answer(record),
            "4.3.2.1.in-addr.arpa domain name pointer host.example.com",
            msg="A PTR record must render the 'domain name pointer' line.",
        )

    def test__cli__host__format_answer_mx(self) -> None:
        """
        Ensure an MX record renders the 'mail is handled by' line with its
        preference and exchange.

        Reference: RFC 1035 §3.3.9 (MX RDATA format).
        """

        record = _record(
            DnsRecordType.MX,
            "example.com",
            b"\x00\x0a" + encode_name("mail.example.com"),
            DnsRdataMx(preference=10, exchange="mail.example.com"),
        )

        self.assertEqual(
            format_answer(record),
            "example.com mail is handled by 10 mail.example.com",
            msg="An MX record must render the 'mail is handled by' line.",
        )

    def test__cli__host__format_answer_soa(self) -> None:
        """
        Ensure an SOA record renders the 'has SOA record' line with its
        names and five timer fields.

        Reference: RFC 1035 §3.3.13 (SOA RDATA format).
        """

        record = _record(
            DnsRecordType.SOA,
            "example.com",
            b"\x00",
            DnsRdataSoa(
                mname="ns.example.com",
                rname="hostmaster.example.com",
                serial=1,
                refresh=2,
                retry=3,
                expire=4,
                minimum=5,
            ),
        )

        self.assertEqual(
            format_answer(record),
            "example.com has SOA record ns.example.com hostmaster.example.com 1 2 3 4 5",
            msg="An SOA record must render the 'has SOA record' line.",
        )

    def test__cli__host__format_answer_txt(self) -> None:
        """
        Ensure a TXT record renders the 'descriptive text' line with each
        character-string quoted.

        Reference: RFC 1035 §3.3.14 (TXT RDATA format).
        """

        record = _record(
            DnsRecordType.TXT,
            "example.com",
            b"\x06v=spf1",
            DnsRdataTxt(strings=(b"v=spf1", b"include:_spf")),
        )

        self.assertEqual(
            format_answer(record),
            'example.com descriptive text "v=spf1" "include:_spf"',
            msg="A TXT record must render each character-string quoted.",
        )


class TestHostFormatResult(TestCase):
    """
    The per-question result formatter tests.
    """

    def _question(self, qtype: DnsRecordType = DnsRecordType.A) -> HostQuestion:
        """
        Build a question for 'example.com' of the given record type.
        """

        return HostQuestion(qname="example.com", qtype=qtype, target="example.com")

    def test__cli__host__format_result_ok_renders_each_answer(self) -> None:
        """
        Ensure an OK result renders one line per answer record.

        Reference: RFC 1035 §4.1.3 (Answer section format).
        """

        result = HostQueryResult(
            question=self._question(),
            status=HostStatus.OK,
            rcode=DnsResponseCode.NOERROR,
            answers=(_record(DnsRecordType.A, "example.com", bytes(Ip4Address("93.184.216.34"))),),
            detail=None,
        )

        self.assertEqual(
            format_host_result(result, show_nodata=False),
            ["example.com has address 93.184.216.34"],
            msg="An OK result must render one line per answer.",
        )

    def test__cli__host__format_result_nodata_hidden_for_default_plan(self) -> None:
        """
        Ensure a NODATA result renders nothing when 'show_nodata' is off
        (the default multi-type plan).

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        result = HostQueryResult(
            question=self._question(DnsRecordType.AAAA),
            status=HostStatus.NODATA,
            rcode=DnsResponseCode.NOERROR,
            answers=(),
            detail=None,
        )

        self.assertEqual(
            format_host_result(result, show_nodata=False),
            [],
            msg="A NODATA result must render nothing when show_nodata is off.",
        )

    def test__cli__host__format_result_nodata_shown_for_explicit_type(self) -> None:
        """
        Ensure a NODATA result renders the 'has no <type> record' line
        when 'show_nodata' is on (an explicit '-t' query).

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        result = HostQueryResult(
            question=self._question(DnsRecordType.MX),
            status=HostStatus.NODATA,
            rcode=DnsResponseCode.NOERROR,
            answers=(),
            detail=None,
        )

        self.assertEqual(
            format_host_result(result, show_nodata=True),
            ["example.com has no MX record"],
            msg="A NODATA result must render the 'has no MX record' line when show_nodata is on.",
        )

    def test__cli__host__format_result_failed_renders_not_found(self) -> None:
        """
        Ensure a FAILED result renders the 'not found' line carrying the
        numeric and symbolic response code.

        Reference: RFC 1035 §4.1.1 (RCODE values).
        """

        result = HostQueryResult(
            question=self._question(),
            status=HostStatus.FAILED,
            rcode=DnsResponseCode.NXDOMAIN,
            answers=(),
            detail=None,
        )

        self.assertEqual(
            format_host_result(result, show_nodata=False),
            ["Host example.com not found: 3(NXDOMAIN)"],
            msg="A FAILED result must render the 'not found' line with the response code.",
        )

    def test__cli__host__format_result_timeout_renders_unreachable(self) -> None:
        """
        Ensure a TIMEOUT result renders the 'connection timed out' line.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        result = HostQueryResult(
            question=self._question(),
            status=HostStatus.TIMEOUT,
            rcode=None,
            answers=(),
            detail=None,
        )

        self.assertEqual(
            format_host_result(result, show_nodata=False),
            [";; connection timed out; no servers could be reached"],
            msg="A TIMEOUT result must render the 'connection timed out' line.",
        )


class TestHostRunHost(TestCase):
    """
    The 'run_host' generator tests (UDP socket faked, no daemon).
    """

    def test__cli__host__run_host_sends_query_and_yields_answer(self) -> None:
        """
        Ensure 'run_host' sends the question to the server and yields an
        OK result carrying the decoded answer.

        Reference: RFC 1035 §4.1.1 (Header section format).
        """

        answer = _record(DnsRecordType.A, "example.com", bytes(Ip4Address("93.184.216.34")))
        frame = _response_frame(query_id=0x1234, qname="example.com", qtype=DnsRecordType.A, answers=(answer,))
        sock = _FakeDnsSocket([frame])

        results = list(
            run_host(
                sock,  # type: ignore[arg-type]
                server=Ip4Address("9.9.9.9"),
                port=53,
                questions=(HostQuestion(qname="example.com", qtype=DnsRecordType.A, target="example.com"),),
                timeout=1.0,
                retries=0,
                id_source=lambda: 0x1234,
            )
        )

        self.assertEqual(
            (results[0].status, results[0].answers[0].address, sock.sent[0][1]),
            (HostStatus.OK, Ip4Address("93.184.216.34"), ("9.9.9.9", 53)),
            msg="run_host must send to the server and yield the decoded answer.",
        )

    def test__cli__host__run_host_classifies_nxdomain_as_failed(self) -> None:
        """
        Ensure 'run_host' classifies an NXDOMAIN response as a FAILED
        result carrying the response code.

        Reference: RFC 1035 §4.1.1 (RCODE values).
        """

        frame = _response_frame(
            query_id=0xABCD,
            qname="nope.example",
            qtype=DnsRecordType.A,
            answers=(),
            rcode=DnsResponseCode.NXDOMAIN,
        )
        sock = _FakeDnsSocket([frame])

        results = list(
            run_host(
                sock,  # type: ignore[arg-type]
                server=Ip4Address("9.9.9.9"),
                port=53,
                questions=(HostQuestion(qname="nope.example", qtype=DnsRecordType.A, target="nope.example"),),
                timeout=1.0,
                retries=0,
                id_source=lambda: 0xABCD,
            )
        )

        self.assertEqual(
            (results[0].status, results[0].rcode),
            (HostStatus.FAILED, DnsResponseCode.NXDOMAIN),
            msg="run_host must classify an NXDOMAIN response as FAILED.",
        )

    def test__cli__host__run_host_times_out_when_no_response(self) -> None:
        """
        Ensure 'run_host' yields a TIMEOUT result when no response arrives
        within the retry budget.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        sock = _FakeDnsSocket([])

        results = list(
            run_host(
                sock,  # type: ignore[arg-type]
                server=Ip4Address("9.9.9.9"),
                port=53,
                questions=(HostQuestion(qname="example.com", qtype=DnsRecordType.A, target="example.com"),),
                timeout=1.0,
                retries=1,
                id_source=lambda: 0x0001,
            )
        )

        self.assertEqual(
            results[0].status,
            HostStatus.TIMEOUT,
            msg="run_host must yield TIMEOUT when no response arrives.",
        )
