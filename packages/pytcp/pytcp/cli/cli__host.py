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
This module contains the DNS lookup ('host') engine behind the
'pytcp host' CLI subcommand, built on the daemon-backed 'pytcp.socket'
drop-in, the 'net_proto' DNS wire codec, and 'net_addr'.

The engine is split so its wire logic is unit-testable without a
daemon: 'record_type_from_name', 'reverse_pointer', 'build_query_plan',
'build_query', 'parse_response', and the formatters are pure functions,
and 'run_host' drives a *caller-supplied* UDP socket and yields one
'HostQueryResult' per question (so a fake socket exercises it). Socket
construction ('open_dns_socket') is the only daemon-touching helper.

A target that parses as an IPv4 / IPv6 literal becomes a reverse PTR
lookup of its 'in-addr.arpa' / 'ip6.arpa' name; any other target is a
forward lookup — A + AAAA + MX by default, or a single record type
when '-t' is given (matching Linux 'host'). The query transport family
follows the *server* address, not the target.

packages/pytcp/pytcp/cli/cli__host.py

ver 3.0.8
"""

import random
import time
from collections.abc import Callable, Iterator
from enum import Enum, auto
from typing import NamedTuple

from net_addr import (
    Ip4Address,
    Ip4AddressFormatError,
    Ip6Address,
    Ip6AddressFormatError,
)
from net_proto import (
    DnsAssembler,
    DnsIntegrityError,
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
    DnsSanityError,
)
from pytcp import socket

DNS__PORT: int = 53
HOST__RECV_LEN: int = 4096
HOST__DEFAULT_TIMEOUT__SEC: float = 5.0
HOST__DEFAULT_RETRIES: int = 2

# The record types 'pytcp host' accepts after '-t', mapped to their wire
# enum. Mirrors the common set Linux 'host' renders.
_RECORD_TYPES: dict[str, DnsRecordType] = {
    "A": DnsRecordType.A,
    "AAAA": DnsRecordType.AAAA,
    "NS": DnsRecordType.NS,
    "CNAME": DnsRecordType.CNAME,
    "SOA": DnsRecordType.SOA,
    "PTR": DnsRecordType.PTR,
    "MX": DnsRecordType.MX,
    "TXT": DnsRecordType.TXT,
}

# The default forward-lookup plan when no '-t' is given (Linux 'host').
_DEFAULT_FORWARD_TYPES: tuple[DnsRecordType, ...] = (DnsRecordType.A, DnsRecordType.AAAA, DnsRecordType.MX)


class HostError(Exception):
    """
    Exception raised for a 'pytcp host' argument error (e.g. an unknown
    record type), reported cleanly by the CLI command.
    """


class HostStatus(Enum):
    """
    The outcome class of a single DNS question.
    """

    OK = auto()  # The server answered with one or more records.
    NODATA = auto()  # NOERROR with an empty answer section (no such record type).
    FAILED = auto()  # The server returned a non-NOERROR response code.
    TIMEOUT = auto()  # No response arrived within the retry budget.
    ERROR = auto()  # A transport error prevented the query.


class HostQuestion(NamedTuple):
    """
    A single question in a lookup plan: the wire question name, its
    record type, and the user-facing target the line speaks about.
    """

    qname: str
    qtype: DnsRecordType
    target: str


class HostQueryResult(NamedTuple):
    """
    The result of a single DNS question — its status, the response code
    (when one arrived), the answer records, and an optional transport
    error detail.
    """

    question: HostQuestion
    status: HostStatus
    rcode: DnsResponseCode | None
    answers: tuple[DnsResourceRecord, ...]
    detail: str | None


def record_type_from_name(text: str, /) -> DnsRecordType:
    """
    Map a '-t' record-type name (case-insensitive) to its wire enum,
    raising 'HostError' for an unsupported type.
    """

    key = text.upper()
    if key not in _RECORD_TYPES:
        supported = ", ".join(sorted(_RECORD_TYPES))
        raise HostError(f"unknown record type {text!r}; supported types are: {supported}")
    return _RECORD_TYPES[key]


def parse_ip_literal(target: str, /) -> Ip4Address | Ip6Address | None:
    """
    Return the address if 'target' is an IPv4 / IPv6 literal, else None.
    """

    try:
        return Ip6Address(target)
    except Ip6AddressFormatError:
        pass
    try:
        return Ip4Address(target)
    except Ip4AddressFormatError:
        pass
    return None


def reverse_pointer(address: Ip4Address | Ip6Address, /) -> str:
    """
    Build the reverse-lookup PTR name for an address — the dotted reverse
    of the four IPv4 octets under 'in-addr.arpa' (RFC 1035 §3.5) or the
    reverse of the 32 IPv6 nibbles under 'ip6.arpa' (RFC 3596 §2.5).
    """

    if isinstance(address, Ip4Address):
        octets = str(address).split(".")
        return ".".join(reversed(octets)) + ".in-addr.arpa"
    nibbles = f"{int(address):032x}"
    return ".".join(reversed(nibbles)) + ".ip6.arpa"


def build_query_plan(*, target: str, record_type: DnsRecordType | None) -> tuple[HostQuestion, ...]:
    """
    Build the list of questions for 'target'. An IP literal becomes a
    single reverse PTR question (or the explicit '-t' type against the
    reverse name); a name with an explicit '-t' becomes a single
    question; a bare name expands to the default A + AAAA + MX plan.
    """

    if (literal := parse_ip_literal(target)) is not None:
        qname = reverse_pointer(literal)
        return (HostQuestion(qname=qname, qtype=record_type or DnsRecordType.PTR, target=target),)

    if record_type is not None:
        return (HostQuestion(qname=target, qtype=record_type, target=target),)

    return tuple(HostQuestion(qname=target, qtype=qtype, target=target) for qtype in _DEFAULT_FORWARD_TYPES)


def build_query(*, query_id: int, qname: str, qtype: DnsRecordType) -> bytes:
    """
    Build a standard recursive DNS query datagram for one question.
    """

    question = DnsQuestion(qname=qname, qtype=qtype, qclass=DnsRecordClass.IN)
    return bytes(DnsAssembler(dns__id=query_id, dns__questions=(question,)))


def parse_response(data: bytes, /, *, query_id: int) -> DnsParser | None:
    """
    Parse a received datagram into a 'DnsParser', returning None when it
    is malformed or its transaction id does not match 'query_id' (a
    stray datagram the caller should keep waiting past).
    """

    try:
        response = DnsParser(memoryview(data))
    except DnsIntegrityError, DnsSanityError:
        return None
    if response.id != query_id:
        return None
    return response


def _default_id_source() -> int:
    """
    Return a fresh 16-bit DNS transaction id.
    """

    return random.getrandbits(16)


def open_dns_socket(*, is_ipv6: bool) -> socket.Socket:
    """
    Open a UDP socket of the server's address family for DNS queries.
    """

    family = socket.AF_INET6 if is_ipv6 else socket.AF_INET
    return socket.socket(family, socket.SOCK_DGRAM)


def _recv_matching(sock: socket.Socket, /, *, query_id: int, timeout: float) -> DnsParser | None:
    """
    Wait up to 'timeout' seconds for a response whose transaction id
    matches 'query_id', ignoring malformed or unrelated datagrams.
    Return the parsed response, or None on timeout.
    """

    deadline = time.monotonic() + timeout
    while (remaining := deadline - time.monotonic()) > 0:
        sock.settimeout(remaining)
        try:
            data, _address = sock.recvfrom(HOST__RECV_LEN)
        except TimeoutError:
            return None
        if (response := parse_response(data, query_id=query_id)) is not None:
            return response
    return None


def _result_from_response(response: DnsParser, question: HostQuestion, /) -> HostQueryResult:
    """
    Classify a parsed response into a 'HostQueryResult'.
    """

    if response.rcode != DnsResponseCode.NOERROR:
        return HostQueryResult(
            question=question, status=HostStatus.FAILED, rcode=response.rcode, answers=(), detail=None
        )
    if not response.answers:
        return HostQueryResult(
            question=question, status=HostStatus.NODATA, rcode=response.rcode, answers=(), detail=None
        )
    return HostQueryResult(
        question=question,
        status=HostStatus.OK,
        rcode=response.rcode,
        answers=response.answers,
        detail=None,
    )


def run_host(
    sock: socket.Socket,
    /,
    *,
    server: Ip4Address | Ip6Address,
    port: int,
    questions: tuple[HostQuestion, ...],
    timeout: float,
    retries: int,
    id_source: Callable[[], int] = _default_id_source,
) -> Iterator[HostQueryResult]:
    """
    Drive 'sock' through each question against 'server', yielding one
    'HostQueryResult' per question. The caller owns socket construction,
    teardown, and output formatting; this generator owns the query
    build, retransmission, and the bounded wait. 'id_source' is a
    zero-argument callable returning a 16-bit transaction id (injected in
    tests).
    """

    for question in questions:
        yield _query_one(
            sock,
            server=server,
            port=port,
            question=question,
            timeout=timeout,
            retries=retries,
            id_source=id_source,
        )


def _query_one(
    sock: socket.Socket,
    /,
    *,
    server: Ip4Address | Ip6Address,
    port: int,
    question: HostQuestion,
    timeout: float,
    retries: int,
    id_source: Callable[[], int],
) -> HostQueryResult:
    """
    Send one question (with retransmissions) and return its result.
    """

    for _attempt in range(retries + 1):
        query_id = id_source() & 0xFFFF
        payload = build_query(query_id=query_id, qname=question.qname, qtype=question.qtype)
        try:
            sock.sendto(payload, (str(server), port))
        except OSError as error:
            return HostQueryResult(
                question=question, status=HostStatus.ERROR, rcode=None, answers=(), detail=str(error)
            )
        if (response := _recv_matching(sock, query_id=query_id, timeout=timeout)) is not None:
            return _result_from_response(response, question)

    return HostQueryResult(question=question, status=HostStatus.TIMEOUT, rcode=None, answers=(), detail=None)


def format_answer(record: DnsResourceRecord, /) -> str:
    """
    Render a single answer record as a Linux-'host'-style line.
    """

    match record.rtype:
        case DnsRecordType.A | DnsRecordType.AAAA:
            if record.address is not None:
                label = "has IPv6 address" if record.rtype == DnsRecordType.AAAA else "has address"
                return f"{record.name} {label} {record.address}"
        case DnsRecordType.CNAME:
            if isinstance(record.rdata_decoded, DnsRdataName):
                return f"{record.name} is an alias for {record.rdata_decoded.name}"
        case DnsRecordType.NS:
            if isinstance(record.rdata_decoded, DnsRdataName):
                return f"{record.name} name server {record.rdata_decoded.name}"
        case DnsRecordType.PTR:
            if isinstance(record.rdata_decoded, DnsRdataName):
                return f"{record.name} domain name pointer {record.rdata_decoded.name}"
        case DnsRecordType.MX:
            if isinstance(record.rdata_decoded, DnsRdataMx):
                mx = record.rdata_decoded
                return f"{record.name} mail is handled by {mx.preference} {mx.exchange}"
        case DnsRecordType.SOA:
            if isinstance(record.rdata_decoded, DnsRdataSoa):
                soa = record.rdata_decoded
                return (
                    f"{record.name} has SOA record {soa.mname} {soa.rname} "
                    f"{soa.serial} {soa.refresh} {soa.retry} {soa.expire} {soa.minimum}"
                )
        case DnsRecordType.TXT:
            if isinstance(record.rdata_decoded, DnsRdataTxt):
                text = " ".join(f'"{string.decode("ascii", "replace")}"' for string in record.rdata_decoded.strings)
                return f"{record.name} descriptive text {text}"
    return f"{record.name} has {record.rtype} record"


def format_host_result(result: HostQueryResult, /, *, show_nodata: bool) -> list[str]:
    """
    Render a 'HostQueryResult' into zero or more Linux-'host'-style
    lines. 'show_nodata' enables the "has no <type> record" line for an
    explicit '-t' query; it is suppressed for the default multi-type
    plan so an absent AAAA / MX does not add noise.
    """

    match result.status:
        case HostStatus.OK:
            return [format_answer(record) for record in result.answers]
        case HostStatus.NODATA:
            return [f"{result.question.target} has no {result.question.qtype} record"] if show_nodata else []
        case HostStatus.FAILED:
            assert result.rcode is not None
            return [f"Host {result.question.target} not found: {int(result.rcode)}({result.rcode.name})"]
        case HostStatus.TIMEOUT:
            return [";; connection timed out; no servers could be reached"]
        case HostStatus.ERROR:
            return [f";; {result.detail}"]
