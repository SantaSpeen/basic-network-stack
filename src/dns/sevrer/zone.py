from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Literal, Any, Iterable

from dnslib import QTYPE, dns, DNSLabel, RR
from loguru import logger

S = 1
M = S*60
H = M*60
TTL = 1*H

TYPE_LOOKUP = {
    # https://yandex.cloud/ru/docs/dns/concepts/resource-record
    'A': (dns.A, QTYPE.A),
    'AAAA': (dns.AAAA, QTYPE.AAAA),
    'CAA': (dns.CAA, QTYPE.CAA),
    'CNAME': (dns.CNAME, QTYPE.CNAME),
    # 'ANAME': (dns.ANAME, QTYPE.ANAME),  # Not supported by dnslib
    'MX': (dns.MX, QTYPE.MX),
    'NS': (dns.NS, QTYPE.NS),
    'PTR': (dns.PTR, QTYPE.PTR),
    'SOA': (dns.SOA, QTYPE.SOA),
    'SRV': (dns.SRV, QTYPE.SRV),
    # 'SVCB': (dns.SVCB, QTYPE.SVCB)  # Not supported by dnslib
    'HTTPS': (dns.HTTPS, QTYPE.HTTPS),
    'TXT': (dns.TXT, QTYPE.TXT),
    # https://www.dynu.com/Resources/DNS-Records
    'RP': (dns.RP, QTYPE.RP),
    # 'URI': (dns.URI, QTYPE.URI),  # Not supported by dnslib
    'SPF': (dns.TXT, QTYPE.TXT),

    # Secure DNS
    # https://www.dynu.com/Resources/DNS-Records
    'DNSKEY': (dns.DNSKEY, QTYPE.DNSKEY),
    'DS': (dns.DS, QTYPE.DS),
    # 'HINFO': (dns.HINFO, QTYPE.HINFO), # Not supported by dnslib
    'LOC': (dns.LOC, QTYPE.LOC),
    'NAPTR': (dns.NAPTR, QTYPE.NAPTR),
    'TLSA ': (dns.TLSA , QTYPE.TLSA),
    'RRSIG': (dns.RRSIG, QTYPE.RRSIG),
}
MultiRecordType = Literal[  # Records that have multiple values
    'CAA', 'MX', 'SOA', 'SRV', 'HTTPS', 'RP',
    # Secure DNS
    'DNSKEY', 'DS', 'LOC', 'NAPTR', 'TLSA', 'RRSIG'
]
SingleRecordType = Literal[  # Records that have single value
    'A', 'AAAA', 'CNAME', 'NS', 'PTR', 'TXT', 'SPF'
]
RecordType = Literal[SingleRecordType, MultiRecordType]

@dataclass
class SOA:
    ns: str
    email: str
    serial_no: int = int((datetime.now(timezone.utc) - datetime(1970, 1, 1, tzinfo=timezone.utc)).total_seconds())
    refresh: int = 2 * H
    retry: int  = 10 * H
    expire: int = 10 * H
    min_ttl: int  = 5 * M


class Record:
    def __init__(self, domain: str, type: RecordType, value: list[Any] | str):
        self.domain = domain
        self.type = type
        self.value = value
        self.rcls, self.qtype = TYPE_LOOKUP[type]
        self.qname = None
        self.rr = None
        self.zone = None

    def link(self, zone: "Zone", _from_add_record=False):
        if not _from_add_record:
            return zone.add_record(self)

        # Fix @ in domain
        self.domain = self.domain.replace("@", zone.domain)
        if not self.domain.endswith("."):
            self.domain += "."

        # Fix @ in value
        if self.type in MultiRecordType:
            if not isinstance(self.value, list):
                raise ValueError(f"Value must be an iterable for {self.type} record")
            for i, v in enumerate(self.value):
                if isinstance(v, str):
                    self.value[i] = v.replace("@", zone.domain)
        else:
            if isinstance(self.value, str):
                self.value = self.value.replace("@", zone.domain)

        self.qname = DNSLabel(self.domain)
        self.rr = RR(self.qname, self.qtype, rdata=self.rcls(self.value), ttl=TTL)

        # Check if domain matches zone
        if self.domain.split(".")[-zone.lvl:] != zone.domain.split("."):
            raise ValueError(f"Domain {self.domain!r} does not match zone {zone.domain!r}")
        self.zone = zone

    def match(self, q):
        return self.qtype == q.qtype and self.qname == q.qname

    def __str__(self):
        if self.type in ("SOA", "MX"):
            return f"Record({self.domain:<20} {TTL}   {self.type:<8}{self.value}); Linked to zone: {self.zone};"
        if self.type in ("TXT", "SPF"):
            return f"Record({self.domain:<20} {TTL}   {self.type:<8}{self.value!r}); Linked to zone: {self.zone};"
        return f"Record({self.domain:<20} {TTL}   {self.type:<8}{self.value:<15}); Linked to zone: {self.zone};"


class Zone:

    def __init__(self, domain: str, soa: SOA | None, ptr=False):
        self.serial_no = soa.serial_no
        if not domain.endswith("."):
            domain += "."
        self.domain = domain
        self.lvl = len(domain.split('.'))
        self.ttl = TTL
        self.records: list[Record] = []
        self.label = DNSLabel(domain)
        if not ptr:
            Record(self.domain, "SOA", [soa.ns, soa.email.replace("@", "."), self.serial_no, soa.refresh, soa.retry, soa.expire, soa.min_ttl]).link(self)
            logger.info(f"[{self.domain!r}] Zone created: level: {self.lvl}, ttl: {self.ttl}, serial_no: {self.serial_no}")
        else:
            logger.info(f"[{self.domain!r}] Zone created")

    def add_record(self, record: Record):
        record.link(self, True)
        logger.info(f"[{self.domain!r}] Added: {record}")
        self.records.append(record)

    def find(self, q, reply=None):
        for record in self.records:
            if record.match(q):
                reply.add_answer(record.rr)

    def __str__(self):
        return f"Zone({self.domain!r}, {self.serial_no}, {self.ttl})"

