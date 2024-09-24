# https://github.com/mansuf/requests-doh/tree/main

import httpx
from dns.message import make_query
from dns.rdatatype import RdataType
from dns.query import https as query_https
from dns.rcode import Rcode

from .exceptions import (
    DNSQueryFailed,
    DoHProviderNotExist,
    NoDoHProvider, InvalidDoHProvider
)

class DNSOverHTTPS:
    _available_providers = {
        "cloudflare": "https://cloudflare-dns.com/dns-query",
        "cloudflare-security": "https://security.cloudflare-dns.com/dns-query",
        "cloudflare-family": "https://family.cloudflare-dns.com/dns-query",
        "opendns": "https://doh.opendns.com/dns-query",
        "opendns-family": "https://doh.familyshield.opendns.com/dns-query",
        "adguard": "https://dns.adguard.com/dns-query",
        "adguard-family": "https://dns-family.adguard.com/dns-query",
        "adguard-unfiltered": "https://unfiltered.adguard-dns.com/dns-query",
        "quad9": "https://dns.quad9.net/dns-query",
        "quad9-unsecured": "https://dns10.quad9.net/dns-query",
        "google": "https://dns.google/dns-query"
    }

    def __init__(self):
        self._provider = self._available_providers['google']
        self._session: httpx.Client = None

    @property
    def provider(self):
        return self._provider

    @provider.setter
    def provider(self, value):
        if value not in self._available_providers:
            raise DoHProviderNotExist(f"Provider '{value}' does not exist.")
        self._provider = value

    @property
    def session(self):
        return self._provider

    @session.setter
    def session(self, value):
        if not isinstance(value, httpx.Client):
            raise ValueError(f"`session` must be `httpx.Client`, {value.__class__.__name__}")
        self._session = value

    @property
    def providers(self):
        return self._available_providers

    def add_provider(self, name, address):
        if address.startswith("https"):
            raise InvalidDoHProvider(f"Invalid URL. Must start with 'https'.")
        self._available_providers[name] = address



def _resolve(session, doh_endpoint, host, rdatatype):
    req_message = make_query(host, rdatatype)
    res_message = query_https(req_message, doh_endpoint, session=session)
    rcode = Rcode(res_message.rcode())
    if rcode != Rcode.NOERROR:
        raise DNSQueryFailed(f"Failed to query DNS {rdatatype.name} from host '{host}' (rcode = {rcode.name}")

    answers = res_message.resolve_chaining().answer
    if answers is None:
        return None

    return tuple(str(i) for i in answers)


def resolve_dns(host):
    if _provider is None:
        raise NoDoHProvider("There is no active DoH provider")

    session = get_resolver_session()

    if session is None:
        session = httpx.Client()
        set_resolver_session(session)

    answers = set()

    # Reuse is good
    def query(rdatatype):
        return _resolve(session, _provider, host, rdatatype)

    # Query A type
    A_ANSWERS = query(RdataType.A)
    if A_ANSWERS is not None:
        answers.update(A_ANSWERS)

    # Query AAAA type
    AAAA_ANSWERS = query(RdataType.AAAA)
    if AAAA_ANSWERS is not None:
        answers.update(AAAA_ANSWERS)

    if not answers:
        raise DNSQueryFailed(
            f"DNS server {_provider} returned empty results from host '{host}'"
        )

    return list(answers)