# https://github.com/mansuf/requests-doh
import socket
from typing import Literal

import httpx
from dns.message import make_query
from dns.query import https as query_https
from dns.rcode import Rcode
from dns.rdatatype import RdataType
from loguru import logger

from .exceptions import (
    DNSQueryFailed,
    DoHProviderNotExist,
    NoDoHProvider, InvalidDoHProvider
)

AvailableProviders = Literal[
    "cloudflare",
    "opendns",
    "quad9",
    "google"
]

class DNSOverHTTPS:

    def __init__(self, provider: AvailableProviders):
        logger.info("Initializing DNSOverHTTPS")
        # name: domain, path, DOH-IPs, Usual-IPs
        self.available_providers: dict[AvailableProviders, tuple[str, str, set, str]] = {
            "cloudflare": ("cloudflare-dns.com", "/dns-query", set(), "1.1.1.1"),
            "google": ("dns.google", "/dns-query", set(), "8.8.8.8"),
            "opendns": ("doh.opendns.com", "/dns-query", set(), "208.67.222.222"),
            "quad9": ("dns.quad9.net", "/dns-query", set(), "9.9.9.9"),
        }
        self._session = httpx.Client()
        self.provider = provider

    def __str__(self):
        return f"DNSOverHTTPS(provider={self._provider[0]!r}, IPs={self.provider[2]})"

    def _update_provider_ips(self, provider: AvailableProviders):
        host = self.available_providers[provider][0]
        self.available_providers[provider][2].add(str(socket.gethostbyname(host)))
        for ip in self.resolve(host):
            self.available_providers[provider][2].add(ip)
        logger.info(f"Resolved IP for {provider}: {', '.join(self.available_providers[provider][2])}")

    @property
    def provider(self):
        return self._provider

    @provider.setter
    def provider(self, provider: AvailableProviders):
        if provider not in self.available_providers:
            raise DoHProviderNotExist(f"Provider '{provider}' does not exist.")
        self._provider = self.available_providers[provider]
        self._update_provider_ips(provider)

    @property
    def session(self):
        return self._session

    @session.setter
    def session(self, value: httpx.Client):
        if not isinstance(value, httpx.Client):
            raise ValueError(f"`session` must be `httpx.Client`, {value.__class__.__name__}")
        self._session = value

    @property
    def providers(self):
        return self.available_providers

    def add_provider(self, name, address, source, upstream):
        self.available_providers[name] = (address, source, set(), upstream)
        try:
            self._update_provider_ips(name)
            logger.info("Added DoH provider: " + name)
        except Exception as e:
            raise InvalidDoHProvider(f"Failed to add DoH provider '{name}'") from e

    def resolve_raw(self, domain_name: str, rdatatype: RdataType) -> tuple[tuple[str, int], ...] | None:
        req_message = make_query(domain_name, rdatatype)
        for ip in self._provider[2]:
            try:
                res_message = query_https(
                    req_message, f"https://{self._provider[0]}{self.provider[1]}",
                    path=self.provider[1], source=ip,
                    session=self._session
                )
                rcode = Rcode(res_message.rcode())
                if rcode != Rcode.NOERROR:
                    raise DNSQueryFailed(f"Failed to query DNS {rdatatype.name} from host '{domain_name}' (rcode={rcode.name})")

                chain = res_message.resolve_chaining()
                answers = chain.answer
                if answers is None:
                    return None
                return tuple((str(i), chain.minimum_ttl) for i in answers)
            except Exception as e:
                if e == DNSQueryFailed:
                    continue
                logger.exception(e)
                continue


    def resolve(self, domain_name: str, ipv6=False):
        answers = set()

        # Query A type (IPv4)
        A_ANSWERS = self.resolve_raw(domain_name, RdataType.A)
        if A_ANSWERS is not None:
            answers.update(A_ANSWERS)

        if ipv6:
            # Query AAAA type (IPv6)
            AAAA_ANSWERS = self.resolve_raw(domain_name, RdataType.AAAA)
            if AAAA_ANSWERS is not None:
                answers.update(AAAA_ANSWERS)

        if not answers:
            raise DNSQueryFailed(f"DNS server {self._provider} returned empty results from host '{domain_name}'")

        return tuple(i[0] for i in answers)
