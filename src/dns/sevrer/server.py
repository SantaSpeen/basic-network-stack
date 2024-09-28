from __future__ import annotations as _annotations

import sys

from dnslib.server import DNSServer as LibDNSServer, DNSLogger
from loguru import logger

from .resolver import ProxyResolver
from .zone import Zone

class DNSServer:
    def __init__(self, zones: list[Zone] | None = None, upstream="8.8.4.4", doh=None, port=53, tcp=True):
        self.zones: list[Zone] = zones or []
        self.doh = doh
        self.port = port
        self.tcp = tcp
        self.upstream = upstream
        self.resolver: ProxyResolver = ProxyResolver(self.upstream, self.doh)
        self.resolver.find_zone = self.find_zone

        dns_logger = DNSLogger(logf=logger.info)
        dns_logger.log_prefix = lambda handler: f'[{handler.__class__.__name__}:{handler.server.resolver.__class__.__name__}] '
        self.udp_server: LibDNSServer = LibDNSServer(self.resolver, port=self.port, logger=dns_logger)
        self.tcp_server: LibDNSServer = LibDNSServer(self.resolver, port=self.port, tcp=True, logger=dns_logger)

    def start(self):
        logger.info(f'Starting DNS server; port={self.port}, doh={self.doh}, upstream={self.upstream!r}')
        self.udp_server.start_thread()
        if self.tcp:
            self.tcp_server.start_thread()
        logger.info("Spoof list: " + ", ".join(self.resolver.cache.spoof_list))
        logger.success('DNS server started')

    def is_alive(self):
        if self.tcp:
            return self.udp_server.isAlive() and self.tcp_server.isAlive()
        return self.udp_server.isAlive()

    def stop(self):
        if self.tcp:
            self.tcp_server.stop()
            self.tcp_server.server.server_close()
        self.udp_server.stop()
        self.udp_server.server.server_close()
        self.resolver.cache.run = False
        self.resolver.cache.worker.join()
        logger.success('DNS server stopped')

    def find_zone(self, q) -> Zone | None:
        for zone in self.zones:
            if q.qname.matchSuffix(zone.label):
                return zone

    def add_zone(self, zone: Zone):
        logger.success(f'[server] Added: {zone}')
        self.zones.append(zone)

    def add_spoof(self, domain: str):
        self.resolver.cache.spoof_list.append(domain)

    def add_spoof_callback(self, callback):
        self.resolver.cache.spoof_callbacks.append(callback)
