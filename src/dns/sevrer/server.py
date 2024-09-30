from __future__ import annotations as _annotations

from dnslib.server import DNSServer as LibDNSServer, DNSLogger
from loguru import logger

from doh import DNSOverHTTPS
from .resolver import ProxyResolver
from .zone import Zone, PTRZone


class DNSServer:
    def __init__(self, *zones: Zone, upstream="8.8.4.4", doh_provider: DNSOverHTTPS | None = None, port=53, tcp=True):
        self.zones: list[Zone] = list(zones) or []
        self.zones.append(PTRZone("127.0.0").add("1", "localhost."))
        self.doh = doh_provider
        self.port = port
        self.tcp = tcp
        self.upstream = upstream
        if doh_provider:
            self.upstream = doh_provider.provider[3]
        self.resolver: ProxyResolver = ProxyResolver(self.upstream, self.doh)
        self.resolver.find_zone = self.find_zone

        dns_logger = DNSLogger(logf=logger.info)
        dns_logger.log_prefix = lambda handler: f'[{handler.__class__.__name__}:{handler.server.resolver.__class__.__name__}] '
        self.udp_server: LibDNSServer = LibDNSServer(self.resolver, port=self.port, logger=dns_logger)
        self.tcp_server: LibDNSServer = LibDNSServer(self.resolver, port=self.port, tcp=True, logger=dns_logger)

    def start(self):
        logger.info(f'Starting DNS server; port={self.port}, upstream={self.upstream!r}, doh={self.doh}')
        self.udp_server.start_thread()
        if self.tcp:
            self.tcp_server.start_thread()
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

    def add_spoof(self, *domains: str):
        self.resolver.cache.spoof_list += domains
        logger.info("Added domains for spoofing: " + ", ".join(domains))

    def add_spoof_callback(self, callback):
        self.resolver.cache.spoof_callbacks.append(callback)
