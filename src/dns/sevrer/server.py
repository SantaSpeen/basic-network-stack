from __future__ import annotations as _annotations

import sys

from dnslib.server import DNSServer as LibDNSServer, DNSLogger
from loguru import logger

from .resolver import ProxyResolver
from .zone import Zone

logger.remove()
logger.add(sys.stdout, level="INFO", backtrace=False, diagnose=False,
           format="\r<green>{time:YYYY-MM-DD HH:mm:ss.SSS}</green> | <level>{level: <8}</level> | {message}")
# TODO: log in file


class DNSServer:
    def __init__(self, zones: list[Zone] | None = None, upstream="8.8.4.4", doh=None, port=53, tcp=True):
        self.zones: list[Zone] = zones or []
        self.doh = doh
        self.port = port
        self.tcp = tcp
        self.upstream = upstream
        self.udp_server: LibDNSServer | None = None
        self.tcp_server: LibDNSServer | None = None

    def start(self):
        logger.info(f'Starting DNS server; port={self.port}, doh={self.doh}, upstream={self.upstream!r}')
        resolver = ProxyResolver(self.upstream, self.doh)
        resolver.find_zone = self.find_zone
        dns_logger = DNSLogger(logf=logger.info)
        dns_logger.log_prefix = lambda handler: f'[{handler.__class__.__name__}:{handler.server.resolver.__class__.__name__}] '
        self.udp_server = LibDNSServer(resolver, port=self.port, logger=dns_logger)
        self.udp_server.start_thread()
        if self.tcp:
            self.tcp_server = LibDNSServer(resolver, port=self.port, tcp=True, logger=dns_logger)
            self.tcp_server.start_thread()
        logger.info('DNS server started')

    def stop(self):
        self.udp_server.stop()
        self.udp_server.server.server_close()
        self.tcp_server.stop()
        self.tcp_server.server.server_close()

    def find_zone(self, q):
        for zone in self.zones:
            if q.qname.matchSuffix(zone.label):
                return zone

    def add_zone(self, zone: Zone):
        logger.info(f'[server] Added: {zone}')
        self.zones.append(zone)
