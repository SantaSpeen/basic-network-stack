# https://github.com/samuelcolvin/dnserver
import os

from dnslib.server import DNSServer as LibDNSServer, DNSLogger
from loguru import logger

from .resolver import ProxyResolver
from .zone import Zone, PTRZone, Record, SOA
from ..doh import DNSOverHTTPS


class DNSServer:
    def __init__(
            self, *zones: Zone,
            upstream="8.8.4.4",
            doh_provider: DNSOverHTTPS | None = None,
            address="0.0.0.0",
            port=53,
            tcp=True,
            spoof_dir=None
    ):
        self.zones: list[Zone] = list(zones) or []
        self.zones.append(PTRZone("127.0.0").add("1", "localhost."))
        self.doh = doh_provider
        self.address = address
        self.port = port
        self.tcp = tcp
        self.spoof_dir = spoof_dir
        self.upstream = upstream
        if doh_provider:
            self.upstream = doh_provider.provider[3]
        self.resolver: ProxyResolver = ProxyResolver(self.upstream, self.doh)
        self.resolver.find_zone = self.find_zone
        self.add_spoof_from_dir(spoof_dir)

        dns_logger = DNSLogger(logf=logger.info)
        dns_logger.log_prefix = lambda handler: f'[{handler.__class__.__name__}:{handler.server.resolver.__class__.__name__}] '
        self.tcp_server: LibDNSServer = LibDNSServer(self.resolver, self.address, self.port, True, dns_logger)
        self.udp_server: LibDNSServer = LibDNSServer(self.resolver, self.address, self.port, False, dns_logger)

    def start(self):
        logger.info(f'Starting DNS server; {self.address}:{self.port} (UDP{"+TPC" if self.tcp else " without TPC"}), upstream={self.upstream!r}, doh={self.doh}')
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

    def add_spoof_from_dir(self, directory):
        logger.info("Reading domains for spoofing from files")
        domains = set()
        for filename in os.listdir(directory):
            file_path = os.path.join(directory, filename)
            if not os.path.isfile(file_path):
                continue
            if not filename.endswith('.spoof'):
                logger.warning(f"Skipping '{filename}'")
                continue
            with open(file_path, 'r', encoding='utf-8') as f:
                file_domains = f.readlines()
            i = 0
            for domain in file_domains:
                if domain in ['.', ''] or len(domain) < 3:
                    continue
                i += 1
                domains.add(domain.strip())
            logger.success(f"Read {i} domains from '{filename}'")
        logger.success(f"Read {len(domains)} domains in total.")
        self.add_spoof(*domains)

    def add_spoof_callback(self, callback):
        logger.success(f"[server] Added spoof callback: {callback.__name__} ({callback})")
        self.resolver.cache.spoof_callbacks.append(callback)

    def add_tick_callback(self, callback):
        logger.success(f"[server] Added tick callback: {callback.__name__} ({callback})")
        self.resolver.cache.tick_callbacks.append(callback)

