import re
import socket
import threading
import time
from typing import Any

from dns.rdatatype import RdataType
from dnslib import QTYPE, DNSRecord, RCODE, RR
from dnslib.proxy import ProxyResolver as LibProxyResolver
from loguru import logger

from doh import DNSQueryFailed
from .zone import TYPE_LOOKUP

ipv4_pattern = r'(?:\b25[0-5]|\b2[0-4][0-9]|\b1[0-9]{2}|\b[1-9][0-9]|\b[0-9])(?:\.(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])){3}'


class DNSCache:

    def __init__(self):
        self.run = True
        self.cache = {}
        self.spoof_list = []
        self.spoof_callbacks = []
        self.tick_callbacks = []
        self.worker = threading.Thread(target=self._worker, daemon=True)
        self.worker.start()

    def get(self, key):
        # Проверяем, жива ли запись, когда ее запрашивают
        record = self.cache.get(key)
        if record:
            rrs, expiry = record
            if time.time() < expiry:
                return rrs
            else:
                del self.cache[key]  # Удаляем запись, если TTL истек
        return None

    def set(self, domain_name, rrs: list[RR], _res):
        # Используем TTL из объекта RR для определения времени истечения
        if len(rrs) == 0:
            return
        ttl = rrs[0].ttl
        self.cache[domain_name] = (rrs, time.time() + ttl)
        for domain in self.spoof_list:
            if domain not in domain_name:
                continue
            logger.debug(f"{domain!r} in {domain_name!r}")
            if rrs[0].rtype == 65:  # https
                for rr in rrs:
                    ipv4_addresses = re.findall(ipv4_pattern, str(rr.rdata))
                    if len(ipv4_addresses) > 0:
                        logger.success(f"Spoofed HTTPS: '{domain_name}' '{rr.rdata}'")
                    [callback(ip, domain_name) for callback in self.spoof_callbacks for ip in ipv4_addresses]
            if rrs[0].rtype == 1:  # A
                logger.success(f"Spoofed: '{domain_name}' {_res}")
                [callback(r, domain_name) for callback in self.spoof_callbacks for r, _ in _res]

    def _sleep(self, t):
        i = 0
        while self.run:
            time.sleep(1)
            i += 1
            if i >= t:
                break

    def _worker(self):
        # Функция для периодической очистки мертвых записей
        while self.run:
            try:
                self._sleep(10)
                [callback() for callback in self.tick_callbacks]
                current_time = time.time()
                keys_to_delete = [key for key, (rr, expiry) in self.cache.items() if expiry < current_time]
                for key in keys_to_delete:
                    del self.cache[key]
            except Exception as e:
                logger.exception(e)


class ProxyResolver(LibProxyResolver):
    def __init__(self, upstream, doh):
        self.doh = doh
        self.cache = DNSCache()
        super().__init__(address=upstream, port=53, timeout=5, strip_aaaa=True)

    def _resolve_from_local(self, request, type_name):
        zone = self.find_zone(request.q)
        if zone:
            reply = request.reply()
            zone.find(request.q, reply)
            if reply.rr:
                logger.info(f'Found in local zones.')
                return reply
            else:
                logger.info(f"Zone found but '{request.q.qname}' ({type_name}) not found.")
                reply.header.rcode = getattr(RCODE, 'NXDOMAIN')
                return reply

        logger.debug(f'Not found in local zones.')

    def _resolve_over_https(self, request, type_name):
        reply = request.reply()
        rcls, qtype = TYPE_LOOKUP[type_name]
        domain_name = str(request.q.qname)
        _cached = self.cache.get(domain_name)
        if _cached:
            logger.info(f'Found in cache.')
            for cached_rr in _cached:
                reply.add_answer(cached_rr)
            return reply
        try:
            res = self.doh.resolve_raw(domain_name, RdataType(qtype))
            if not res:
                reply.header.rcode = getattr(RCODE, 'NXDOMAIN')
            else:
                logger.info(f'Found in DOH.')
                rrs = []
                for i, min_ttl in res:
                    if qtype == QTYPE.HTTPS:
                        rdata = rcls.fromZone(i.split(" ", maxsplit=2))
                    else:
                        rdata = rcls(i)
                    rr = RR(request.q.qname, qtype, rdata=rdata, ttl=min_ttl)
                    rrs.append(rr)
                    reply.add_answer(rr)
                self.cache.set(domain_name, rrs, res)
            return reply
        except DNSQueryFailed as e:
            logger.error(f"Domain: {domain_name} ({type_name})")
            logger.error(e)
            reply.header.rcode = getattr(RCODE, 'NXDOMAIN')
            return reply
        except Exception as e:
            raise e

    def _resolve_from_upstream(self, request, handler):
        logger.info(f'Querying upstream.')
        try:
            if self.strip_aaaa and request.q.qtype == QTYPE.AAAA:
                reply = request.reply()
                reply.header.rcode = RCODE.NXDOMAIN
            else:
                if handler.protocol == 'udp':
                    proxy_r = request.send(self.address, self.port,
                                           timeout=self.timeout)
                else:
                    proxy_r = request.send(self.address, self.port,
                                           tcp=True, timeout=self.timeout)
                reply = DNSRecord.parse(proxy_r)
        except socket.timeout:
            reply = request.reply()
            reply.header.rcode = getattr(RCODE, 'NXDOMAIN')
        return reply

    def resolve(self, request, handler):
        try:
            type_name = QTYPE[request.q.qtype]
            local_reply = self._resolve_from_local(request, type_name)
            if type_name not in TYPE_LOOKUP:
                raise TypeError(f"Unknown {type_name=}. '{request.q.qname}' ({type_name})")
            if local_reply:
                return local_reply
            return self._resolve_over_https(request, type_name)
        except Exception as e:
            logger.exception(e)
            return self._resolve_from_upstream(request, handler)

    def find_zone(self, q) -> Any:
        ...
