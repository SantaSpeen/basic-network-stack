import socket

from dnslib import QTYPE, DNSRecord, RCODE, RR
from dnslib.proxy import ProxyResolver as LibProxyResolver
from loguru import logger

from .zone import TYPE_LOOKUP, TTL


class ProxyResolver(LibProxyResolver):
    def __init__(self, upstream, doh):
        self.doh = doh
        super().__init__(address=upstream, port=53, timeout=5, strip_aaaa=True)

    def _resolve_from_local(self, request):
        type_name = QTYPE[request.q.qtype]
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

    def _resolve_over_https(self, request):
        reply = request.reply()
        type_name = QTYPE[request.q.qtype]
        rcls, qtype = TYPE_LOOKUP[type_name]
        res = self.doh.resolve_raw(str(request.q.qname), type_name)
        if not res:
            reply.header.rcode = getattr(RCODE, 'NXDOMAIN')
        else:
            for i in res:
                rr = RR(request.q.qname, qtype, rdata=rcls(i), ttl=TTL)
                reply.add_answer(rr)
        logger.info(f'Found in DOH.')
        return reply

    def _resolve_from_upstream(self, request, handler):
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
        local_reply = self._resolve_from_local(request)
        if local_reply:
            return local_reply
        if self.doh:
            return self._resolve_over_https(request)
        else:
            return self._resolve_from_upstream(request, handler)
