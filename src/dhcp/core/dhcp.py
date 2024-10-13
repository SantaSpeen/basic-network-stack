# https://github.com/niccokunzmann/python_dhcp_server

import collections
import socket
import time
from enum import Enum

import select
from dhcppython import options
from dhcppython.packet import DHCPPacket
from loguru import logger

from .config import DHCPServerConfiguration
from .database import HostDatabase


# noinspection SpellCheckingInspection
class DHCPMessages(Enum):
    DHCPDISCOVER = 1
    DHCPOFFER = 2
    DHCPREQUEST = 3
    DHCPDECLINE = 4
    DHCPACK = 5
    DHCPNAK = 6
    DHCPRELEASE = 7
    DHCPINFORM = 8


class Transaction:

    def __init__(self, server):
        self.start = time.time()
        self.server: "DHCPServer" = server
        self.configuration = server.conf
        self.packets = []
        self.timeout = time.time() + 30
        self.closed = False

    def is_done(self):
        return self.closed or self.timeout < time.time()

    def close(self):
        self.closed = True

    def receive(self, packet: DHCPPacket):
        if self.closed:
            return
        if packet.op == "BOOTREQUEST":  # From client
            message = packet.options.by_code(53)
            try:
                dhcp_message = DHCPMessages[message.value['dhcp_message_type']]
            except KeyError:
                logger.warning(f"Unknown dhcp_message: {message}")
                return False
            match dhcp_message:
                case DHCPMessages.DHCPDISCOVER:
                    self.send_offer(packet)
                case DHCPMessages.DHCPREQUEST:
                    self.send_ack(packet)
                case _:
                    logger.warning(f"Unhandled: {dhcp_message}")

    def send_offer(self, packet: DHCPPacket):
        mac = packet.chaddr
        req_ip = packet.options.by_code(50)
        if req_ip:
            req_ip = req_ip.value.get('requested_ip_address')
        else:
            req_ip = packet.ciaddr
        hostname = packet.options.by_code(12)
        if hostname:
            hostname = hostname.value.get("hostname")
        ip = self.server.hosts.find_or_register(mac, req_ip, hostname)
        if ip == 0:
            return
        offer = DHCPPacket.Offer(
            packet.chaddr,
            int(time.time() - self.start),
            packet.xid,
            ip,
            option_list=self.server.conf.options
        )
        offer.siaddr = self.server.conf.dhcp_server_ip
        self.server.broadcast(offer)

    def send_ack(self, packet: DHCPPacket):
        host = self.server.hosts.get(mac=packet.chaddr)
        if host is None:
            logger.error(f"Fail DORA: No host found; MAC: {packet.chaddr}")
            return self.send_nak(packet)
        req_ip = packet.options.by_code(50)
        if not req_ip:
            req_ip = req_ip.value.get('requested_ip_address')
            if host.ip != req_ip:
                logger.error(f"Fail DORA: IP mismatched {host.ip=} != {req_ip=}; MAC: {packet.chaddr}")
                return self.send_nak(packet)
        ack = DHCPPacket.Ack(
            packet.chaddr,
            int(time.time() - self.start),
            packet.xid,
            host.ip,
            option_list=self.server.conf.options
        )
        ack.siaddr = self.server.conf.dhcp_server_ip
        self.server.broadcast(ack)

    def send_nak(self, packet: DHCPPacket):
        nack = DHCPPacket.Ack(
            packet.chaddr,
            int(time.time() - self.start),
            packet.xid,
            packet.yiaddr
        )
        nack.siaddr = self.server.conf.dhcp_server_ip
        nack.options = options.OptionList([options.options.short_value_to_object(53, "DHCPNAK")])
        self.server.broadcast(nack)

class DHCPServer:

    def __init__(self, configuration: DHCPServerConfiguration = None):
        self.conf = configuration or DHCPServerConfiguration()
        self.socket = socket.socket(type=socket.SOCK_DGRAM)
        self.closed = False
        self.transactions = collections.defaultdict(lambda: Transaction(self))  # id: transaction
        self.hosts = HostDatabase(self.conf)
        self.time_started = time.time()

    def __str__(self):
        return f"DHCPServer(configuration={self.conf})"

    def broadcast(self, packet: DHCPPacket) -> None:
        logger.info(
            f"{'broadcasting:':<14}{packet.options.by_code(53).value['dhcp_message_type']:<12}; "
            f"'srv -> cli'; MAC: {packet.chaddr}"
        )
        with socket.socket(type=socket.SOCK_DGRAM) as broadcast_socket:
            broadcast_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            broadcast_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            try:
                data = packet.asbytes
                broadcast_socket.bind((str(self.conf.dhcp_server_ip), 67))
                broadcast_socket.sendto(data, ('255.255.255.255', 68))
                broadcast_socket.sendto(data, (str(self.conf.network.broadcast_address), 68))
            except Exception as e:
                logger.exception(e)
                logger.error(f"Failed to broadcast from {self.conf.dhcp_server_ip}: {e}")

    def _worker(self, timeout=0):
        try:
            reads = select.select([self.socket], [], [], timeout)[0]
        except ValueError:  # -1
            return
        for sock in reads:
            try:
                packet = DHCPPacket.from_bytes(sock.recvfrom(4096)[0])
            except OSError:  # An operation was attempted on something that is not a socket
                pass
            else:
                logger.info(f"{'received:':<14}{packet.options.by_code(53).value['dhcp_message_type']:<12}; "
                            f"{'cli -> srv' if packet.op == 'BOOTREQUEST' else 'srv -> cli'}; MAC: {packet.chaddr}")
                self.transactions[packet.xid].receive(packet)
        for transaction_id, transaction in list(self.transactions.items()):
            if transaction.is_done():
                transaction.close()
                self.transactions.pop(transaction_id)

    def start(self):
        logger.success("Started")
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.bind(("0.0.0.0", 67))
        while not self.closed:
            try:
                self._worker(1)
            except KeyboardInterrupt:
                self.stop()
            except Exception as e:
                logger.exception(e)

    def stop(self, *_, **__):
        self.closed = True
        self.hosts.run = False
        time.sleep(1)
        self.socket.close()
        self.hosts.flush()
        if self.hosts.t:
            self.hosts.t.join()
        for transaction in list(self.transactions.values()):
            transaction.close()
        logger.success("Closed")
