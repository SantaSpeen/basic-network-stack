# https://github.com/niccokunzmann/python_dhcp_server

import collections
import select
import socket
import threading
import time

from loguru import logger

from .config import DHCPServerConfiguration
from .database import Host, HostDatabase
from .packets import ReadBootProtocolPacket, WriteBootProtocolPacket


class Transaction:

    def __init__(self, server):
        self.server = server
        self.configuration = server.configuration
        self.packets = []
        self.done_time = time.time() + self.configuration.length_of_transaction
        self.done = False

    def is_done(self):
        return self.done or self.done_time < time.time()

    def close(self):
        self.done = True

    def receive(self, packet):
        # packet from client <-> packet.message_type == 1
        if packet.message_type == 1:
            match packet.dhcp_message_type:
                case "DHCPDISCOVER":
                    self.received_dhcp_discover(packet)
                case "DHCPREQUEST":
                    self.received_dhcp_request(packet)
                case "DHCPINFORM":
                    self.received_dhcp_inform(packet)
                case _:
                    logger.warning(f"Unknown dhcp_message_type: {packet.dhcp_message_type}")
            return True
        return False

    def received_dhcp_discover(self, discovery):
        if not self.is_done():
            self.send_offer(discovery)

    def received_dhcp_request(self, request):
        if not self.is_done():
            self.server.client_has_chosen(request)
            self.acknowledge(request)
            self.close()

    def received_dhcp_inform(self, inform):
        self.close()
        self.server.client_has_chosen(inform)

    def send_offer(self, discovery):
        # https://tools.ietf.org/html/rfc2131
        offer = WriteBootProtocolPacket(self.configuration)
        offer.parameter_order = discovery.parameter_request_list
        mac = discovery.client_mac_address
        offer.your_ip_address = self.server.get_ip_address(discovery)
        # offer.client_ip_address =
        offer.transaction_id = discovery.transaction_id
        # offer.next_server_ip_address =
        offer.relay_agent_ip_address = discovery.relay_agent_ip_address
        offer.client_mac_address = mac
        offer.client_ip_address = discovery.client_ip_address or '0.0.0.0'
        offer.bootp_flags = discovery.bootp_flags
        offer.dhcp_message_type = 'DHCPOFFER'
        offer.client_identifier = mac
        self.server.broadcast(offer)

    def acknowledge(self, request):
        ack = WriteBootProtocolPacket(self.configuration)
        ack.parameter_order = request.parameter_request_list
        ack.transaction_id = request.transaction_id
        # ack.next_server_ip_address =
        ack.bootp_flags = request.bootp_flags
        ack.relay_agent_ip_address = request.relay_agent_ip_address
        mac = request.client_mac_address
        ack.client_mac_address = mac
        # requested_ip_address = request.requested_ip_address
        ack.client_ip_address = request.client_ip_address or '0.0.0.0'
        ack.your_ip_address = self.server.get_ip_address(request)
        ack.dhcp_message_type = 'DHCPACK'
        self.server.broadcast(ack)

def sorted_hosts(hosts):
    hosts = list(hosts)
    hosts.sort(key=lambda host: (host.hostname.lower(), host.mac.lower(), host.ip.lower()))
    return hosts


class DHCPServer:

    def __init__(self, configuration: DHCPServerConfiguration = None):
        self.configuration = configuration or DHCPServerConfiguration()
        self.socket = socket.socket(type=socket.SOCK_DGRAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.bind((self.configuration.bind_address, 67))
        self.closed = False
        self.transactions = collections.defaultdict(lambda: Transaction(self))  # id: transaction
        self.hosts = HostDatabase(self.configuration.host_file)
        self.time_started = time.time()

    def print_configuration(self):
        logger.info(f'DHCP configuration')
        logger.info(f'Network: {self.configuration.network}/{self.configuration.subnet_cidr}')
        logger.info(f'Options: '
                    f'dhcp ips: {tuple(self.configuration.server_addresses)}; '
                    f'gw: {tuple(self.configuration.router)};'
                    f' dns: {tuple(self.configuration.domain_name_server)}; '
                    f'lease: {self.configuration.ip_address_lease_time}s')

    def close(self, *s):
        self.closed = True
        if s:
            time.sleep(1)
        self.socket.close()
        for transaction in list(self.transactions.values()):
            transaction.close()
        logger.success("Closed")

    def update(self, timeout=0):
        try:
            reads = select.select([self.socket], [], [], timeout)[0]
        except ValueError:
            # ValueError: file descriptor cannot be a negative integer (-1)
            return
        for sock in reads:
            try:
                packet = ReadBootProtocolPacket(*sock.recvfrom(4096))
            except OSError:
                # OSError: [WinError 10038] An operation was attempted on something that is not a socket
                pass
            else:
                self.received(packet)
        for transaction_id, transaction in list(self.transactions.items()):
            if transaction.is_done():
                transaction.close()
                self.transactions.pop(transaction_id)

    def is_valid_client_address(self, address):
        if address is None:
            return False
        a = address.split('.')
        s = self.configuration.subnet_mask.split('.')
        n = self.configuration.network.split('.')
        return all(s[i] == '0' or a[i] == n[i] for i in range(4))

    def get_ip_address(self, packet):
        mac_address = packet.client_mac_address
        requested_ip_address = packet.requested_ip_address
        known_hosts = self.hosts.get(mac=mac_address)
        assigned_addresses = set(host.ip for host in self.hosts.all())
        ip = None
        if known_hosts:
            # 1. choose known ip address
            for host in known_hosts:
                if self.is_valid_client_address(host.ip):
                    ip = host.ip
            logger.info(f'Known device. IP: {ip}; MAC: {mac_address}')
        if ip is None and self.is_valid_client_address(requested_ip_address) and ip not in assigned_addresses:
            # 2. choose valid requested ip address
            ip = requested_ip_address
            logger.info(f'New device; Requested IP: {ip}. MAC: {mac_address}')
        if ip is None:
            # 3. choose new, free ip address
            chosen = False
            network_hosts = self.hosts.get(ip=self.configuration.network_filter())
            for ip in self.configuration.all_ip_addresses():
                if not any(host.ip == ip for host in network_hosts):
                    chosen = True
                    break
            if not chosen:
                # 4. reuse old valid ip address
                network_hosts.sort(key=lambda host: host.last_used)
                ip = network_hosts[0].ip
                assert self.is_valid_client_address(ip)
            logger.info(f'New device. MAC: {mac_address}')
        if not any([host.ip == ip for host in known_hosts]):
            logger.success(f'Device registered. IP: {ip}; HostName: {packet.host_name}; MAC: {mac_address}')
            self.hosts.replace(Host(mac_address, ip, packet.host_name or '', time.time()))
        return ip

    def received(self, packet):
        logger.info(f"{'received:':<19}{packet.named_options['dhcp_message_type']:<12}; {'srv <- cli' if packet.message_type == 1 else 'srv -> cli'}; MAC: {packet.client_mac_address}")
        self.transactions[packet.transaction_id].receive(packet)

    def client_has_chosen(self, packet):
        host = Host.from_packet(packet)
        logger.info(f"Requested IP: {host.ip} from MAC: {packet.client_mac_address}")
        if not host.has_valid_ip():
            return
        self.hosts.replace(host)

    def broadcast(self, packet):
        _packet = ReadBootProtocolPacket(packet.to_bytes())
        logger.info(f"{'broadcasting:':<19}{_packet.named_options['dhcp_message_type']:<12}; {'srv <- cli' if _packet.message_type == 1 else 'srv -> cli'}; MAC: {_packet.client_mac_address}")
        for addr in self.configuration.server_addresses:
            broadcast_socket = socket.socket(type=socket.SOCK_DGRAM)
            broadcast_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            broadcast_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            packet.server_identifier = addr
            broadcast_socket.bind((addr, 67))
            try:
                data = packet.to_bytes()
                broadcast_socket.sendto(data, ('255.255.255.255', 68))
                broadcast_socket.sendto(data, (addr, 68))
            finally:
                broadcast_socket.close()

    def run(self):
        logger.success("Started")
        while not self.closed:
            try:
                self.update(1)
            except KeyboardInterrupt:
                self.close()
            except Exception as e:
                logger.exception(e)

    def run_in_thread(self):
        thread = threading.Thread(target=self.run)
        thread.start()
        return thread

    def get_all_hosts(self):
        return sorted_hosts(self.hosts.all())
