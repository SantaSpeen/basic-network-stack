# https://github.com/niccokunzmann/python_dhcp_server

import collections
import queue
import socket
import threading
import time
from ipaddress import ip_address

from loguru import logger

from .listener import *

def get_interface_ip(interface_name):
    try:
        import fcntl
    except ImportError:
        logger.error("Windwos moment...")
        logger.info("Just use 'bind: all'")
        exit(1)
    sock = socket(AF_INET, SOCK_DGRAM)
    try:
        ip = fcntl.ioctl(
            sock.fileno(),
            0x8915,  # SIOCGIFADDR
            struct.pack('256s', interface_name[:15].encode('utf-8'))
        )[20:24]
        return inet_ntoa(ip)
    except OSError as e:
        logger.error(f"Error getting IP for interface {interface_name}: {e}")
        exit(1)


class WriteBootProtocolPacket(object):
    message_type = 2  # 1 client -> server; 2 server -> client
    hardware_type = 1
    hardware_address_length = 6
    hops = 0

    transaction_id = None

    seconds_elapsed = 0
    bootp_flags = 0  # unicast

    client_ip_address = '0.0.0.0'
    your_ip_address = '0.0.0.0'
    next_server_ip_address = '0.0.0.0'
    relay_agent_ip_address = '0.0.0.0'

    client_mac_address = None
    magic_cookie = '99.130.83.99'

    parameter_order = []

    def __init__(self, configuration):
        for i in range(256):
            names = ['option_{}'.format(i)]
            if i < len(options) and hasattr(configuration, options[i][0]):
                names.append(options[i][0])
            for name in names:
                if hasattr(configuration, name):
                    setattr(self, name, getattr(configuration, name))

    def to_bytes(self):
        result = bytearray(236)

        result[0] = self.message_type
        result[1] = self.hardware_type
        result[2] = self.hardware_address_length
        result[3] = self.hops

        result[4:8] = struct.pack('>I', self.transaction_id)

        result[8:10] = shortpack(self.seconds_elapsed)
        result[10:12] = shortpack(self.bootp_flags)

        result[12:16] = inet_aton(self.client_ip_address)
        result[16:20] = inet_aton(self.your_ip_address)
        result[20:24] = inet_aton(self.next_server_ip_address)
        result[24:28] = inet_aton(self.relay_agent_ip_address)

        result[28:28 + self.hardware_address_length] = macpack(self.client_mac_address)

        result += inet_aton(self.magic_cookie)

        if self.options:
            for option in self.options:
                value = self.get_option(option)
                if value is None:
                    continue
                result += bytes([option, len(value)]) + value
        result += bytes([255])
        return bytes(result)

    def get_option(self, option):
        if option < len(options) and hasattr(self, options[option][0]):
            value = getattr(self, options[option][0])
        elif hasattr(self, 'option_{}'.format(option)):
            value = getattr(self, 'option_{}'.format(option))
        else:
            return None
        function = options[option][2]
        if function and value is not None:
            value = function(value)
        return value

    @property
    def options(self):
        done = list()
        # fulfill wishes
        if self.parameter_order:
            for option in self.parameter_order:
                if option < len(options) and hasattr(self, options[option][0]) or hasattr(self,
                                                                                          'option_{}'.format(option)):
                    # this may break with the specification because we must try to fulfill the wishes
                    if option not in done:
                        done.append(option)
        # add my stuff
        for option, o in enumerate(options):
            if o[0] and hasattr(self, o[0]):
                if option not in done:
                    done.append(option)
        for option in range(256):
            if hasattr(self, 'option_{}'.format(option)):
                if option not in done:
                    done.append(option)
        return done

    def __str__(self):
        return str(ReadBootProtocolPacket(self.to_bytes()))


class DelayWorker(object):

    def __init__(self):
        self.closed = False
        self.queue = queue.Queue()
        self.thread = threading.Thread(target=self._delay_response_thread)
        self.thread.start()

    def _delay_response_thread(self):
        while not self.closed:
            if self.closed:
                break
            try:
                p = self.queue.get(timeout=1)
                t, func, args, kw = p
                now = time.time()
                if now < t:
                    time.sleep(0.01)
                    self.queue.put(p)
                else:
                    func(*args, **kw)
            except queue.Empty:
                continue

    def do_after(self, seconds, func, args=(), kw={}):
        self.queue.put((time.time() + seconds, func, args, kw))

    def close(self):
        self.closed = True


class Transaction(object):

    def __init__(self, server):
        self.server = server
        self.configuration = server.configuration
        self.packets = []
        self.done_time = time.time() + self.configuration.length_of_transaction
        self.done = False
        self.do_after = self.server.delay_worker.do_after

    def is_done(self):
        return self.done or self.done_time < time.time()

    def close(self):
        self.done = True

    def receive(self, packet):
        # packet from client <-> packet.message_type == 1
        if packet.message_type == 1 and packet.dhcp_message_type == 'DHCPDISCOVER':
            self.do_after(self.configuration.dhcp_offer_after_seconds,
                          self.received_dhcp_discover, (packet,), )
        elif packet.message_type == 1 and packet.dhcp_message_type == 'DHCPREQUEST':
            self.do_after(self.configuration.dhcp_acknowledge_after_seconds,
                          self.received_dhcp_request, (packet,), )
        elif packet.message_type == 1 and packet.dhcp_message_type == 'DHCPINFORM':
            self.received_dhcp_inform(packet)
        else:
            return False
        return True

    def received_dhcp_discover(self, discovery):
        if self.is_done(): return
        self.configuration.debug('discover:\n {}'.format(str(discovery).replace('\n', '\n  ')))
        self.send_offer(discovery)

    def send_offer(self, discovery):
        # https://tools.ietf.org/html/rfc2131
        offer = WriteBootProtocolPacket(self.configuration)
        offer.parameter_order = discovery.parameter_request_list
        mac = discovery.client_mac_address
        ip = offer.your_ip_address = self.server.get_ip_address(discovery)
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

    def received_dhcp_request(self, request):
        if self.is_done(): return
        self.server.client_has_chosen(request)
        self.acknowledge(request)
        self.close()

    def acknowledge(self, request):
        ack = WriteBootProtocolPacket(self.configuration)
        ack.parameter_order = request.parameter_request_list
        ack.transaction_id = request.transaction_id
        # ack.next_server_ip_address =
        ack.bootp_flags = request.bootp_flags
        ack.relay_agent_ip_address = request.relay_agent_ip_address
        mac = request.client_mac_address
        ack.client_mac_address = mac
        requested_ip_address = request.requested_ip_address
        ack.client_ip_address = request.client_ip_address or '0.0.0.0'
        ack.your_ip_address = self.server.get_ip_address(request)
        ack.dhcp_message_type = 'DHCPACK'
        self.server.broadcast(ack)

    def received_dhcp_inform(self, inform):
        self.close()
        self.server.client_has_chosen(inform)


class DHCPServerConfiguration(object):
    dhcp_offer_after_seconds = 1
    dhcp_acknowledge_after_seconds = 1
    length_of_transaction = 40

    bind_address = ''
    network = '10.0.0.0'
    broadcast_address = '255.255.255.255'
    subnet_mask = '255.255.255.0'
    router = None  # list of ips
    ip_address_lease_time = 300  # seconds
    domain_name_server = ["8.8.8.8", "8.8.4.4"]  # list of ips

    server_addresses = gethostbyname_ex(gethostname())[2]

    host_file = 'hosts.csv'

    debug = lambda *args, **kw: None

    def __init__(self, config=None):
        if config:
            _ba = config.get('bind', self.bind_address)
            if _ba == "all":
                _ba = '0.0.0.0'
            try:
                ip_address(_ba)
            except ValueError:
                __ba = _ba
                _ba = get_interface_ip(_ba)
                logger.info(f"Using interface {__ba} ({_ba})")
            self.bind_address = _ba
            self.network = config.get('network', self.network)
            self.broadcast_address = config.get('broadcast', self.broadcast_address)
            self.subnet_mask = config.get('netmask', self.subnet_mask)
            self.router = config.get('router', self.router)
            self.ip_address_lease_time = config.get('lease_time', self.ip_address_lease_time)
            self.domain_name_server = config.get('dns_servers', self.domain_name_server)
            self.server_addresses = config.get('server_addresses', self.server_addresses)
            self.host_file = config.get('host_file', self.host_file)

    def load(self, file):
        with open(file) as f:
            exec(f.read(), self.__dict__)

    def all_ip_addresses(self):
        ips = ip_addresses(self.network, self.subnet_mask)
        for i in range(5):
            next(ips)
        return ips

    def network_filter(self):
        return NETWORK(self.network, self.subnet_mask)


def ip_addresses(network, subnet_mask):
    import socket, struct
    subnet_mask = struct.unpack('>I', socket.inet_aton(subnet_mask))[0]
    network = struct.unpack('>I', socket.inet_aton(network))[0]
    network = network & subnet_mask
    start = network + 1
    end = (network | (~subnet_mask & 0xffffffff))
    return (socket.inet_ntoa(struct.pack('>I', i)) for i in range(start, end))


class ALL(object):
    def __eq__(self, other):
        return True

    def __repr__(self):
        return self.__class__.__name__


ALL = ALL()


class GREATER(object):
    def __init__(self, value):
        self.value = value

    def __eq__(self, other):
        return type(self.value)(other) > self.value


class NETWORK(object):
    def __init__(self, network, subnet_mask):
        self.subnet_mask = struct.unpack('>I', inet_aton(subnet_mask))[0]
        self.network = struct.unpack('>I', inet_aton(network))[0]

    def __eq__(self, other):
        ip = struct.unpack('>I', inet_aton(other))[0]
        return ip & self.subnet_mask == self.network and \
            ip - self.network and \
            ip - self.network != ~self.subnet_mask & 0xffffffff


class CASEINSENSITIVE(object):
    def __init__(self, s):
        self.s = s.lower()

    def __eq__(self, other):
        return self.s == other.lower()


class CSVDatabase(object):
    delimiter = ';'

    def __init__(self, file_name):
        self.file_name = file_name
        self.file('a').close()  # create file

    def file(self, mode='r'):
        return open(self.file_name, mode)

    def get(self, pattern):
        pattern = list(pattern)
        return [line for line in self.all() if pattern == line]

    def add(self, line):
        with self.file('a') as f:
            f.write(self.delimiter.join(line) + '\n')

    def delete(self, pattern):
        lines = self.all()
        lines_to_delete = self.get(pattern)
        self.file('w').close()  # empty file
        for line in lines:
            if line not in lines_to_delete:
                self.add(line)

    def all(self):
        with self.file() as f:
            return [list(line.strip().split(self.delimiter)) for line in f]


class Host(object):

    def __init__(self, mac, ip, hostname, last_used):
        self.mac = mac.upper()
        self.ip = ip
        self.hostname = hostname
        self.last_used = int(last_used)

    @classmethod
    def from_tuple(cls, line):
        mac, ip, hostname, last_used = line
        last_used = int(last_used)
        return cls(mac, ip, hostname, last_used)

    @classmethod
    def from_packet(cls, packet):
        return cls(packet.client_mac_address,
                   packet.requested_ip_address or packet.client_ip_address,
                   packet.host_name or '',
                   int(time.time()))

    @staticmethod
    def get_pattern(mac=ALL, ip=ALL, hostname=ALL, last_used=ALL):
        return [mac, ip, hostname, last_used]

    def to_tuple(self):
        return [self.mac, self.ip, self.hostname, str(int(self.last_used))]

    def to_pattern(self):
        return self.get_pattern(ip=self.ip, mac=self.mac)

    def __hash__(self):
        return hash(self.key)

    def __eq__(self, other):
        return self.to_tuple() == other.to_tuple()

    def has_valid_ip(self):
        return self.ip and self.ip != '0.0.0.0'


class HostDatabase(object):
    def __init__(self, file_name):
        self.db = CSVDatabase(file_name)

    def get(self, **kw):
        pattern = Host.get_pattern(**kw)
        return list(map(Host.from_tuple, self.db.get(pattern)))

    def add(self, host):
        self.db.add(host.to_tuple())

    def delete(self, host=None, **kw):
        if host is None:
            pattern = Host.get_pattern(**kw)
        else:
            pattern = host.to_pattern()
        self.db.delete(pattern)

    def all(self):
        return list(map(Host.from_tuple, self.db.all()))

    def replace(self, host):
        self.delete(host)
        self.add(host)


def sorted_hosts(hosts):
    hosts = list(hosts)
    hosts.sort(key=lambda host: (host.hostname.lower(), host.mac.lower(), host.ip.lower()))
    return hosts


class DHCPServer(object):

    def __init__(self, configuration: DHCPServerConfiguration = None):
        self.configuration = configuration or DHCPServerConfiguration()
        logger.info(f'DHCP server ({configuration.server_addresses}) configuration')
        logger.info(f'Network: {configuration.network} {configuration.subnet_mask}')
        logger.info(f'Options: gw: {configuration.router}, dns: {configuration.domain_name_server}, lease: {configuration.ip_address_lease_time}s')
        self.socket = socket(type=SOCK_DGRAM)
        self.socket.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
        self.socket.bind((self.configuration.bind_address, 67))
        self.delay_worker = DelayWorker()
        self.closed = False
        self.transactions = collections.defaultdict(lambda: Transaction(self))  # id: transaction
        self.hosts = HostDatabase(self.configuration.host_file)
        self.time_started = time.time()

    def close(self):
        self.socket.close()
        self.closed = True
        self.delay_worker.close()
        for transaction in list(self.transactions.values()):
            transaction.close()

    def update(self, timeout=0):
        try:
            reads = select.select([self.socket], [], [], timeout)[0]
        except ValueError:
            # ValueError: file descriptor cannot be a negative integer (-1)
            return
        for socket in reads:
            try:
                packet = ReadBootProtocolPacket(*socket.recvfrom(4096))
            except OSError:
                # OSError: [WinError 10038] An operation was attempted on something that is not a socket
                pass
            else:
                self.received(packet)
        for transaction_id, transaction in list(self.transactions.items()):
            if transaction.is_done():
                transaction.close()
                self.transactions.pop(transaction_id)

    def received(self, packet):
        if not self.transactions[packet.transaction_id].receive(packet):
            self.configuration.debug('received:\n {}'.format(str(packet).replace('\n', '\n  ')))

    def client_has_chosen(self, packet):
        self.configuration.debug('client_has_chosen:\n {}'.format(str(packet).replace('\n', '\n  ')))
        host = Host.from_packet(packet)
        if not host.has_valid_ip():
            return
        self.hosts.replace(host)

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
        known_hosts = self.hosts.get(mac=CASEINSENSITIVE(mac_address))
        assigned_addresses = set(host.ip for host in self.hosts.get())
        ip = None
        if known_hosts:
            # 1. choose known ip address
            for host in known_hosts:
                if self.is_valid_client_address(host.ip):
                    ip = host.ip
            logger.info(f'[DHCP] Known device, IP: {ip}')
        if ip is None and self.is_valid_client_address(requested_ip_address) and ip not in assigned_addresses:
            # 2. choose valid requested ip address
            ip = requested_ip_address
            logger.info(f'[DHCP] Requested IP: {ip}')
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
            logger.info(f'[DHCP] New device')
        if not any([host.ip == ip for host in known_hosts]):
            logger.success(f'[DHCP] Device registered. MAC: {mac_address}; IP: {ip}; HostName: {packet.host_name}')
            self.hosts.replace(Host(mac_address, ip, packet.host_name or '', time.time()))
        return ip


    def broadcast(self, packet):
        self.configuration.debug('broadcasting:\n {}'.format(str(packet).replace('\n', '\n  ')))
        for addr in self.configuration.server_addresses:
            broadcast_socket = socket(type=SOCK_DGRAM)
            broadcast_socket.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
            broadcast_socket.setsockopt(SOL_SOCKET, SO_BROADCAST, 1)
            packet.server_identifier = addr
            broadcast_socket.bind((addr, 67))
            try:
                data = packet.to_bytes()
                broadcast_socket.sendto(data, ('255.255.255.255', 68))
                broadcast_socket.sendto(data, (addr, 68))
            finally:
                broadcast_socket.close()

    def run(self):
        logger.success("[DHCP] Server started")
        while not self.closed:
            try:
                self.update(1)
            except KeyboardInterrupt:
                self.close()
                logger.success("[DHCP] Closed")
            except Exception as e:
                logger.exception(e)

    def run_in_thread(self):
        thread = threading.Thread(target=self.run)
        thread.start()
        return thread

    def debug_clients(self):
        for line in self.ips.all():
            line = '\t'.join(line)
            if line:
                self.configuration.debug(line)

    def get_all_hosts(self):
        return sorted_hosts(self.hosts.get())

    def get_current_hosts(self):
        return sorted_hosts(self.hosts.get(last_used=GREATER(self.time_started)))
