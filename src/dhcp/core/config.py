import ipaddress
import struct
from socket import inet_aton, inet_ntoa


def ip_addresses(network, subnet_mask):
    subnet_mask = struct.unpack('>I', inet_aton(subnet_mask))[0]
    network = struct.unpack('>I', inet_aton(network))[0]
    network = network & subnet_mask
    start = network + 1
    end = (network | (~subnet_mask & 0xffffffff))
    return (inet_ntoa(struct.pack('>I', i)) for i in range(start, end))


class NETWORK:
    def __init__(self, network, subnet_mask):
        self.subnet_mask = struct.unpack('>I', inet_aton(subnet_mask))[0]
        self.network = struct.unpack('>I', inet_aton(network))[0]

    def __eq__(self, other):
        ip = struct.unpack('>I', inet_aton(other))[0]
        return ip & self.subnet_mask == self.network and \
            ip - self.network and \
            ip - self.network != ~self.subnet_mask & 0xffffffff


class DHCPServerConfiguration:
    dhcp_offer_after_seconds = 1
    dhcp_acknowledge_after_seconds = 1
    length_of_transaction = 40

    bind_address = ''
    network = '10.47.0.0'
    broadcast_address = '10.47.0.255'
    dhcp_range = ['10.47.0.2', '10.47.0.250']
    subnet_mask = '255.255.255.0'
    subnet_cidr = 24
    router = ['10.47.0.1']  # list of ips
    ip_address_lease_time = 300  # seconds
    domain_name_server = ['10.47.0.1']  # list of ips

    server_addresses = '10.47.0.1'

    host_file = 'hosts.json'

    debug = lambda *args, **kw: None

    def __init__(self, config=None):
        if config:
            self.bind_address = '0.0.0.0'
            if "/" in config.get('network'):
                net = ipaddress.ip_network(config.get('network'))
                self.network = str(net.network_address)
                self.subnet_mask = str(net.netmask)
                self.subnet_cidr = net.prefixlen
            else:
                self.network = config.get('network', self.network)
                self.subnet_mask = config.get('netmask', self.subnet_mask)
                self.subnet_cidr = ipaddress.ip_network((0, self.subnet_mask)).prefixlen
            self.broadcast_address = config.get('broadcast', self.broadcast_address)
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
