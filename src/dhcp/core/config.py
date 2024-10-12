import ipaddress
import json
import platform
import random
import re
import subprocess
from dataclasses import dataclass, field
from loguru import logger

from dhcppython import options


def get_range(network):
    """Get the first and last host in a network"""
    first_host = network.network_address + 1
    last_host = network.broadcast_address - 1
    return int(first_host), int(last_host)


def get_all_interfaces():
    os_type = platform.system()
    try:
        if os_type == "Windows":
            return get_windows_ips()
        elif os_type == "Linux":
            return get_linux_ips()
        else:
            raise NotImplementedError(f"OS '{os_type}' not supported")
    except Exception as e:
        logger.exception(e)


def get_windows_ips():
    ips = []
    command = "powershell -Command \"& {chcp 437; ipconfig}\""
    output = subprocess.check_output(command, shell=True)
    output = output.decode('cp437', errors='ignore')
    lines = output.splitlines()
    for line in lines:
        ip_match = re.search(r'IPv4 Address[. ]+:\s+([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)', line)
        if ip_match:
            ips.append(ip_match.group(1))
    return ips

def get_linux_ips():
    ips = []
    output = subprocess.check_output(["ip", "addr"], encoding='latin1')
    lines = output.splitlines()
    for line in lines:
        if "inet " in line:
            ip_match = re.search(r'inet ([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)', line)
            if ip_match:
                ips.append(ip_match.group(1))
    return ips

@dataclass
class DHCPServerConfiguration:
    """Class for storing the configuration of the DHCP server"""
    network: ipaddress.IPv4Network = ipaddress.ip_network('10.47.0.0/24')
    dhcp_range: tuple[int, int] = field(default_factory=lambda: (170852353, 170852606))  # 10.47.0.1, 10.47.0.254
    router: str = field(default_factory=lambda: '10.47.0.1')
    domain: str = field(default_factory=lambda: 'localnet')
    lease_time: int = 300
    domain_name_servers: set = field(default_factory=lambda: set('10.47.0.1'))
    dhcp_server_ip: ipaddress.IPv4Address = field(default_factory=lambda: None)
    data_file: str = 'hosts.json'

    @property
    def dhcp_range_len(self):
        return self.dhcp_range[1] - self.dhcp_range[0]

    def check(self):
        """Check if the configuration is valid"""
        if self.dhcp_server_ip is None:
            logger.error("No valid IPs on any interface (maybe not in DHCP network?)")
            logger.info(f"{get_all_interfaces()}")
            exit(1)
        logger.success(f"Using interface with '{self.dhcp_server_ip}' for DHCP Server.")
        s, e = ipaddress.IPv4Address(self.dhcp_range[0]), ipaddress.IPv4Address(self.dhcp_range[1])
        if s not in self.network or e not in self.network:
            logger.error(f"Bad DHCP range: '{s}'-'{e}' not in network")
            exit(1)
        if self.dhcp_range_len < 1:
            logger.error(f"Bad DHCP range: range is too small")
            exit(1)
        if ipaddress.IPv4Address(self.router) not in self.network:
            logger.warning("Router not in network")

    def in_range(self, ip):
        """Check if an IP address is in the DHCP range"""
        return ipaddress.ip_address(ip) in self.network

    def random_ip(self):
        """Return a random IP address in the DHCP range"""
        return str(ipaddress.ip_address(random.randint(*self.dhcp_range)))

    @classmethod
    def from_file(cls, filename):
        """Create a configuration object from a JSON file"""
        try:
            with open(filename) as f:
                data = json.load(f)
            data['network'] = ipaddress.ip_network(data['network'])
            if data.get('dhcp_range'):
                s, e = ipaddress.IPv4Address(data['dhcp_range'][0]), ipaddress.IPv4Address(data['dhcp_range'][1])
                data['dhcp_range'] = (int(s), int(e))
            else:
                data['dhcp_range'] = get_range(data['network'])
            if not data.get('dhcp_server_ip'):
                i = set(i for i in get_all_interfaces() if ipaddress.IPv4Address(i) in data['network'])
                if len(i) > 0:
                    data['dhcp_server_ip'] = ipaddress.IPv4Address(i.pop())
            data['domain_name_servers'] = set(data['domain_name_servers'])
            conf = cls(**data)
            conf.check()
            return conf
        except Exception as e:
            logger.exception(e)
            exit(1)


    @property
    def options(self):
        """Return the options for the configuration"""
        return options.OptionList(
            [
                options.options.short_value_to_object(1, str(self.network.netmask)),
                options.options.short_value_to_object(3, [str(self.router)]),
                options.options.short_value_to_object(6, self.domain_name_servers),
                options.options.short_value_to_object(15, self.domain),
                options.options.short_value_to_object(28, self.network.broadcast_address),
                options.options.short_value_to_object(51, self.lease_time),
                options.options.short_value_to_object(54, self.dhcp_server_ip),
                options.options.short_value_to_object(58, int(self.lease_time*0.5)),
                options.options.short_value_to_object(59, int(self.lease_time*0.875)),
            ]
        )

