import json
import time
from pathlib import Path

from loguru import logger


class Host:
    def __init__(self, mac, ip, hostname, last_used):
        self.mac = mac.upper()
        self.ip = ip
        self.hostname = hostname
        self.last_used = int(last_used)

    @classmethod
    def from_packet(cls, packet):
        return cls(packet.client_mac_address,
                   packet.requested_ip_address or packet.client_ip_address,
                   packet.host_name or '',
                   int(time.time()))

    @classmethod
    def from_tuple(cls, line):
        mac, ip, hostname, last_used = line
        last_used = int(last_used)
        return cls(mac, ip, hostname, last_used)

    def to_tuple(self) -> tuple:
        return self.mac, self.ip, self.hostname, str(int(self.last_used))

    def __eq__(self, other):
        return self.to_tuple() == other.to_tuple()

    def __str__(self):
        return f"Host(name={self.hostname} identifier=({self.mac}) @ {self.ip})"


class HostDatabase:
    def __init__(self, conf):
        self.conf = conf
        self.file = Path(self.conf.data_file)
        self.data = {'index': {'ip': {}}, 'devices': {}}
        self._read()

    def _read(self):
        if not self.file.exists():
            self._write()
        with open(self.file, "r", encoding="utf-8") as f:
            self.data = json.load(f)

    def _write(self):
        with open(self.file, "w", encoding="utf-8") as f:
            json.dump(self.data, f, indent=4)

    def get(self, ip=None, mac=None):
        if ip:
            mac = self.data['index']['ip'].get(ip)
        if self.data['devices'].get(mac):
            return Host.from_tuple(self.data['devices'][mac])

    def add(self, host: Host):
        if host.ip:
            self.data['index']['ip'][host.ip] = host.mac
        self.data['devices'][host.mac] = host.to_tuple()
        self._write()

    def delete(self, host: Host):
        if host.ip:
            del self.data['index']['ip'][host.ip]
        del self.data['devices'][host.mac]

    def all(self):
        return list(map(Host.from_tuple, self.data['devices'].values()))

    def replace(self, host):
        self.delete(host)
        self.add(host)

    def _get_free_address(self):
        if len(self.data['index']['ip']) >= self.conf.dhcp_range_len:
            logger.error("[DHCP] Range is out")
            return 0
        ip = self.conf.random_ip()
        if self.data['index']['ip'].get(ip):
            return self._get_free_address()
        return ip

    def find_or_register(self, mac, requested_ip, hostname):
        host = self.get(mac=mac)
        if host:
            if not self.conf.in_range(host.ip):
                self.delete(host)
                return self.find_or_register(mac, requested_ip, hostname)
            logger.info(f'Known device: {host}')
        new_ip = self._get_free_address()
        host = self.get(ip=requested_ip)
        if host:  # Assigned IP
            host.ip = new_ip
            self.replace(host)
            logger.info(f'Known device; New IP; {host}')
        else:
            if self.conf.in_range(requested_ip):  # IP in range, all is good
                ip = requested_ip
                logger.info(f'New(?) device; IP: {ip}. MAC: {mac}')
            else:  # ip not in range in requested_ip
                ip = new_ip
                logger.info(f'New device. IP: {ip}. MAC: {mac}')
            host = Host(mac, ip, hostname or 'UnknownName', time.time())
            self.add(host)
            logger.success(f'Device registered: {host}')
        return host.ip
