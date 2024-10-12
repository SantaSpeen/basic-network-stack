import json
import time
from pathlib import Path
from threading import Thread

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
        return f"Host(name='{self.hostname}' identifier=({self.mac} @ {self.ip})"


class HostDatabase:
    def __init__(self, conf):
        self.t = None
        self.run = True
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
            mac = self.data['index']['ip'].get(str(ip))
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

    def flush(self):
        now = time.time()
        for host in self.all():
            if host.last_used == 0:
                continue
            if now - host.last_used > self.conf.lease_time:
                self.delete(host)
        self._write()

    def _auto_deleter(self):
        while self.run:
            self.flush()
            i_max = self.conf.lease_time/10
            i = 0
            while i < i_max:
                time.sleep(1)
                i += 1
                if not self.run:
                    return

    def auto_deleter(self):
        self.t = Thread(target=self._auto_deleter, daemon=True)
        self.t.start()

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
            return host.ip
        if self.conf.in_range(requested_ip) and self.get(ip=requested_ip) is None:
            ip = requested_ip
            logger.info(f'New(?) device; IP: {ip}. MAC: {mac}')
        else:
            ip = self._get_free_address()
            logger.info(f'New device. IP: {ip}. MAC: {mac}')
        host = Host(mac, ip, hostname or 'UnknownName', time.time())
        self.add(host)
        logger.success(f'Device registered: {host}')
        return host.ip
