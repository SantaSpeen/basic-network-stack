import json
import time
from pathlib import Path


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

    def has_valid_ip(self):
        return self.ip and self.ip != '0.0.0.0'


class HostDatabase:
    def __init__(self, file_name):
        self.file = Path(file_name)
        self.data = {'index': {'ip': {}}, 'devices': {}}
        self._read()

    def _read(self):
        if not self.file.exists():
            self._write()
        with open(self.file, "r", encoding="utf-8") as f:
            self.data = json.load(f)

    def _write(self):
        with open(self.file, "w", encoding="utf-8") as f:
            json.dump(self.data, f)

    def get(self, ip=None, mac=None):
        if not all((ip, mac)):
            return self.all()
        if ip:
            mac = self.data['ip'][ip]
        if mac:
            return Host.from_tuple(*self.data['devices'][mac])

    def add(self, host: Host):
        if host.ip:
            self.data['index']['ip'][host.ip] = host.mac
        self.data['devices'][host.mac] = host.to_tuple()
        self._write()

    def delete(self, host: Host):
        if host.ip:
            self.data['index']['ip'][host.ip] = None
        self.data['devices'][host.mac] = None

    def all(self):
        return list(map(Host.from_tuple, self.data['devices'].values()))

    def replace(self, host):
        self.delete(host)
        self.add(host)
