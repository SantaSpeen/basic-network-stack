import json
import subprocess
from collections import defaultdict

from loguru import logger

from core import linux

_added = set()
_hosts = defaultdict(lambda: [])
def _callback(ip, domain):
    if ip in _added:
        return
    _added.add(ip)
    if linux:
        subprocess.run(f"ip route add {ip} dev {interface}", shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        logger.success(f"Added route for {ip};({domain}) via {interface}")
    _hosts[domain].append(ip)

def _tick_callback():
    with open("data.json", "w") as f:
        json.dump(_hosts, f, indent=4)

dns_server.add_spoof_callback(_callback)
dns_server.add_tick_callback(_tick_callback)
