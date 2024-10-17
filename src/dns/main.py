import glob
import json
import os
import platform
import subprocess
import sys
import time
import zipfile
from collections import defaultdict
from datetime import datetime
from pathlib import Path

from loguru import logger

from doh import DNSOverHTTPS
from sevrer import DNSServer, Zone, Record, SOA, PTRZone

logger.remove()
system = platform.system()
if system == "Linux":
    # Logging
    log_dir = Path("/var/log/bns/")
    log_file = log_dir / "dns.log"
    os.makedirs(log_dir, exist_ok=True)
    if os.path.exists(log_file):
        ftime = os.path.getmtime(log_file)
        index = 1
        while True:
            zip_path = log_dir / f"dns-{datetime.fromtimestamp(ftime).strftime('%Y-%m-%d')}-{index}.zip"
            if not os.path.exists(zip_path):
                break
            index += 1
        with zipfile.ZipFile(zip_path, "w") as zipf:
            logs_files = glob.glob(f"{log_dir}/dns*.log")
            for file in logs_files:
                if os.path.exists(file):
                    zipf.write(file, os.path.basename(file))
                    os.remove(file)
    logger.add(sys.stdout, level=0, backtrace=False, diagnose=False, enqueue=True, colorize=False, format="| {level: <8} | {message}")
    logger.add(log_file, rotation="10 MB", retention="10 days", compression="zip")
    # Configurations
    os.makedirs("/etc/bns/dns_spoof", exist_ok=True)
else:
    logger.add(sys.stdout, level="INFO", backtrace=False, diagnose=False, enqueue=True,
               format="\r<green>{time:YYYY-MM-DD HH:mm:ss.SSS}</green> | <level>{level: <8}</level> | {message}")


doh = DNSOverHTTPS("cloudflare")

# Home zone
home = Zone("home", SOA("ns.home", "santaspeen@yandex.ru"))
records = (
    Record("@", "NS", "ns.home."),
    Record("ns.home", "A", "10.47.0.1"),
    Record("lilrt.home", "A", "10.47.0.1"),
    Record("lilrt.home", "A", "10.41.0.2"),
    Record("torrent.home", "CNAME", "lilrt.home."),
    Record("nginx.home", "CNAME", "lilrt.home."),
    Record("lako.home", "A", "192.168.0.10"),
    Record("lako.home", "A", "192.168.0.11"),
    Record("nginx.lako.home", "CNAME", "lako.home."),
    Record("torrent.lako.home", "CNAME", "lako.home."),
)
home.add_records(*records)

home_ptr_47 = PTRZone("10.47.0")
home_ptr_47.add("1", "ns.home.")
home_ptr_47.add("1", "lilrt.home.")
home_ptr_41 = PTRZone("10.41.0")
home_ptr_41.add("2", "lilrt.home.")
home_ptr_168 = PTRZone("192.168.0")
home_ptr_168.add("10", "lako.home.")
home_ptr_168.add("11", "lako.home.")

dns_server = DNSServer(
    home, home_ptr_47, home_ptr_41, home_ptr_168,
     doh_provider=doh
)


def read_domains_from_files(directory):
    logger.info("Reading domains for spoofing from files")
    domains = []
    for filename in os.listdir(directory):
        file_path = os.path.join(directory, filename)
        if not os.path.isfile(file_path):
            continue
        if not filename.endswith('.spoof'):
            logger.warning(f"Skipping '{filename}'")
            continue
        with open(file_path, 'r', encoding='utf-8') as f:
            file_domains = f.readlines()
        domains.extend([domain.strip() for domain in file_domains])
        logger.success(f"Read {len(file_domains)} domains from '{filename}'")
    logger.success(f"Read {len(domains)} domains in total.")
    return domains


spoof_dir = "-etc-bns-dns_spoof"
if system == "Linux":
    spoof_dir = "/etc/bns/dns_spoof"
dns_server.add_spoof(*read_domains_from_files(spoof_dir))

_added = set()
_hosts = defaultdict(lambda: [])
interface = "wg0stg5"

# restart interface (reset routes)
if system == "Linux":
    subprocess.run(f"ip link set {interface} down", shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    subprocess.run(f"ip link set {interface} up", shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

def _callback(ip, domain):
    if ip in _added:
        return
    _added.add(ip)
    if system == "Linux":
        route_cmd = f"ip route add {ip} dev {interface}"
        subprocess.run(route_cmd, shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        logger.success(f"Added route for {ip};({domain}) via {interface}")
    _hosts[domain].append(ip)

def _tick_callback():
    with open("data.json", "w") as f:
        json.dump(_hosts, f, indent=4)

dns_server.add_spoof_callback(_callback)
dns_server.add_tick_callback(_tick_callback)

if __name__ == '__main__':
    try:
        dns_server.start()
        while dns_server.is_alive():
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    except Exception as e:
        logger.exception(e)
    finally:
        dns_server.stop()
