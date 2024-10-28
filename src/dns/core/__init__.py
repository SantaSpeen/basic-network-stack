import argparse
import glob
import os
import re
import subprocess
import zipfile
import sys
import platform
from datetime import datetime
from pathlib import Path

from loguru import logger

from .doh import DNSOverHTTPS
from .sevrer import DNSServer, Zone, Record, SOA, PTRZone

logger.remove()
system = platform.system()
# Linux - Prod
#  else - Test
linux = system == "Linux"
if linux:
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
    logger.add(log_file, rotation="10 MB", retention="1 day")
    # Configurations
    os.makedirs("/etc/bns/dns_spoof", exist_ok=True)
else:
    logger.add(sys.stdout, level="INFO", backtrace=False, diagnose=False, enqueue=True,
               format="\r<green>{time:YYYY-MM-DD HH:mm:ss.SSS}</green> | <level>{level: <8}</level> | {message}")

__title__ = "[BNS] DNS Service"
__version__ = "1.0.3"
__build__ = "stable"

parser = argparse.ArgumentParser(description=f'{__title__}')
parser.add_argument('-v', '--version', action="store_true", help='Print version and exit.', default=False)
# parser.add_argument('-c', '--config', help='Configuration file', default=None)
parser.add_argument('-d', '--vpn', help='Interface for VPN.', default=None)
parser.add_argument('--address', help='DNS Server IP-Address.', default="0.0.0.0")
parser.add_argument('--port', help='DNS Server Port.', default=53)
parser.add_argument('--provider', help='DOH Provider for DNS Server.', default="cloudflare", choices=['cloudflare', 'opendns', 'quad9', 'google'])
parser.add_argument('--no-tcp', action="store_true", help='Do not enable TCP mode.', default=False)
_spoof_dir = "-etc-bns-dns_spoof"
if linux:
    _spoof_dir = "/etc/bns/dns_spoof"
parser.add_argument('--spoof-dir', help='Directory with *.spoof files with domains.', default=_spoof_dir)

args = parser.parse_args()
if args.version:
    print(f"{__title__} v{__version__} ({__build__})")
    exit(0)
logger.info(f"Starting {__title__} v{__version__} ({__build__})")

interface = args.vpn

def get_linux_interfaces():
    output = subprocess.check_output(["ip", "link"], encoding='utf-8')
    interfaces = re.findall(r'^\d+: (\w+):', output, re.MULTILINE)
    return interfaces

def restart_interface(iface):
    subprocess.run(f"ip link set {iface} down", shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    subprocess.run(f"ip link set {iface} up", shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

def activate_masquerade(iface):
    try:
        check_nat_cmd = f"iptables-save | grep -q 'POSTROUTING.*-o {iface}.*MASQUERADE'"
        nat_exists = subprocess.call(check_nat_cmd, shell=True) == 0
        if not nat_exists:
            logger.info(f"Activating masquerade for '{iface}'")
            os.system(f"iptables -t nat -A POSTROUTING -o {iface} -j MASQUERADE")
        else:
            logger.info(f"Masquerade already active for '{iface}'")
    except Exception as e:
        logger.error(f"Error activating masquerade: {e}")

# init interface (only for linux)
if linux:
    # validate interface
    if not interface:
        logger.error(f"Bad interface (use --vpn).")
        exit(1)
    if interface not in get_linux_interfaces():
        logger.error(f"Interface not found: {interface}")
        logger.info(f"Available: {get_linux_interfaces()}")
        exit(1)
    # reset routes
    restart_interface(interface)
    # activate masquerade
    activate_masquerade(interface)