import argparse
import glob
import json
import os
import platform
import subprocess
import sys
import zipfile
from datetime import datetime
from pathlib import Path

from loguru import logger

from core import DHCPServer
from core import DHCPServerConfiguration

logger.remove()
system = platform.system()
if system == "Linux":
    # Logging
    log_dir = Path("/var/log/bns/")
    log_file = log_dir / "dhcp.log"
    os.makedirs(log_dir, exist_ok=True)
    if os.path.exists(log_file):
        ftime = os.path.getmtime(log_file)
        index = 1
        while True:
            zip_path = log_dir / f"dhcp-{datetime.fromtimestamp(ftime).strftime('%Y-%m-%d')}-{index}.zip"
            if not os.path.exists(zip_path):
                break
            index += 1
        with zipfile.ZipFile(zip_path, "w") as zipf:
            logs_files = glob.glob(f"{log_dir}/dhcp*.log")
            for file in logs_files:
                if os.path.exists(file):
                    zipf.write(file, os.path.basename(file))
                    os.remove(file)
    logger.add(sys.stdout, level=0, backtrace=False, diagnose=False, enqueue=True, colorize=False, format="| {level: <8} | {message}")
    logger.add(log_file, rotation="10 MB", retention="1 day")
    # Configurations
    os.makedirs("/etc/bns/", exist_ok=True)
else:
    logger.add(sys.stdout, level="INFO", backtrace=False, diagnose=False, enqueue=True,
               format="\r<green>{time:YYYY-MM-DD HH:mm:ss.SSS}</green> | <level>{level: <8}</level> | {message}")


__title__ = "[BNS] DHCP Service"
__version__ = "1.0.1"
__build__ = "stable"

parser = argparse.ArgumentParser(description=f'{__title__}')
parser.add_argument('-v', '--version', action="store_true", help='Print version and exit.', default=False)
parser.add_argument('-c', '--config', help='Configuration file', default=None)
parser.add_argument('-m', '--masquerade', help='Interfaces for masquerade (ex: eth0,eth1)', default=None)
args = parser.parse_args()


def init_program():
    if args.version:
        print(f"{__title__} v{__version__} ({__build__})")
        sys.exit(0)
    base_config = {
        "network": "10.47.0.0/24",
        "dhcp_range": ["10.47.0.2", "10.47.0.255"],
        "router": "10.47.0.1",
        "domain": "localnet",
        "lease_time": 300,
        "domain_name_servers": ["10.47.0.1"],
        "data_file": "data.json"
    }
    config_file = "config.json"
    if platform.system() == "Linux":
        os.makedirs("/etc/bns/", exist_ok=True)
        config_file = "/etc/bns/dhcp.json"
        base_config['data_file'] = "/etc/bns/dhcp-hosts.json"
    config_file = Path(args.config or config_file)
    if not config_file.exists():
        logger.info(f"Creating default configuration file: {config_file}")
        with open(config_file, "w") as f:
            json.dump(base_config, f, indent=4)

    return config_file

def activate_masquerade(out_iface):
    try:
        # logger.info(f"Checking if masquerade is already active for '{out_iface}'")
        check_nat_cmd = f"iptables-save | grep -q 'POSTROUTING.*-o {out_iface}.*MASQUERADE'"
        nat_exists = subprocess.call(check_nat_cmd, shell=True) == 0
        if not nat_exists:
            logger.info(f"Activating masquerade for '{out_iface}'")
            os.system(f"iptables -t nat -A POSTROUTING -o {out_iface} -j MASQUERADE")
        else:
            logger.info(f"Masquerade already active for '{out_iface}'")
    except Exception as e:
        logger.error(f"Error activating masquerade: {e}")

def main():
    logger.info(f"Starting {__title__} v{__version__} ({__build__})")
    config_file = init_program()
    cfg = DHCPServerConfiguration.from_file(config_file)
    srv = DHCPServer(cfg)
    if args.masquerade:
        [activate_masquerade(inf) for inf in args.masquerade.split(",")]
    logger.info(srv)
    srv.start()

if __name__ == '__main__':
    main()
