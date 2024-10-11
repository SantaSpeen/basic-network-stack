import argparse
import os
import platform
import sys

from loguru import logger

from core import DHCPServer
from core import DHCPServerConfiguration

logger.remove()
logger.add(sys.stdout, level="INFO", backtrace=False, diagnose=False, enqueue=True,
           format="\r<green>{time:YYYY-MM-DD HH:mm:ss.SSS}</green> | <level>{level: <8}</level> | {message}")
os.makedirs("/var/log/bns/dhcp/", exist_ok=True)
os.makedirs("/etc/bns/", exist_ok=True)
logger.add("/var/log/bns/dhcp/info.log", rotation="10 MB", retention="10 days", compression="zip")

__title__ = "BasicNetworkStack - DHCP Module"
__version__ = "0.4.2"
__build__ = "development"

parser = argparse.ArgumentParser(description=f'{__title__}')
parser.add_argument('-v', '--version', action="store_true", help='Print version and exit.', default=False)
parser.add_argument('-c', '--config', help='Configuration file', default=None)

def init_program():
    args = parser.parse_args()
    if args.version:
        print(f"{__title__} v{__version__} ({__build__})")
        sys.exit(0)
    base_config = {
        "network": "",
        "router": "",
        "lease_time": 300,
        "domain_name_servers": [],
        "dhcp_servers": [],
        "data_file": "data.json"
    }
    config_file = "config.json"
    if platform.system() == "Linux":
        config_file = "/etc/bns/dhcp.json"
        base_config['data_file'] = "/etc/bns/dhcp-hosts.json"
    return args.config or config_file

def main():
    logger.info("Hello")
    config_file = init_program()
    cfg = DHCPServerConfiguration.from_file(config_file)
    srv = DHCPServer(cfg)
    logger.info(srv)
    srv.run()

if __name__ == '__main__':
    main()
