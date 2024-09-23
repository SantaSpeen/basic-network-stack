#!/bin/python3
import argparse
import os
import re
import sys
import textwrap
from pathlib import Path

from loguru import logger

from core.dhcp import DHCPServerConfiguration, DHCPServer
from ruamel.yaml import YAML

__title__ = "BasicNetworkStack"
__version__ = "0.1.0"
__build__ = "development"

parser = argparse.ArgumentParser(description=f'{__title__}\nDHCP + DNS (DoH bridge to DNS) with telegram notifications and audit.')
parser.add_argument('-v', '--version', action="store_true", help='Print version and exit.', default=False)
parser.add_argument('--config', help='Path to the config file.', nargs='?', default="config.yml", type=str)
parser.add_argument('--mode', help='Starting mode.', nargs='?', default="normal", type=str, choices=("normal", "dhcp", "dns"))

logger.remove()
logger.add(sys.stdout, level="INFO", backtrace=False, diagnose=False,
           format="\r<green>{time:YYYY-MM-DD HH:mm:ss.SSS}</green> | <level>{level: <8}</level> | {message}")

yaml = YAML()


class Config:

    def __init__(self, config_file: str):
        self._file = Path(config_file)
        self._raw = {}
        self.dhcp = None
        self.dns = None
        self.telegram = None
        self._load()

    def _load(self):
        if self._file.is_file():
            _raw = yaml.load(self._file)
            if not _raw:
                logger.error(f"Error while loading '{self._file}': File is empty")
                logger.warning("Removing it...")
                os.remove(self._file)
                return self._load()
            if not isinstance(_raw, dict):
                logger.error(f"Error while loading '{self._file}': Bad file-type. Remove it or fix.")
                exit(1)
            self._raw = _raw
            self.dhcp = _raw.get("dhcp")
            self.dns = _raw.get("dns")
            self.telegram = _raw.get("telegram")
            if self.telegram and self.telegram.get("token"):
                if not re.match(r"[0-9]{1,}:[a-zA-Z0-9_-]{35}", self.telegram["token"]):
                    logger.error("Error while loading: Bad telegram token.")
                    exit(1)
            logger.success("Configuration loaded.")
        else:
            logger.info("Generating new config file..")
            with open(self._file, "w", encoding="utf-8") as f:
                f.write(textwrap.dedent("""\
                    dhcp:
                        network: 10.47.0.0/24
                        router: 10.47.0.1
                        dns_servers: [8.8.8.8, 8.8.4.4]
                        lease_time: 300
                        broadcast: 10.0.0.255
                        server_addresses: [10.0.0.1]
                        hosts_file: hosts.csv

                    doh:
                        enabled: false  # WIP

                    telegram:
                      token: null # Bot token
                      admin: null  # tg_id of admin user (or list of ids)
                    """))
            logger.success(f"Config file generated. File: '{self._file}'")
            return self._load()


def main():
    logger.info("Hello.. Starting the Basic Network Stack...")
    args, _ = parser.parse_known_args()
    if args.version:
        print(f"{__title__}:\n\tVersion: {__version__}\n\tBuild: {__build__}")
        exit(0)
    config = Config(args.config)
    dhcp_cfg = DHCPServerConfiguration(config.dhcp)
    match args.mode:
        case "normal":
            logger.info("Starting in normal mode...")
            logger.warning("Normal mode is not implemented yet.")
        case "dhcp":
            logger.info("Starting in DHCP mode...")
            dhcp_cfg.debug = print
            dhcp_server = DHCPServer(dhcp_cfg)
            dhcp_server.run()
        case "dns":
            logger.info("Starting in DNS mode...")
            logger.warning("dns mode is not implemented yet.")
        case _:
            print("Invalid mode!")
            exit(1)


if __name__ == '__main__':
    main()
