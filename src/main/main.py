import argparse

from loguru import logger

from config import Config
from core.dhcp import DHCPServerConfiguration, DHCPServer

__title__ = "BasicNetworkStack"
__version__ = "0.1.0"
__build__ = "development"

parser = argparse.ArgumentParser(description=f'{__title__}\nDHCP + DNS (DoH bridge to DNS) with telegram notifications and audit.')
parser.add_argument('-v', '--version', action="store_true", help='Print version and exit.', default=False)
parser.add_argument('--config', help='Path to the config file.', nargs='?', default="config.yml", type=str)
parser.add_argument('--mode', help='Starting mode.', nargs='?', default="normal", type=str, choices=("normal", "dhcp", "dns"))


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
