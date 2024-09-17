import argparse
import sys
from os import getenv
from loguru import logger

from core import DHCPServer
from core import DHCPServerConfiguration
import redis
logger.remove()
logger.add(sys.stdout, level="INFO", backtrace=False, diagnose=False,
           format="\r<green>{time:YYYY-MM-DD HH:mm:ss.SSS}</green> | <level>{level: <8}</level> | {message}")
# TODO: log in file

docker_mode = False
if getenv("IN_DOCKER"):
    docker_mode = True

__title__ = "BasicNetworkStack - DHCP Module"
__version__ = "0.4.2"
__build__ = "development"

parser = argparse.ArgumentParser(description=f'{__title__}')
parser.add_argument('-v', '--version', action="store_true", help='Print version and exit.', default=False)

def main():
    cfg = DHCPServerConfiguration()
    if docker_mode:
        pass # TODO: Wait config from main via redis
    else:
        logger.info("Using test mode with default settings")
        cfg.server_addresses = ['10.47.0.1']
    dhcp_server = DHCPServer(cfg)
    dhcp_server.run()

if __name__ == '__main__':
    main()
