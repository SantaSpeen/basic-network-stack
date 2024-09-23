import argparse
import json
import signal
import sys
import time
from os import getenv
from threading import Thread

import redis
from loguru import logger
from redis import Redis

from core import DHCPServer
from core import DHCPServerConfiguration

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

class Manage:
    def __init__(self, dhcp_server: DHCPServer):
        self.lthread = Thread(target=self._listener)
        self._config = None
        self.run = True
        self.dhcp_server = dhcp_server
        logger.info("Connecting to redis..")
        self.redis = Redis(
            host=getenv("REDIS_HOST", "127.0.0.1"),
            port=int(getenv("REDIS_PORT", "6379")),
            db=int(getenv("REDIS_DB", "0"))
        )
        try:
            version = self.redis.info()['redis_version']
            logger.success(f"Connected to redis server: v{version}")
        except redis.exceptions.ConnectionError as e:
            logger.exception(e)
            exit(1)

    def _listener(self):
        while self.run:
            try:
                task = self.redis.blpop(['dhcp'], timeout=3)
                if task is None:
                    continue
                act, data = task.split(b":", 1)
                match act:
                    case b"config":
                        self._config = json.loads(data)
                    case b"stop":
                        self.stop()
                    case _:
                        logger.warning(f"Unknown act in dhcp channel: {task!r}")
            except Exception as e:
                logger.exception(e)

    def listener(self):
        self.lthread.start()

    def callback(self, message: dict):
        # 0 - bot
        # 1 - dhcp
        # 2 - dns
        self.redis.rpush("main", f"1:{json.dumps(message)}")

    def config(self, cfg: DHCPServerConfiguration):
        logger.info("Waiting config from bns-main.")
        i = 0
        while self._config is None:
            time.sleep(1)
            if i > 30:
                logger.error("TIMEOUT")
                self.stop()
                break
            i+=1
        logger.success("Config received.")
        self.dhcp_server.print_configuration()

    def start(self):
        pass

    def stop(self, *a):
        self.run = False
        self.dhcp_server.close(None)
        logger.info("Goodbye")


def main():
    logger.info("Hello")
    cfg = DHCPServerConfiguration()
    srv = DHCPServer(cfg)
    if docker_mode:
        logger.info("Entered in Docker mode.")
        mng = Manage(srv)
        signal.signal(signal.SIGINT, mng.stop)
        signal.signal(signal.SIGTERM, mng.stop)
        mng.listener()
        mng.config(cfg)
        mng.start()
        mng.lthread.join()
    else:
        logger.info("Using test mode with default settings")
        cfg.server_addresses = ['10.47.0.1']
        srv.print_configuration()
        srv.run()

if __name__ == '__main__':
    main()
