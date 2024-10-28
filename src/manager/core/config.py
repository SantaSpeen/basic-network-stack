import glob
import os
import platform
import sys
import zipfile
from datetime import datetime
from pathlib import Path

import yaml
from loguru import logger

system = platform.system()
# yaml = YAML()
# yaml.default_flow_style = True

logger.remove()
if system == "Linux":
    # Logging
    log_dir = Path("/var/log/bns/")
    log_file = log_dir / "manager.log"
    os.makedirs(log_dir, exist_ok=True)
    if os.path.exists(log_file):
        ftime = os.path.getmtime(log_file)
        index = 1
        while True:
            zip_path = log_dir / f"manager-{datetime.fromtimestamp(ftime).strftime('%Y-%m-%d')}-{index}.zip"
            if not os.path.exists(zip_path):
                break
            index += 1
        with zipfile.ZipFile(zip_path, "w") as zipf:
            logs_files = glob.glob(f"{log_dir}/manager*.log")
            for file in logs_files:
                if os.path.exists(file):
                    zipf.write(file, os.path.basename(file))
                    os.remove(file)
    logger.add(sys.stdout, level=0, backtrace=False, diagnose=False, enqueue=True, colorize=False, format="| {level: <8} | {message}")
    logger.add(log_file, rotation="10 MB", retention="1 day")
    # Configurations
    os.makedirs("/etc/bns/manager", exist_ok=True)
else:
    logger.add(sys.stdout, level="INFO", backtrace=False, diagnose=False, enqueue=True,
               format="\r<green>{time:YYYY-MM-DD HH:mm:ss.SSS}</green> | <level>{level: <8}</level> | {message}")


class Strings:
    def __init__(self, strings):
        self.data = strings

    def __getitem__(self, item):
        return self.data.get(item, f"Error: unknown str: {item}. Please configure it in 'strings.yaml'")

class Config:

    def __init__(self, config_dir):
        self.config_dir = config_dir
        self.manager = {"socket": "/var/run/bns.sock"}
        self.telegram = {
            "token": "PASTE_YOUR_TOKEN",
            "admin_list": [],
            "notify": [
                "dhcp_new_device"
            ],
        }
        self._strings = {
            "unknown_command": "Unknown command.",
            "not_admin": "You are not an admin.",
            "start": "Hello. Type /help for more commands.",
            "help": "Commands:\n"
                    "/help - Show this message\n"
                    "/status - Show status about services\n"
                    "/counters - Show counters from services\n"
                    "/about - Show information about manager\n",
            "status": "Status:\n"
                      "DHCP: {0}\n"
                      "DNS: {1)\n",
            "counters": "Counters:\n"
                        "DNS Uptime: {2}\n"
                        "DNS requests: {3}\n"
                        "DNS IPs spoofed: {4}\n"
                        "DHCP Uptime: {5}\n"
                        "DHCP Active devices: {7}\n"
                        "DHCP ALL devices: {8}\n",
            "about": "BasicNetworkStack - Manager Module\n"
                     "Bot for managing services:\n"
                     "- DHCP Module\n"
                     "- DNS Module\n"
                     "Version: {0}\n"
                     "GitHub: {1}",
        }
        self.strings = Strings(self._strings)

    def load(self):
        if not os.path.exists(self.config_dir):
            os.makedirs(self.config_dir)
        mng = f"{self.config_dir}/manager.yaml"
        tlg = f"{self.config_dir}/telegram.yaml"
        strf = f"{self.config_dir}/strings.yaml"
        if os.path.exists(mng):
            with open(mng) as f:
                self.manager = yaml.full_load(f)
        else:
            with open(f"{self.config_dir}/manager.yaml", "w") as f:
                yaml.dump(self.manager, f)
            logger.success(f"File {mng!r} generated")

        if os.path.exists(tlg):
            with open(tlg) as f:
                self.telegram = yaml.full_load(f)
        else:
            with open(tlg, "w") as f:
                yaml.dump(self.telegram, f)
            logger.success(f"File {tlg!r} generated")

        if os.path.exists(strf):
            with open(strf) as f:
                self._strings = yaml.full_load(f)
                self.strings = Strings(self._strings)
        else:
            with open(strf, "w") as f:
                yaml.dump(self._strings, f)
            logger.success(f"File {strf!r} generated")
        logger.success("Config files loaded")