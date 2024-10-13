import json
import os
import platform
import subprocess
import sys
import time
from collections import defaultdict
from datetime import datetime

from loguru import logger

from doh import DNSOverHTTPS
from sevrer import DNSServer, Zone, Record, SOA, PTRZone

logger.remove()
system = platform.system()
if system == "Linux":
    logger.add(sys.stdout, level=0, backtrace=False, diagnose=False,
               enqueue=True, colorize=False, format="| {level: <8} | {message}")
    os.makedirs("/var/log/bns/", exist_ok=True)
    os.makedirs("/etc/bns/", exist_ok=True)
    log_path = "/var/log/bns/dns.log"
    if os.path.exists(log_path):
        creation_date = datetime.fromtimestamp(os.path.getctime(log_path)).strftime('%Y-%m-%d')
        os.rename("/var/log/bns/dns.log", f"/var/log/bns/dns_{creation_date}.log")
    logger.add(log_path, rotation="10 MB", retention="10 days", compression="zip")
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

# Spoofing youtube.com
youtube_list = (
    "youtube.com.",
    "youtu.be.",
    "yt.be.",
    "googlevideo.com.",
    "ytimg.com.",
    "ggpht.com.",
    "gvt1.com.",
    "youtube-nocookie.com.",
    "youtube-ui.l.google.com.",
    "youtubeembeddedplayer.googleapis.com.",
    "youtube.googleapis.com.",
    "youtubei.googleapis.com.",
    "yt-video-upload.l.google.com.",
    "wide-youtube.l.google.com."
)
dns_server.add_spoof(*youtube_list)

# Spoofing openai
openai_list = (
    "openai.com.",
    "chatgpt.com.",
    "oaistatic.com.",
    "oaiusercontent.com."
)
dns_server.add_spoof(*openai_list)

# Spoofing instagram (+ facebook)
meta_list = (
    "instagram.com.",
    "cdninstagram.com.",
    "facebook.com.",
    "fbcdn.net."
)
dns_server.add_spoof(*meta_list)

# Spoofing jetbrains
dns_server.add_spoof("jetbrains.com.")


# Spoofing 2ip
dns_server.add_spoof("2ip.ru.", "2ip.io.")


# Spoofing discord
discord_list = (
    "discord-attachments-uploads-prd.storage.googleapis.com",
    "dis.gd",
    "discord.co",
    "discord.com",
    "discord.media",
    "discord.design",
    "discord.dev",
    "discord.gg",
    "discord.gift",
    "discord.gifts",
    "discord.new",
    "discord.store",
    "discord.tools",
    "discord.media",
    "discordapp.com",
    "discordapp.net",
    "discordmerch.com",
    "discordpartygames.com",
    "discord-activities.com",
    "discordactivities.com",
    "discordsays.com",
    "discordstatus.com",
    "discordcdn.com"
)
dns_server.add_spoof(*discord_list)

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
dns_server.resolver.cache.tick_callbacks.append(_tick_callback)

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
