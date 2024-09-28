import os
import sys
import time
from ezipset import ezIPSet
from loguru import logger

from doh import DNSOverHTTPS
from sevrer import DNSServer, Zone, Record, SOA

logger.remove()
logger.add(sys.stdout, level="INFO", backtrace=False, diagnose=False, enqueue=True,
           format="\r<green>{time:YYYY-MM-DD HH:mm:ss.SSS}</green> | <level>{level: <8}</level> | {message}")
os.makedirs("/var/log/bns/dns/", exist_ok=True)
logger.add("/var/log/bns/dns/info.log", rotation="10 MB", retention="10 days", compression="zip")

ipset = ezIPSet()
doh = DNSOverHTTPS()
doh.provider = "google"

# Home zone
home = Zone("home", SOA("ns.home", "admin@home"))
home.add_record(Record("@", "NS", "ns.home."))
home.add_record(Record("@", "A", "10.47.0.1"))
home.add_record(Record("@", "A", "10.40.0.10"))
home.add_record(Record("@", "A", "10.41.0.2"))
home.add_record(Record("ns.home", "A", "10.47.0.1"))
home.add_record(Record("torrent.home", "CNAME", "@"))

dns_server = DNSServer([home], "8.8.8.8", doh)

# Spoofing youtube.com
dns_server.add_spoof("youtube.com.")
dns_server.add_spoof("youtu.be.")
dns_server.add_spoof("yt.be.")
dns_server.add_spoof("googlevideo.com.")
dns_server.add_spoof("ytimg.com.")
dns_server.add_spoof("ggpht.com.")
dns_server.add_spoof("gvt1.com.")
dns_server.add_spoof("youtube-nocookie.com.")
dns_server.add_spoof("youtube-ui.l.google.com.")
dns_server.add_spoof("youtubeembeddedplayer.googleapis.com.")
dns_server.add_spoof("youtube.googleapis.com.")
dns_server.add_spoof("youtubei.googleapis.com.")
dns_server.add_spoof("yt-video-upload.l.google.com.")
dns_server.add_spoof("wide-youtube.l.google.com.")

# Spoofing openai
dns_server.add_spoof("openai.com.")
dns_server.add_spoof("chatgpt.com.")
dns_server.add_spoof("oaistatic.com.")
dns_server.add_spoof("oaiusercontent.com.")

# Spoofing instagram (+ facebook)
dns_server.add_spoof("instagram.com.")
dns_server.add_spoof("cdninstagram.com.")
dns_server.add_spoof("facebook.com.")
dns_server.add_spoof("fbcdn.net.")

# Spoofing jetbrains
dns_server.add_spoof("jetbrains.com.")

# Spoofing github (+ copilot)
dns_server.add_spoof("github")
dns_server.add_spoof("copilot")

def _callback(ip, domain):
    ipset.add_entry('haharkn', ip, comment=domain, ignore_if_exists=True)

# Configure ipset
if 'haharkn' not in ipset.set_names:
    c = ipset.create_set("haharkn", "hash:ip", with_comment=True)
    logger.info(f"ipset 'haharkn' created: {c}")
dns_server.add_spoof_callback(_callback)

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
