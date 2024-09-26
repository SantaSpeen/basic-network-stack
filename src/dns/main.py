import time

from doh import DNSOverHTTPS
from sevrer import DNSServer, Zone, Record

doh = DNSOverHTTPS()
doh.provider = "cloudflare"
dns_server = DNSServer(None, "1.1.1.1", doh)

if __name__ == '__main__':

    home = Zone("home")
    home.add_soa("ns.home", "admin@home")
    home.add_record(Record("@", "NS", "ns.home."))
    home.add_record(Record("@", "A", "10.47.0.1"))
    home.add_record(Record("@", "A", "10.40.0.10"))
    home.add_record(Record("@", "A", "10.41.0.2"))
    home.add_record(Record("ns.home", "A", "10.47.0.1"))
    home.add_record(Record("torrent.home", "CNAME", "@"))

    dns_server.add_zone(home)
    dns_server.start()
    while dns_server.is_alive():
        time.sleep(1)
    dns_server.stop()
