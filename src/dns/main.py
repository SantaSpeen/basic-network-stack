import time

from doh import DNSOverHTTPS
from sevrer import DNSServer, Zone, Record

doh = DNSOverHTTPS()
doh.provider = "cloudflare"
dsrv = DNSServer(None, "1.1.1.1", doh)

if __name__ == '__main__':
    home = Zone("home")
    home.add_soa("ns.home", "admin@home")
    home.add_record(Record("@", "NS", "ns.home."))
    home.add_record(Record("@", "A", "10.47.0.1"))
    home.add_record(Record("@", "A", "10.40.0.10"))
    home.add_record(Record("@", "A", "10.41.0.2"))
    home.add_record(Record("ns.home", "A", "10.47.0.1"))
    home.add_record(Record("torrent.home", "CNAME", "@"))
    dsrv.add_zone(home)
    dsrv.start()
    while dsrv.udp_server.isAlive() and dsrv.tcp_server.isAlive():
        time.sleep(1)
    dsrv.stop()
