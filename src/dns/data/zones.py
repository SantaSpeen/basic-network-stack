from core import Zone, SOA, Record, PTRZone

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

dns_server.add_zone(home)
dns_server.add_zone(home_ptr_47)
dns_server.add_zone(home_ptr_41)
dns_server.add_zone(home_ptr_168)
