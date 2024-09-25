from doh import DNSOverHTTPS

doh = DNSOverHTTPS()

if __name__ == '__main__':
    print(doh.resolve("youtube.com"))
