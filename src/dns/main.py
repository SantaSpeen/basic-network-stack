import builtins
import time

from loguru import logger

from core import args, interface, DNSOverHTTPS, DNSServer

doh = DNSOverHTTPS(args.provider)

dns_server = DNSServer(
    doh_provider=doh,
    address=args.address,
    port=args.port,
    tcp=not args.no_tcp,
    spoof_dir=args.spoof_dir
)
# Added 'dns_server' and 'interface' into builtins for using in data.zones and data.callbacks without import
builtins.dns_server = dns_server
builtins.interface = interface

# noinspection PyUnresolvedReferences
def init_data():
    import data.zones
    import data.callbacks

init_data()

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
