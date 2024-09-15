import argparse

from dhcp import DHCPServerConfiguration, DHCPServer

__title__ = "BasicNetworkStack"
__version__ = "0.1.0"
__build__ = "development"

parser = argparse.ArgumentParser(description=f'{__title__}\nDHCP + DNS (DoH bridge to DNS) with telegram notifications and audit.')
parser.add_argument('-v', '--version', action="store_true", help='Print version and exit.', default=False)
parser.add_argument('--config', help='Path to the config file.', nargs='?', default=None, type=str)
parser.add_argument('--mode', help='Starting mode.', nargs='?', default="normal", type=str, choices=("normal", "dhcp", "dns"))


def main():
    args, _ = parser.parse_known_args()
    if args.version:
        print(f"{__title__}:\n\tVersion: {__version__}\n\tBuild: {__build__}")
        exit(0)
    match args.mode:
        case "normal":
            print("Starting in normal mode...")
            print("Normal mode is not implemented yet.")
        case "dhcp":
            print("Starting in DHCP mode...")
            _cfg = DHCPServerConfiguration()
            _cfg.debug = print
            _cfg.adjust_if_this_computer_is_a_router()
            _cfg.ip_address_lease_time = 60
            DHCP_server = DHCPServer(_cfg)
            DHCP_server.run()
        case "dns":
            print("Starting in DNS mode...")
            print("dns mode is not implemented yet.")
        case _:
            print("Invalid mode!")
            exit(1)


if __name__ == '__main__':
    main()
