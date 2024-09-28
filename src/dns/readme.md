# Модуль DNS для Basic-Network-Stack

## TODO:

- [x] DNS Over HTTPS (doh)
- [x] DNS Server
- [x] doh2dns (DNS Bridge)
- [x] Caches (Only for DOH)
- [x] Local Zones
- [x] Spoofing
- [x] ipset
- [ ] Интеграция с BNS

```shell

iptables -t mangle -A PREROUTING -m set --match-set haharkn src -j MARK --set-mark 5
ip rule add fwmark 5 table 105
ip route add default dev wg0stg5 table 105

```