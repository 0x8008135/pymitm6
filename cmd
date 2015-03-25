sudo python2 pymitm6.py -bad 2001:6f8:608:ace::/64 -good 2001:6f8:608:fab::/64 -dns4 8.8.8.8 -dns6 2001:6f8:608:fab::2 -tun nat64 -int eth2 -pool 192.168.100.0/24 -mktun
