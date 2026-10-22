ip link del br0 2>/dev/null
ip link add name br0 type bridge
ip link set br0 up
ip link set h3-eth0 master br0
ip link set h3-eth1 master br0
echo 16384 > /sys/class/net/br0/bridge/group_fwd_mask
echo "relay is up:"; ip -br link show master br0
