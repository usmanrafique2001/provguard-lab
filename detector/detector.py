#!/usr/bin/env python3
"""Mini ProvGuard-style detector. Polls Floodlight, keeps a short history,
and flags two control-policy-manipulation signals:
  1. LINK FABRICATION - a port that was ever a host attachment now also
     appears as a switch-to-switch link endpoint (impossible for a real port).
  2. ACL BYPASS - a host with an active DENY rule moved to a new switch
     where no matching drop flow exists.
"""
import json, time, urllib.request

BASE = "http://127.0.0.1:8080"

def get(path):
    with urllib.request.urlopen(BASE + path, timeout=5) as r:
        return json.load(r)

ever_host_ports = {}
dev_location = {}
alerted = set()

def poll():
    try:
        devices = get("/wm/device/")
        links = get("/wm/topology/links/json")
        acl = get("/wm/acl/rules/json")
    except Exception as e:
        print("poll error:", e); return

    dev_by_ip = {}
    for d in devices:
        ips = d.get("ipv4", []); macs = d.get("mac", [])
        label = ips[0] if ips else (macs[0] if macs else "?")
        for ip in ips: dev_by_ip[ip] = d
        for ap in d.get("attachmentPoint", []):
            ever_host_ports[(ap["switchDPID"], ap["port"])] = label

    link_ports = set()
    for l in links:
        link_ports.add((l["src-switch"], l["src-port"]))
        link_ports.add((l["dst-switch"], l["dst-port"]))

    for key in link_ports:
        if key in ever_host_ports and ("linkfab", key) not in alerted:
            alerted.add(("linkfab", key))
            print("\n[ALERT] LINK FABRICATION")
            print("  switch %s port %s was a HOST attachment (%s)" % (key[0], key[1], ever_host_ports[key]))
            print("  but now appears as a switch-to-switch LINK endpoint -> LLDP relay suspected.")

    for rule in acl:
        if rule.get("action") != "DENY": continue
        src = rule.get("nw_src","").split("/")[0]; dst = rule.get("nw_dst","").split("/")[0]
        dev = dev_by_ip.get(src)
        if not dev or not dev.get("attachmentPoint"): continue
        cur = dev["attachmentPoint"][0]["switchDPID"]; prev = dev_location.get(src)
        dev_location[src] = cur
        if prev and prev != cur:
            try: flows = json.dumps(get("/wm/core/switch/%s/flow/json" % cur)).lower()
            except Exception: flows = ""
            if not (src in flows and dst in flows and "drop" in flows):
                if ("bypass", src, dst, cur) not in alerted:
                    alerted.add(("bypass", src, dst, cur))
                    print("\n[ALERT] ACL BYPASS")
                    print("  host %s moved %s -> %s; DENY %s->%s active but no drop flow at new switch." % (src, prev, cur, src, dst))

def main():
    print("detector running (Ctrl+C to stop)...")
    while True:
        poll(); time.sleep(3)

if __name__ == "__main__":
    main()
