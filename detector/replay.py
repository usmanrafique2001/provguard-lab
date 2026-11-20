#!/usr/bin/env python3
"""Replay the v2 tamper-evident log and run the detector's two checks on it.
The log is verified first. If verification fails, every finding is marked UNTRUSTED."""
import json, os, sys, time

HERE = os.path.dirname(os.path.abspath(__file__))
PROVLOG = os.path.join(HERE, "..", "provlog")
sys.path.insert(0, PROVLOG)
from verify import verify

def when(ts):
    return time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(ts))

def replay(log_path, key, anchors_path=None):
    problems = verify(log_path, key, anchors_path)
    tag = ""
    if problems:
        print("[!] LOG FAILED VERIFICATION - findings below cannot be trusted:")
        for p in problems:
            print("    " + p)
        tag = "UNTRUSTED "
    else:
        print("[*] log verified" + (" against checkpoints" if anchors_path else ""))

    state = {"links": [], "devices": [], "acl": []}
    ever_host_ports, dev_location, alerted = {}, {}, set()
    findings = 0
    with open(log_path) as f:
        for line in f:
            if not line.strip():
                continue
            e = json.loads(line)
            state[e["source"]] = e["state"]
            where = "seq %d, %s" % (e["seq"], when(e["ts"]))

            devices = state["devices"]
            if isinstance(devices, dict):
                devices = devices.get("devices", [])
            dev_by_ip = {}
            for d in devices:
                ips = d.get("ipv4", []); macs = d.get("mac", [])
                label = ips[0] if ips else (macs[0] if macs else "?")
                for ip in ips:
                    dev_by_ip[ip] = d
                for ap in d.get("attachmentPoint", []):
                    ever_host_ports[(ap["switchDPID"], ap["port"])] = label

            link_ports = set()
            for l in state["links"]:
                link_ports.add((l["src-switch"], l["src-port"]))
                link_ports.add((l["dst-switch"], l["dst-port"]))
            for port in sorted(link_ports):
                if port in ever_host_ports and ("linkfab", port) not in alerted:
                    alerted.add(("linkfab", port)); findings += 1
                    print("\n[%sALERT] LINK FABRICATION (%s)" % (tag, where))
                    print("  switch %s port %s was a HOST attachment (%s)" % (port[0], port[1], ever_host_ports[port]))
                    print("  but now appears as a switch-to-switch LINK endpoint -> LLDP relay suspected.")

            for rule in state["acl"]:
                if rule.get("action") != "DENY":
                    continue
                src = rule.get("nw_src", "").split("/")[0]
                dst = rule.get("nw_dst", "").split("/")[0]
                dev = dev_by_ip.get(src)
                if not dev or not dev.get("attachmentPoint"):
                    continue
                cur = dev["attachmentPoint"][0]["switchDPID"]
                prev = dev_location.get(src)
                dev_location[src] = cur
                if prev and prev != cur and ("bypass", src, dst, cur) not in alerted:
                    alerted.add(("bypass", src, dst, cur)); findings += 1
                    print("\n[%sALERT] POSSIBLE ACL BYPASS (%s)" % (tag, where))
                    print("  host %s moved %s -> %s while DENY %s->%s was active." % (src, prev, cur, src, dst))
    print("\n[*] %d finding(s)" % findings)
    return findings, problems

if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit("usage: replay.py EVENTS.jsonl [ANCHORS.jsonl]")
    key = open(os.path.join(PROVLOG, "log.key"), "rb").read().strip()
    findings, problems = replay(sys.argv[1], key, sys.argv[2] if len(sys.argv) > 2 else None)
    sys.exit(2 if problems else 0)
