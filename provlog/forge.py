#!/usr/bin/env python3
"""Tamper test 4: an attacker WITH the key rewrites one entry and re-signs the rest.
Usage: forge.py IN.jsonl OUT.jsonl SEQ OLD NEW"""
import hashlib, hmac, json, os, sys
KEY = open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "log.key"), "rb").read().strip()
canon = lambda o: json.dumps(o, sort_keys=True, separators=(",", ":"))
src, dst, seq, old, new = sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4], sys.argv[5]
entries = [json.loads(l) for l in open(src) if l.strip()]
prev, out = "0" * 64, []
for e in entries:
    e.pop("hash")
    if e["seq"] == seq:
        e = json.loads(canon(e).replace(old, new))
    e["prev"] = prev
    e["hash"] = hmac.new(KEY, canon(e).encode(), hashlib.sha256).hexdigest()
    prev = e["hash"]
    out.append(canon(e))
open(dst, "w").write("\n".join(out) + "\n")
print("forged seq %d and re-signed %d entries -> %s" % (seq, len(out), dst))
