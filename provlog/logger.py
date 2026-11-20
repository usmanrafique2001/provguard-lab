#!/usr/bin/env python3
"""Poll Floodlight and append state changes to a hash-chained, HMAC-keyed log."""
import hashlib, hmac, json, sys, time, urllib.request

CTRL = "http://127.0.0.1:8080"
SOURCES = {
    "links":   "/wm/topology/links/json",
    "devices": "/wm/device/",
    "acl":     "/wm/acl/rules/json",
}
LOG = sys.argv[1] if len(sys.argv) > 1 else "events.jsonl"
KEY = open("log.key", "rb").read().strip()
GENESIS = "0" * 64
NOISY = {"lastSeen"}  # fields that change on every packet

def canon(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))

def strip(obj):
    if isinstance(obj, dict):
        return {k: strip(v) for k, v in obj.items() if k not in NOISY}
    if isinstance(obj, list):
        return [strip(v) for v in obj]
    return obj

def fetch(path):
    with urllib.request.urlopen(CTRL + path, timeout=5) as r:
        return strip(json.load(r))

def tail(path):
    last = None
    try:
        with open(path) as f:
            for line in f:
                if line.strip():
                    last = line
    except FileNotFoundError:
        pass
    if last is None:
        return -1, GENESIS
    e = json.loads(last)
    return e["seq"], e["hash"]

def append(path, source, state):
    seq, prev = tail(path)
    body = {"seq": seq + 1, "ts": time.time(), "source": source,
            "state": state, "prev": prev}
    body["hash"] = hmac.new(KEY, canon(body).encode(), hashlib.sha256).hexdigest()
    with open(path, "a") as f:
        f.write(canon(body) + "\n")
    return body["seq"]

def main():
    seen = {}
    while True:
        for name, path in SOURCES.items():
            try:
                state = fetch(path)
            except Exception as exc:
                print(f"[!] {name}: {exc}", file=sys.stderr)
                continue
            digest = hashlib.sha256(canon(state).encode()).hexdigest()
            if seen.get(name) != digest:
                seen[name] = digest
                print(f"[+] seq {append(LOG, name, state)}: {name} changed")
        time.sleep(2)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[*] logger stopped")
