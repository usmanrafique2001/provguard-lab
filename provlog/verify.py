#!/usr/bin/env python3
"""Verify a hash-chained log, and optionally checkpoints taken earlier."""
import hashlib, hmac, json, os, sys

GENESIS = "0" * 64

def canon(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))

def verify(log_path, key, anchors_path=None):
    problems, hashes = [], []
    prev, want_seq = GENESIS, 0
    with open(log_path) as f:
        for line_no, line in enumerate(f, 1):
            if not line.strip():
                continue
            e = json.loads(line)
            claimed = e.pop("hash")
            good = hmac.new(key, canon(e).encode(), hashlib.sha256).hexdigest()
            if not hmac.compare_digest(claimed, good):
                problems.append(f"line {line_no} (seq {e['seq']}): entry altered")
            if e["prev"] != prev:
                problems.append(f"line {line_no}: chain broken (entry removed, inserted or reordered)")
            if e["seq"] != want_seq:
                problems.append(f"line {line_no}: expected seq {want_seq}, found {e['seq']}")
            prev, want_seq = claimed, e["seq"] + 1
            hashes.append(claimed)
    if anchors_path:
        with open(anchors_path) as f:
            for line in f:
                if not line.strip():
                    continue
                a = json.loads(line)
                n, head = a["count"], a["head"]
                if len(hashes) < n:
                    problems.append(f"checkpoint at {a['taken']}: log has {len(hashes)} entries, checkpoint says {n} (truncated)")
                elif hashes[n - 1] != head:
                    problems.append(f"checkpoint at {a['taken']}: entry {n - 1} does not match (history rewritten)")
    return problems

if __name__ == "__main__":
    key = open(os.environ.get("PROVLOG_KEY", os.path.join(os.path.dirname(os.path.abspath(__file__)), "log.key")), "rb").read().strip()
    found = verify(sys.argv[1], key, sys.argv[2] if len(sys.argv) > 2 else None)
    print("\n".join(found) if found else "OK: log verified")
    sys.exit(1 if found else 0)
