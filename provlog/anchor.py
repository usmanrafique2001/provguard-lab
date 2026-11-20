#!/usr/bin/env python3
"""Print a checkpoint (entry count + newest hash) to store off the VM."""
import json, sys, time
lines = [l for l in open(sys.argv[1]) if l.strip()]
print(json.dumps({"count": len(lines),
                  "head": json.loads(lines[-1])["hash"],
                  "taken": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}))
