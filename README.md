# ProvGuard Lab — SDN Control-Plane Attacks & Provenance-Based Detection

A small, reproducible software-defined networking (SDN) lab that stages two control-plane attacks and detects them. Built to work hands-on with the ideas in the ProvGuard paper (Liu, Mao et al., NDSS 2025) on detecting SDN control-policy manipulation via provenance graphs.

Citation: Z. Liu, J. Mao, J. Zeng, J. Li, Q. Lin, J. Liu, J. Zhuge, and Z. Liang, "ProvGuard: Detecting SDN Control Policy Manipulation via Contextual Semantics of Provenance Graphs," in Proc. Network and Distributed System Security Symposium (NDSS), 2025.

## Why this lab exists

ProvGuard reasons about SDN security by building provenance graphs — tracking how control-plane state (topology, flow rules, host locations) came to be, so that illegitimate changes stand out. To understand that argument properly rather than just read it, this lab reproduces the kind of control-plane manipulation provenance is meant to catch, and implements a lightweight detector over the resulting evidence.

## Environment

- Controller: Floodlight 1.2 (REST API on http://127.0.0.1:8080)
- Dataplane: Mininet + Open vSwitch
- OS: Ubuntu 20.04
- Java: OpenJDK 8 (required by Floodlight 1.2)
- **Run only in an isolated VM.** These are live control-plane attacks — do not run them on a production, shared, or campus network.
- All scripts assume the controller and Mininet are already up.

## Repository layout

- `topology/linkfab_topo.py` — Mininet topology for the link-fabrication scenario
- `attacks/attack_a_acl_bypass.sh` — Access-control bypass via host migration
- `attacks/attack_b_link_fabrication.sh` — Link-fabrication attack
- `detector/detector.py` — Detects the attacks from control-plane state
- `evidence/` — raw captures and detection results

## The attacks

### Attack A — Access-control bypass via host migration
Exploits a Floodlight ACL behaviour where a host that migrates between switches can slip past a deny rule. The script installs an ACL deny for 10.0.0.1 -> 10.0.0.2, confirms traffic is blocked, migrates h1 from s1 to s2, then re-tests connectivity — the previously blocked flow now succeeds (bypass).

### Attack B — Link fabrication
Injects a fabricated link into the controller's view of the topology, the class of topology-poisoning attack ProvGuard targets. See `attacks/attack_b_link_fabrication.sh` and `topology/linkfab_topo.py`.

> **Note:** `attack_b_link_fabrication.sh` has no shebang and must be run inside the Mininet `h3` namespace. At the `mininet>` prompt run:
> ```
> h3 bash attacks/attack_b_link_fabrication.sh
> ```

## Detection

`detector/detector.py` inspects control-plane state and flags the anomalies produced by the attacks above. Results are captured in `evidence/detection_results.txt`.

## Baseline (false-alarm test)

Before running the attacks, run a benign baseline: migrate a host between switches **with no ACL rule in place**. The detector should stay **silent** — no detection raised. This is the first false-positive check: it confirms the detector flags the attack behaviour, not ordinary host mobility.

## Reproducing

1. Start Floodlight and bring up the relevant Mininet topology.
2. Run the benign baseline above and confirm the detector stays silent.
3. Run the attack script(s) under `attacks/` (Attack B inside the `h3` namespace — see note).
4. Run the detector and compare against the captures in `evidence/`.

## Known limitations

- The "no drop flow" check inspects the Floodlight flow JSON for the string `drop`. Floodlight represents a drop as a flow entry with **empty actions**, not an explicit `drop` keyword — so this check effectively succeeds because the deny flow is *absent*, not because it matched `drop`. As a result it can misfire on a legitimate host move and should be treated as a heuristic, not a definitive signal.
- A more robust version would inspect the flow's action set directly (empty actions = drop) and correlate it with the provenance of the host-location change, closer to ProvGuard's own approach.

## Status / notes

- Lab built as independent study toward an SDN-security master's application.
- Evidence files are the raw captures from live runs on the VM.

Author: Usman Rafique
