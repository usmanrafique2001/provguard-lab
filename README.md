# ProvGuard Lab — SDN Control-Plane Attacks & Provenance-Based Detection

A small, reproducible software-defined networking (SDN) lab that stages two control-plane attacks and detects them. Built to work hands-on with the ideas in the ProvGuard paper (Liu, Mao et al., NDSS 2025) on detecting SDN control-policy manipulation via provenance graphs.

Citation: Z. Liu, J. Mao, J. Zeng, J. Li, Q. Lin, J. Liu, J. Zhuge, and Z. Liang, "ProvGuard: Detecting SDN Control Policy Manipulation via Contextual Semantics of Provenance Graphs," in Proc. Network and Distributed System Security Symposium (NDSS), 2025.

## Why this lab exists

ProvGuard reasons about SDN security by building provenance graphs — tracking how control-plane state (topology, flow rules, host locations) came to be, so that illegitimate changes stand out. To understand that argument properly rather than just read it, this lab reproduces the kind of control-plane manipulation provenance is meant to catch, and implements a lightweight detector over the resulting evidence.

## Environment

- Controller: Floodlight (REST API on http://127.0.0.1:8080)
- Dataplane: Mininet + Open vSwitch
- Base topology (Attack A): linear,2 — h1@s1, h2@s2
- Custom topology (Attack B): topology/linkfab_topo.py
- Run on a Linux VM. All scripts assume the controller and Mininet are already up.

## Repository layout

- topology/linkfab_topo.py — Mininet topology for the link-fabrication scenario
- attacks/attack_a_acl_bypass.sh — Access-control bypass via host migration
- attacks/attack_b_link_fabrication.sh — Link-fabrication attack
- detector/detector.py — Detects the attacks from control-plane state
- evidence/ — raw captures and detection results

## The attacks

### Attack A — Access-control bypass via host migration
Exploits a Floodlight ACL behaviour where a host that migrates between switches can slip past a deny rule. The script installs an ACL deny for 10.0.0.1 -> 10.0.0.2, confirms traffic is blocked, migrates h1 from s1 to s2, then re-tests connectivity — the previously blocked flow now succeeds (bypass).

### Attack B — Link fabrication
Injects a fabricated link into the controller's view of the topology, the class of topology-poisoning attack ProvGuard targets. See attacks/attack_b_link_fabrication.sh and topology/linkfab_topo.py.

## Detection

detector/detector.py inspects control-plane state and flags the anomalies produced by the attacks above. Results are captured in evidence/detection_results.txt.

## Reproducing

1. Start Floodlight and bring up the relevant Mininet topology.
2. Run the attack script(s) under attacks/.
3. Run the detector and compare against the captures in evidence/.

## Status / notes

- Lab built as independent study toward an SDN-security master's application.
- Evidence files are the raw captures from live runs on the VM.

Author : Mohammed Usman Rafique

