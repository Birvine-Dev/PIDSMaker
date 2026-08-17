"""witfoo_translate.py — WitFoo -> PIDSMaker table translation (toy + real).

Implements the toy example doc (tables 4a-4e) as runnable code:
  * Mapping A: no reification (events stay edges; hosts carry ground truth)
  * Mapping B: full reification, typed stubs  (NETWORK_FLOW_SRC / _DST, ...)
  * Mapping C: full reification, generic stubs (SRC_OF / DST_OF)
  * --shift-benign: subtract a constant offset from benign/suspicious
    timestamps so the live-capture hour overlaps the attack era
    (Etienne's direction, 23 July). Ordering/gaps preserved exactly.

Usage:
  python witfoo_translate.py --toy --mapping B -o out_toy_B
  python witfoo_translate.py --nodes nodes.jsonl --edges edges.jsonl \
      --mapping B --shift-benign-to 2024-07-08T11:00:00 -o out_2m_B

Outputs (CSV per PIDSMaker table, ready for postgres COPY later):
  subject_node_table.csv   uuid,path,cmd
  file_node_table.csv      uuid,path
  netflow_node_table.csv   uuid,label
  event_table.csv          src,operation,dst,timestamp_rec
  ground_truth_nodes.csv   uuid
  summary.txt              counts + samples of what ORTHRUS will receive
"""

import argparse
import csv
import hashlib
import json
import os
from datetime import datetime, timezone

CONFIRMED = {"Disrupted", "Resolved"}
NS = 1_000_000_000

# ----------------------------------------------------------------------------
# The toy graph (doc sections 2-3): 9 entities, 12 events.
# Malicious burst = real incident 9fd6e430 structure; benign = realistic
# composites (the dataset has no window containing both - see doc §2).
# ----------------------------------------------------------------------------
TOY_NODES = [
    {"node_id": "100.64.10.131", "type": "HOST", "attrs": {"hostname": "HOST-0131", "ip": "100.64.10.131"}},
    {"node_id": "100.64.10.132", "type": "HOST", "attrs": {"hostname": "HOST-0132", "ip": "100.64.10.132"}},
    {"node_id": "172.21.61.66",  "type": "HOST", "attrs": {"hostname": "HOST-0066", "ip": "172.21.61.66"}},
    {"node_id": "172.24.247.113","type": "HOST", "attrs": {"hostname": "HOST-0113", "ip": "172.24.247.113"}},
    {"node_id": "100.64.5.9",    "type": "HOST", "attrs": {"hostname": "HOST-0509", "ip": "100.64.5.9"}},
    {"node_id": "192.168.147.151","type": "HOST","attrs": {"hostname": "HOST-0151", "ip": "192.168.147.151"}},
    {"node_id": "10.184.2.7",    "type": "HOST", "attrs": {"hostname": "HOST-0207", "ip": "10.184.2.7"}},
    {"node_id": "100.64.1.28",   "type": "HOST", "attrs": {"hostname": "HOST-0128", "ip": "100.64.1.28"}},
    {"node_id": "USER-1776",     "type": "CREDENTIAL", "attrs": {"credential": "USER-1776"}},
]

def _toy_edge(i, src, dst, etype, mtype, action, ts, mal=False, **attrs):
    e = {"edge_id": f"e-toy{i:02d}", "src": src, "dst": dst, "type": etype,
         "timestamp": float(ts),
         "attrs": {"message_type": mtype, "action": action, **attrs},
         "labels": {}}
    if mal:
        e["labels"] = {"label_binary": "malicious", "disposition": "Disrupted",
                       "incident_ids": ["9fd6e430-toy"]}
    else:
        e["labels"] = {"label_binary": "benign"}
    return e

TOY_EDGES = [
    _toy_edge(1, "100.64.10.131", "172.21.61.66", "NETWORK_FLOW", "firewall_action", "block", 1715695200, mal=True, protocol=6, src_port=45516, dst_port=3210, stream="cisco_asa"),
    _toy_edge(2, "100.64.10.131", "172.21.61.66", "NETWORK_FLOW", "firewall_action", "block", 1715695200, mal=True, protocol=6, src_port=45517, dst_port=3210, stream="cisco_asa"),
    _toy_edge(3, "100.64.10.132", "172.21.61.66", "NETWORK_FLOW", "firewall_action", "block", 1715695200, mal=True, protocol=6, src_port=51002, dst_port=3210, stream="cisco_asa"),
    _toy_edge(4, "100.64.10.131", "172.24.247.113", "NETWORK_FLOW", "firewall_action", "block", 1715695200, mal=True, protocol=6, src_port=45518, dst_port=8443, stream="cisco_asa"),
    _toy_edge(5, "100.64.10.132", "172.24.247.113", "NETWORK_FLOW", "firewall_action", "block", 1715695200, mal=True, protocol=6, src_port=51003, dst_port=8443, stream="cisco_asa"),
    _toy_edge(6, "100.64.5.9", "192.168.147.151", "DNS_RESOLVE", "dns_event", "query", 1715522400, stream="dnsmasq"),
    _toy_edge(7, "100.64.5.9", "10.184.2.7", "NETWORK_FLOW", "flow", "allow", 1715522410, protocol=6, src_port=62858, dst_port=7680, stream="meraki"),
    _toy_edge(8, "10.184.2.7", "100.64.5.9", "NETWORK_FLOW", "flow", "allow", 1715522411, protocol=6, src_port=7680, dst_port=62858, stream="meraki"),
    _toy_edge(9, "USER-1776", "100.64.5.9", "EVENT", "account_logon", "Logon", 1715522395, stream="microsoft-windows-security-auditing"),
    _toy_edge(10, "USER-1776", "10.184.2.7", "EVENT", "account_logon", "Logon", 1715608800, stream="microsoft-windows-security-auditing"),
    _toy_edge(11, "100.64.1.28", "192.168.147.151", "DNS_RESOLVE", "dns_event", "query", 1715608810, stream="dnsmasq"),
    _toy_edge(12, "100.64.5.9", "172.21.61.66", "NETWORK_FLOW", "flow", "allow", 1715695190, protocol=6, src_port=50110, dst_port=443, stream="meraki"),
]

# ----------------------------------------------------------------------------
# Field rules (doc tables 4a-4e) — THE rulebook, one function per node class
# ----------------------------------------------------------------------------

def host_row(node):
    """HOST -> subject_node_table (uuid, path=hostname, cmd=ip). Doc 4a."""
    a = node.get("attrs") or {}
    return (node["node_id"], a.get("hostname") or node["node_id"], a.get("ip") or node["node_id"])

def credential_row(node):
    """CREDENTIAL -> file_node_table (uuid, path='user:<name>'). Doc 4b."""
    a = node.get("attrs") or {}
    cred = a.get("credential") or node["node_id"]
    label = cred if str(cred).startswith("user:") else f"user:{cred}"
    return (node["node_id"], label)

def event_node_row(edge):
    """Reified event -> netflow_node_table (4 text slots per PIDSMaker schema).
    ORTHRUS's label recipe reads type+remote_ip+remote_port, which the graph
    builder maps to (dst_addr, dst_port) - so the richest text goes there."""
    a = edge.get("attrs") or {}
    flavour = " ".join(str(x) for x in (edge.get("type"), a.get("message_type"), a.get("action")) if x)
    transport = " ".join(str(x) for x in (a.get("protocol"), a.get("stream")) if x)
    ports = f"{a.get('src_port','')}:{a.get('dst_port','')}".strip(":")
    # (src_addr, src_port) -> local_* (unused by ORTHRUS recipe, kept meaningful)
    return (edge["edge_id"], transport, str(a.get("protocol") or ""), flavour, ports)

def _h(x):
    return hashlib.md5(str(x).encode()).hexdigest()

def stub_type(edge, mapping):
    """Doc 4d / open question 1. B: carry event type; C: generic."""
    if mapping == "C":
        return "SRC_OF", "DST_OF"
    t = edge.get("type", "EVENT")
    return f"{t}_SRC", f"{t}_DST"

def is_confirmed_malicious(edge):
    lab = edge.get("labels") or {}
    return lab.get("label_binary") == "malicious" and lab.get("disposition") in CONFIRMED

def is_benignish(edge):
    return (edge.get("labels") or {}).get("label_binary") in ("benign", "suspicious")

# ----------------------------------------------------------------------------
# Translation
# ----------------------------------------------------------------------------

def translate(nodes_iter, edges_iter, mapping, shift_to=None, out="out"):
    os.makedirs(out, exist_ok=True)
    subjects, files_, netflows, events, gt = [], [], [], [], []
    node_type = {}
    uuid2idx = {}
    def idx(u):
        if u not in uuid2idx:
            uuid2idx[u] = len(uuid2idx)
        return uuid2idx[u]
    skipped_ts = 0
    n_edges = n_mal = 0
    shift_delta = None
    benign_min = None

    nodes = list(nodes_iter)
    edges = list(edges_iter)

    # Pass -1: determine which edges will be kept, and therefore which nodes
    # are actually referenced — isolated (incident-side) nodes are not emitted.
    kept_endpoints = set()
    for e in edges:
        if e.get("type") == "INCIDENT_LINK":
            continue
        ts0 = e.get("timestamp")
        if not ts0 or ts0 < 1_500_000_000:
            continue
        kept_endpoints.add(e.get("src"))
        kept_endpoints.add(e.get("dst"))

    # Pass 0: date-shift delta (constant offset; preserves ordering exactly)
    if shift_to is not None:
        target = datetime.fromisoformat(shift_to).replace(tzinfo=timezone.utc).timestamp()
        b_ts = [e["timestamp"] for e in edges if is_benignish(e) and e.get("timestamp", 0) > 1_500_000_000]
        if b_ts:
            benign_min = min(b_ts)
            shift_delta = benign_min - target

    # Nodes (only those referenced by kept edges)
    n_isolated = 0
    for n in nodes:
        if n["node_id"] not in kept_endpoints:
            n_isolated += 1
            continue
        t = str(n.get("type", "")).upper()
        if t in ("CRED",):
            t = "CREDENTIAL"  # normalise straggler alias
        node_type[n["node_id"]] = t
        if t == "HOST" or t in ("SERVICE", "FILE", "ACTOR"):
            u, path, cmd = host_row(n)
            subjects.append((u, _h((path, cmd)), path, cmd, idx(u)))
        elif t == "CREDENTIAL":
            u, path = credential_row(n)
            files_.append((u, _h(path), path, idx(u)))

    known = set(node_type)

    # Edges
    for e in edges:
        if e.get("type") == "INCIDENT_LINK":
            continue  # label leakage; excluded (doc/profiling)
        ts = e.get("timestamp")
        if not ts or ts < 1_500_000_000:
            skipped_ts += 1
            continue  # corrupt timestamps (year-1300 bug)
        if e.get("src") not in known or e.get("dst") not in known:
            continue  # ghost endpoints (all were INCIDENT_LINK-only in real data)
        if shift_delta is not None and is_benignish(e):
            ts = ts - shift_delta
        ts_ns = int(ts * NS)
        n_edges += 1
        mal = is_confirmed_malicious(e)
        if mal:
            n_mal += 1

        if mapping == "A":
            events.append((e["src"], idx(e["src"]), e.get("type", "EVENT"),
                           e["dst"], idx(e["dst"]), e["edge_id"], ts_ns))
            if mal:
                gt.extend([e["src"], e["dst"]])
        else:  # B or C: reify
            uuid, sa, sp, da, dp = event_node_row(e)
            netflows.append((uuid, _h((sa, sp, da, dp)), sa, sp, da, dp, idx(uuid)))
            st_src, st_dst = stub_type(e, mapping)
            events.append((e["src"], idx(e["src"]), st_src, uuid, idx(uuid), f"{e['edge_id']}:s", ts_ns))
            events.append((uuid, idx(uuid), st_dst, e["dst"], idx(e["dst"]), f"{e['edge_id']}:d", ts_ns))
            if mal:
                gt.append(uuid)

    gt = sorted(set(gt))

    # Write tables
    def w(name, header, rows):
        with open(os.path.join(out, name), "w", newline="") as f:
            wr = csv.writer(f)
            wr.writerow(header)
            wr.writerows(rows)

    w("subject_node_table.csv", ["node_uuid", "hash_id", "path", "cmd", "index_id"], subjects)
    w("file_node_table.csv", ["node_uuid", "hash_id", "path", "index_id"], files_)
    w("netflow_node_table.csv", ["node_uuid", "hash_id", "src_addr", "src_port", "dst_addr", "dst_port", "index_id"], netflows)
    w("event_table.csv", ["src_node", "src_index_id", "operation", "dst_node", "dst_index_id", "event_uuid", "timestamp_rec"], events)
    # PIDSMaker GT format: headerless 3-column (uuid, label, extra) per labelling.py
    with open(os.path.join(out, "ground_truth_nodes.csv"), "w", newline="") as f:
        wr = csv.writer(f)
        wr.writerows((g, "malicious", "") for g in gt)

    total_nodes = len(subjects) + len(files_) + len(netflows)
    lines = [
        f"Mapping {mapping}  |  output: {out}/",
        f"nodes: {total_nodes}  (subject {len(subjects)}, file {len(files_)}, netflow/event {len(netflows)}; {n_isolated} isolated source nodes not emitted)",
        f"edges: {len(events)}  (from {n_edges} source events; {n_mal} confirmed-malicious; {skipped_ts} corrupt-ts skipped)",
        f"ground-truth positives: {len(gt)}  ({100*len(gt)/max(total_nodes,1):.1f}% of nodes)",
    ]
    if shift_delta is not None:
        lines.append(f"benign shift: -{shift_delta:.0f}s  (capture start {datetime.fromtimestamp(benign_min, tz=timezone.utc)} -> {shift_to})")
    lines.append("")
    lines.append("sample rows ORTHRUS-side (what featurization will read):")
    for r in subjects[:2]:
        lines.append(f"  subject: uuid={r[0]}  path={r[2]}  cmd={r[3]}  idx={r[4]}")
    for r in files_[:1]:
        lines.append(f"  file:    uuid={r[0]}  path={r[2]}  idx={r[3]}")
    for r in netflows[:3]:
        lines.append(f"  event:   uuid={r[0]}  ORTHRUS-label-text='netflow {r[4]} {r[5]}'  idx={r[6]}")
    for r in events[:4]:
        lines.append(f"  edge:    {r[0]} -[{r[2]}]-> {r[3]}  @ {r[6]}")
    summary = "\n".join(lines)
    with open(os.path.join(out, "summary.txt"), "w") as f:
        f.write(summary + "\n")
    print(summary)
    return summary


def iter_jsonl(path):
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line:
                yield json.loads(line)


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--toy", action="store_true", help="use the built-in 21-node toy graph")
    p.add_argument("--nodes", help="real nodes.jsonl")
    p.add_argument("--edges", help="real edges.jsonl")
    p.add_argument("--mapping", choices=["A", "B", "C"], default="B")
    p.add_argument("--shift-benign-to", default=None,
                   help="ISO datetime; shift benign/suspicious so capture starts here (e.g. 2024-07-08T11:00:00)")
    p.add_argument("-o", "--out", default="out")
    args = p.parse_args()

    if args.toy:
        translate(TOY_NODES, TOY_EDGES, args.mapping, args.shift_benign_to, args.out)
    else:
        translate(iter_jsonl(args.nodes), iter_jsonl(args.edges), args.mapping,
                  args.shift_benign_to, args.out)


if __name__ == "__main__":
    main()
