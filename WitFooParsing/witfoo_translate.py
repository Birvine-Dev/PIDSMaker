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

def translate(nodes_iter, edges_iter, mapping, shift_to=None, out="out", shift_chunks=None, gt_date=None, shift_chunks_frac=None, org=None, clean_train_dates=None, edges_factory=None, benign_sample_mod=None):
    def _apply_filters(it, is_edges=True):
        if org is not None:
            def _f(inner):
                for r in inner:
                    if (r.get("attrs") or {}).get("org_id") == org:
                        yield r
            it = _f(it)
        if is_edges and benign_sample_mod:
            K = benign_sample_mod
            def _samp(inner):
                import hashlib as _hl
                for r in inner:
                    if is_confirmed_malicious(r):
                        yield r
                        continue
                    h = int(_hl.md5(str(r.get("edge_id")).encode()).hexdigest()[:8], 16)
                    if h % K == 0:
                        yield r
            it = _samp(it)
        if is_edges and clean_train_dates:
            _ctd = set(clean_train_dates)
            def _clean(inner):
                for r in inner:
                    lab = r.get("labels") or {}
                    if lab.get("label_binary") == "malicious":
                        t = r.get("timestamp", 0)
                        if t and t > 1.5e9 and datetime.fromtimestamp(t, tz=timezone.utc).strftime("%Y-%m-%d") in _ctd:
                            continue
                    yield r
            it = _clean(it)
        return it

    nodes_iter = _apply_filters(nodes_iter, is_edges=False)
    edges_iter = _apply_filters(edges_iter)

    streaming = (edges_factory is not None and shift_to is None
                 and shift_chunks is None and shift_chunks_frac is None)
    if streaming:
        return _translate_streaming(nodes_iter, edges_factory, _apply_filters,
                                    mapping, out, gt_date)
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

    # Pass 0a: fraction-based chunk plan -> absolute-time chunks
    chunk_plan = None
    if shift_chunks_frac:
        b_sorted = sorted(e["timestamp"] for e in edges if is_benignish(e) and e.get("timestamp", 0) > 1_500_000_000)
        n = len(b_sorted)
        chunk_plan = []
        for part in shift_chunks_frac.split(","):
            rng, target = part.split(":", 1)
            f0, f1 = (float(x) for x in rng.split("-"))
            c0 = b_sorted[min(int(f0 * n), n - 1)]
            c1 = b_sorted[min(int(f1 * n), n - 1)] + (1e-6 if f1 >= 1 else 0)
            tgt = datetime.fromisoformat(target).replace(tzinfo=timezone.utc).timestamp()
            chunk_plan.append((c0, c1, tgt))
        shift_to = None

    # Pass 0b: chunked shift plan (cut capture into chunks, each landing on its own date)
    if shift_chunks and chunk_plan is None:
        b_ts = [e["timestamp"] for e in edges if is_benignish(e) and e.get("timestamp", 0) > 1_500_000_000]
        t0 = min(b_ts)
        chunk_plan = []
        for part in shift_chunks.split(","):
            rng, target = part.split(":", 1)
            m0, m1 = (float(x) for x in rng.split("-"))
            tgt = datetime.fromisoformat(target).replace(tzinfo=timezone.utc).timestamp()
            chunk_plan.append((t0 + m0 * 60, t0 + m1 * 60, tgt))
        shift_to = None  # chunks override the single shift

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
        if t == "FILE":
            u = n["id"]; path = (n.get("attrs") or {}).get("hostname") or u
            files_.append((u, _h(path), path, idx(u)))
        elif t == "HOST" or t in ("SERVICE", "ACTOR"):
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
        if chunk_plan is not None and is_benignish(e):
            for c0, c1, tgt in chunk_plan:
                if c0 <= ts < c1:
                    ts = tgt + (ts - c0)
                    break
        elif shift_delta is not None and is_benignish(e):
            ts = ts - shift_delta
        ts_ns = int(ts * NS)
        n_edges += 1
        mal = is_confirmed_malicious(e)
        if mal and gt_date is not None:
            d = datetime.fromtimestamp(e["timestamp"], tz=timezone.utc).strftime("%Y-%m-%d")
            if d != gt_date:
                mal = False  # stays an ordinary (dormant) event; excluded from GT
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
    if chunk_plan is not None:
        counts = [sum(1 for e in edges if is_benignish(e) and e.get("timestamp",0) > 1_500_000_000 and c0 <= e["timestamp"] < c1) for c0, c1, _ in chunk_plan]
        lines.append("benign events per chunk: " + ", ".join(f"{c:,}" for c in counts))
        for c0, c1, tgt in chunk_plan:
            lines.append(f"chunk {int((c0-chunk_plan[0][0])/60)}-{int((c1-chunk_plan[0][0])/60)}min -> {datetime.fromtimestamp(tgt, tz=timezone.utc):%Y-%m-%d %H:%M} UTC")
    if gt_date is not None:
        lines.append(f"ground truth restricted to confirmed-malicious events on {gt_date} (dormant archive excluded)")
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




def _translate_streaming(nodes_iter, edges_factory, apply_filters, mapping, out, gt_date):
    """Constant-memory path for unshifted runs (84M-scale). Two passes over
    edges from disk; node/event rows stream straight to CSV. Only the entity
    registry (~hosts/creds/files) is held in memory. Output is byte-identical
    to the legacy path for the same inputs."""
    os.makedirs(out, exist_ok=True)
    uuid2idx = {}
    next_idx = [0]
    def idx(u):
        if u not in uuid2idx:
            uuid2idx[u] = next_idx[0]
            next_idx[0] += 1
        return uuid2idx[u]

    # Pass 1 over edges: endpoints referenced by kept events
    kept_endpoints = set()
    for e in apply_filters(edges_factory()):
        if e.get("type") == "INCIDENT_LINK":
            continue
        ts0 = e.get("timestamp")
        if not ts0 or ts0 < 1_500_000_000:
            continue
        kept_endpoints.add(e.get("src"))
        kept_endpoints.add(e.get("dst"))

    # Nodes: emit entity tables now (small), registering indices
    node_type = {}
    subjects, files_ = [], []
    n_isolated = 0
    for n in nodes_iter:
        if n["node_id"] not in kept_endpoints:
            n_isolated += 1
            continue
        t = str(n.get("type", "")).upper()
        if t in ("CRED",):
            t = "CREDENTIAL"
        node_type[n["node_id"]] = t
        if t == "FILE":
            u = n["id"]; path = (n.get("attrs") or {}).get("hostname") or u
            files_.append((u, _h(path), path, idx(u)))
        elif t == "HOST" or t in ("SERVICE", "ACTOR"):
            u, path, cmd = host_row(n)
            subjects.append((u, _h((path, cmd)), path, cmd, idx(u)))
        elif t == "CREDENTIAL":
            u, path = credential_row(n)
            files_.append((u, _h(path), path, idx(u)))
    known = set(node_type)

    # Pass 2 over edges: stream netflow + event rows to disk
    f_net = open(os.path.join(out, "netflow_node_table.csv"), "w", newline="")
    f_evt = open(os.path.join(out, "event_table.csv"), "w", newline="")
    w_net, w_evt = csv.writer(f_net), csv.writer(f_evt)
    w_net.writerow(["node_uuid", "hash_id", "src_addr", "src_port", "dst_addr", "dst_port", "index_id"])
    w_evt.writerow(["src_node", "src_index_id", "operation", "dst_node", "dst_index_id", "event_uuid", "timestamp_rec"])
    gt = []
    sample_net, sample_evt = [], []
    n_edges = n_mal = skipped_ts = 0
    n_netflows = n_events = 0
    for e in apply_filters(edges_factory()):
        if e.get("type") == "INCIDENT_LINK":
            continue
        ts = e.get("timestamp")
        if not ts or ts < 1_500_000_000:
            skipped_ts += 1
            continue
        if e.get("src") not in known or e.get("dst") not in known:
            continue
        ts_ns = int(ts * NS)
        n_edges += 1
        mal = is_confirmed_malicious(e)
        if mal and gt_date is not None:
            d = datetime.fromtimestamp(e["timestamp"], tz=timezone.utc).strftime("%Y-%m-%d")
            if d != gt_date:
                mal = False
        if mal:
            n_mal += 1
        if mapping == "A":
            w_evt.writerow((e["src"], idx(e["src"]), e.get("type", "EVENT"),
                            e["dst"], idx(e["dst"]), e["edge_id"], ts_ns))
            n_events += 1
            if mal:
                gt.extend([e["src"], e["dst"]])
        else:
            uuid, sa, sp, da, dp = event_node_row(e)
            # Event uuids derive from native edge_ids, which are unique in the
            # source data (input contract; verified for 2M, assumed for 84M) -
            # so they get a direct sequential index and are never registered,
            # keeping memory flat at any scale.
            ev_idx = next_idx[0]; next_idx[0] += 1
            row_net = (uuid, _h((sa, sp, da, dp)), sa, sp, da, dp, ev_idx)
            w_net.writerow(row_net)
            if len(sample_net) < 3: sample_net.append(row_net)
            n_netflows += 1
            st_src, st_dst = stub_type(e, mapping)
            row_s = (e["src"], idx(e["src"]), st_src, uuid, ev_idx, f"{e['edge_id']}:s", ts_ns)
            row_d = (uuid, ev_idx, st_dst, e["dst"], idx(e["dst"]), f"{e['edge_id']}:d", ts_ns)
            w_evt.writerow(row_s); w_evt.writerow(row_d)
            if len(sample_evt) < 4: sample_evt.append(row_s)
            if len(sample_evt) < 4: sample_evt.append(row_d)
            n_events += 2
            if mal:
                gt.append(uuid)
    f_net.close(); f_evt.close()

    gt = sorted(set(gt))
    def w(name, header, rows):
        with open(os.path.join(out, name), "w", newline="") as f:
            wr = csv.writer(f)
            wr.writerow(header)
            wr.writerows(rows)
    w("subject_node_table.csv", ["node_uuid", "hash_id", "path", "cmd", "index_id"], subjects)
    w("file_node_table.csv", ["node_uuid", "hash_id", "path", "index_id"], files_)
    with open(os.path.join(out, "ground_truth_nodes.csv"), "w", newline="") as f:
        wr = csv.writer(f)
        wr.writerows((g, "malicious", "") for g in gt)

    total_nodes = len(subjects) + len(files_) + n_netflows
    lines = [
        f"Mapping {mapping}  |  output: {out}/",
        f"nodes: {total_nodes}  (subject {len(subjects)}, file {len(files_)}, netflow/event {n_netflows}; {n_isolated} isolated source nodes not emitted)",
        f"edges: {n_events}  (from {n_edges} source events; {n_mal} confirmed-malicious; {skipped_ts} corrupt-ts skipped)",
        f"ground-truth positives: {len(gt)}  ({100*len(gt)/max(total_nodes,1):.1f}% of nodes)",
    ]
    if gt_date is not None:
        lines.append(f"ground truth restricted to confirmed-malicious events on {gt_date} (dormant archive excluded)")
    lines.append("")
    lines.append("sample rows ORTHRUS-side (what featurization will read):")
    for r in subjects[:2]:
        lines.append(f"  subject: uuid={r[0]}  path={r[2]}  cmd={r[3]}  idx={r[4]}")
    for r in files_[:1]:
        lines.append(f"  file:    uuid={r[0]}  path={r[2]}  idx={r[3]}")
    for r in sample_net[:3]:
        lines.append(f"  event:   uuid={r[0]}  ORTHRUS-label-text='netflow {r[4]} {r[5]}'  idx={r[6]}")
    for r in sample_evt[:4]:
        lines.append(f"  edge:    {r[0]} -[{r[2]}]-> {r[3]}  @ {r[6]}")
    print("\n".join(lines))
    with open(os.path.join(out, "summary.txt"), "w") as f:
        f.write("\n".join(lines) + "\n")


def iter_jsonl(path):
    """Yield JSON rows from a file, a .gz file, a directory of shards, or a glob.
    Shards are read in sorted order so edge numbering stays stable."""
    import glob as _glob, gzip as _gzip, os as _os
    if _os.path.isdir(path):
        paths = sorted(_glob.glob(_os.path.join(path, "edges-*.jsonl*")) or
                       _glob.glob(_os.path.join(path, "*.jsonl*")))
    elif any(c in path for c in "*?["):
        paths = sorted(_glob.glob(path))
    else:
        paths = [path]
    if not paths:
        raise SystemExit(f"no input files match: {path}")
    for p in paths:
        opener = _gzip.open if p.endswith(".gz") else open
        with opener(p, "rt") as f:
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
    p.add_argument("--shift-chunks", default=None,
                   help="Cut the benign capture into chunks landed on separate dates: "
                        "'0-40:2024-07-05T11:00:00,40-50:2024-07-06T11:00:00,50-9999:2024-07-08T11:00:00' "
                        "(minutes from capture start). Overrides --shift-benign-to.")
    p.add_argument("--shift-chunks-frac", default=None,
                   help="Like --shift-chunks but boundaries are CUMULATIVE EVENT FRACTIONS of the benign capture "
                        "(robust to bursty traffic): '0-0.6:2024-07-05T11:00:00,0.6-0.75:2024-07-06T11:00:00,0.75-1:2024-07-08T18:03:00'")
    p.add_argument("--benign-sample-mod", type=int, default=None,
                   help="keep only 1/K of benign+suspicious events, chosen deterministically by md5(edge_id) - confirmed-malicious events are ALWAYS kept, so ground truth is unchanged; use for density-ladder experiments")
    p.add_argument("--clean-train-dates", default=None,
                   help="comma-separated UTC dates (YYYY-MM-DD); malicious events on these dates are DROPPED (benign/suspicious kept) so the dates can serve as clean training days")
    p.add_argument("--org", default=None,
                   help="Keep only events/nodes of this org (e.g. ORG-0004). New multi-org exports.")
    p.add_argument("--gt-date", default=None,
                   help="Emit ground truth ONLY for confirmed-malicious events on this UTC date (e.g. 2024-07-08). Default: all.")
    p.add_argument("-o", "--out", default="out")
    args = p.parse_args()

    if args.toy:
        translate(TOY_NODES, TOY_EDGES, args.mapping, args.shift_benign_to, args.out,
                  shift_chunks=args.shift_chunks, gt_date=args.gt_date, shift_chunks_frac=args.shift_chunks_frac, org=args.org, clean_train_dates=(args.clean_train_dates.split(",") if args.clean_train_dates else None), edges_factory=((lambda: iter_jsonl(args.edges)) if getattr(args, 'edges', None) else None), benign_sample_mod=args.benign_sample_mod)
    else:
        translate(iter_jsonl(args.nodes), iter_jsonl(args.edges), args.mapping,
                  args.shift_benign_to, args.out, shift_chunks=args.shift_chunks, gt_date=args.gt_date,
                  shift_chunks_frac=args.shift_chunks_frac, org=args.org,
                  clean_train_dates=(args.clean_train_dates.split(",") if args.clean_train_dates else None), edges_factory=((lambda: iter_jsonl(args.edges)) if getattr(args, 'edges', None) else None), benign_sample_mod=args.benign_sample_mod)


if __name__ == "__main__":
    main()
