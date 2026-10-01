"""security/attack_graph/attack_graph_lib.py -- pure graph-building and
analysis core for the AI Agent Attack Graph module.

This module is the promised consumer of
security/shadow_ai/shadow_ai_monitor.sh's own "integration point for a
future module" (see that file's own header, Phase 90): every
agent_to_agent finding it emits already carries complete edge data
(client process identity + listener pid/command/port) under a stable,
deterministic id. This module reads that JSONL finding stream and
turns it into a directed graph of "which local AI-flagged process talks
to which," then runs a small set of deliberately simple, fully
auditable graph queries over it -- same "state the basis, not just the
verdict" posture as security/incident_learning/incident_confidence.sh's
own formula, never a black-box score.

Coupling is DELIBERATELY loose: this module does not import
shadow_ai_lib.py or anything else from security/shadow_ai/ -- it only
depends on the documented JSON finding SCHEMA (id, finding_type,
category, signature_matched, process, network, risk, confidence -- see
parse_findings()'s own header for the exact fields read). Any producer
that emits JSONL matching that schema can feed this module; Shadow AI
Monitor is its first and, for now, only real producer.

No I/O beyond what the caller hands it as plain strings/dicts -- every
function here is a pure function of its arguments, directly
unit-testable with fixed finding lists, no live ps/lsof/graph-builder
state needed.
"""

import json


RISK_ORDER = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]


def _risk_index(risk):
    return RISK_ORDER.index(risk) if risk in RISK_ORDER else 0


def _higher_risk(a, b):
    return a if _risk_index(a) >= _risk_index(b) else b


# --- finding parsing -----------------------------------------------------

def parse_findings(lines):
    """lines: an iterable of raw JSONL strings (e.g. a file's own
    readlines(), or Shadow AI Monitor's own stdout captured line by
    line). Returns a list of finding dicts. A blank or non-JSON line is
    silently skipped -- same "skip gracefully, never crash on a
    malformed line" posture every Collector-contract reader in this
    repo already has (see
    security/incident_learning/incident_normalizer.sh's own while-read
    loop). Fields this module actually reads from each finding:
    id, finding_type, category, signature_matched, risk, confidence,
    process (dict with at least 'comm', 'pid', or None), and for
    finding_type=='agent_to_agent'/'listening_port'/'outbound_connection'
    a network dict carrying local_port/remote_port/listener_pid/
    listener_command as applicable. Every other field a real Shadow AI
    Monitor finding carries (reason, signature_label, match_kind,
    detected_at, allowlisted) is preserved on the parsed dict but not
    otherwise interpreted here.
    """
    findings = []
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            findings.append(json.loads(line))
        except (json.JSONDecodeError, TypeError):
            continue
    return findings


# --- node identity ---------------------------------------------------------

def _node_name(process):
    """A node is identified by its process's own comm (command name) --
    the same stable-across-restarts identifier Shadow AI Monitor's own
    inventory keys on conceptually, NEVER a pid (which is different
    every time the same real process restarts). Returns None if no
    usable process context exists (e.g. a listening_port finding whose
    owning process wasn't resolved) -- the caller skips building
    anything for a None node name rather than inventing a placeholder
    identity for something this module can't actually name.
    """
    if not process:
        return None
    return process.get("comm")


def _ensure_node(nodes, name, category=None):
    if name not in nodes:
        nodes[name] = {
            "category": category,
            "highest_risk": "LOW",
            "finding_ids": [],
            "exposures": [],
        }
    elif category and not nodes[name]["category"]:
        nodes[name]["category"] = category
    return nodes[name]


# --- graph construction ----------------------------------------------------

def build_graph(findings):
    """findings -> {"nodes": {name: {...}}, "edges": [{...}, ...]}.

    Node attributes:
      category      - the AI category last observed for this node (may
                       be None if this node is only ever seen as an
                       agent_to_agent LISTENER with no matching process
                       finding of its own -- still a real node, just
                       with incomplete category context).
      highest_risk  - the highest risk (LOW..CRITICAL) across every
                       finding/edge touching this node.
      finding_ids   - every finding id that contributed to this node,
                       for traceability back to the original evidence
                       (same "never just a verdict, always a pointer
                       back to the basis" posture as every audit trail
                       in this repo).
      exposures     - listening_port/outbound_connection findings
                       belonging to this node (port + risk), kept as
                       node attributes rather than graph edges: a
                       process merely being exposed on a known AI port
                       is real evidence worth carrying, but it is NOT a
                       confirmed local agent-to-agent EDGE the way an
                       actual agent_to_agent finding is -- conflating
                       the two would let an ordinary outbound HTTPS
                       call to a cloud AI API look identical to a
                       confirmed local agent chain, which is a real
                       finding-severity distinction this module must
                       not blur.

    Edges (a list, not keyed by name -- two nodes can have more than
    one distinct edge, e.g. two different agent_to_agent findings on
    different ports) come ONLY from finding_type == 'agent_to_agent':
      {from, to, risk, confidence, port, finding_id}
    'from' is the CLIENT process's own node name, 'to' is the
    LISTENER's (network.listener_command) -- directionality matches
    which side initiated the connection, the one piece of real
    asymmetry this module's own upstream data (lsof's own
    LISTEN/ESTABLISHED split) actually supports.
    """
    nodes = {}
    edges = []

    for f in findings:
        ftype = f.get("finding_type")
        risk = f.get("risk", "LOW")
        process = f.get("process")
        network = f.get("network")

        if ftype == "process":
            name = _node_name(process)
            if name is None:
                continue
            node = _ensure_node(nodes, name, f.get("category"))
            node["highest_risk"] = _higher_risk(node["highest_risk"], risk)
            node["finding_ids"].append(f.get("id"))

        elif ftype in ("listening_port", "outbound_connection"):
            name = _node_name(process)
            if name is None:
                continue
            node = _ensure_node(nodes, name, f.get("category"))
            node["highest_risk"] = _higher_risk(node["highest_risk"], risk)
            node["finding_ids"].append(f.get("id"))
            node["exposures"].append({
                "type": ftype,
                "port": (network or {}).get("local_port") or (network or {}).get("remote_port"),
                "risk": risk,
            })

        elif ftype == "agent_to_agent":
            from_name = _node_name(process)
            to_name = (network or {}).get("listener_command")
            if from_name is None or to_name is None:
                continue
            from_node = _ensure_node(nodes, from_name, f.get("category"))
            to_node = _ensure_node(nodes, to_name)
            from_node["highest_risk"] = _higher_risk(from_node["highest_risk"], risk)
            to_node["highest_risk"] = _higher_risk(to_node["highest_risk"], risk)
            from_node["finding_ids"].append(f.get("id"))
            edges.append({
                "from": from_name,
                "to": to_name,
                "risk": risk,
                "confidence": f.get("confidence"),
                "port": (network or {}).get("remote_port"),
                "finding_id": f.get("id"),
            })

    return {"nodes": nodes, "edges": edges}


# --- graph analysis ----------------------------------------------------

def _adjacency(edges):
    adj = {}
    for e in edges:
        adj.setdefault(e["from"], []).append(e["to"])
    return adj


def detect_cycles(edges):
    """Simple DFS cycle detection over the directed agent_link edges.
    Returns a list of cycles, each a list of node names in traversal
    order (the first node repeated at the end, e.g. ['a','b','a']).
    Deliberately simple (one cycle reported per distinct starting point
    on the current DFS stack, not an exhaustive enumeration of every
    possible rotation/overlap of a shared cycle) -- enough to answer
    "does a feedback loop exist at all," which is the actual question
    an agent-to-agent feedback loop (a real operational risk: two
    agents endlessly re-triggering each other) raises.
    """
    adj = _adjacency(edges)
    cycles = []
    visited = set()

    def dfs(node, stack):
        if node in stack:
            cycle_start = stack.index(node)
            cycles.append(stack[cycle_start:] + [node])
            return
        if node in visited:
            return
        visited.add(node)
        for neighbor in adj.get(node, []):
            dfs(neighbor, stack + [node])

    for start in list(adj.keys()):
        dfs(start, [])

    return cycles


def find_attack_paths(nodes, edges, low_risk_max="MEDIUM", high_risk_min="HIGH"):
    """Finds every directed path (via agent_link edges) from a node at
    or below `low_risk_max` to a DIFFERENT node at or above
    `high_risk_min` -- the concrete "attack graph" question this module
    exists to answer: could a low-visibility/low-risk-looking local AI
    process reach a high-risk one purely through existing local
    agent-to-agent connections (lateral movement between local AI
    agents), without needing any new information beyond what Shadow AI
    Monitor already observed. Returns the SHORTEST such path per
    (start, end) pair (BFS), each as
    {from, to, path: [names...], path_risk: the highest risk among
    every node on the path}. Deliberately a plain BFS over a small,
    locally-observed graph (real-world node counts are a handful to a
    few dozen processes on one machine) -- no MITRE ATT&CK technique
    mapping, no probability/likelihood scoring, matching this repo's
    own "deliberately simple, fully auditable" posture for every other
    classification step (see incident_confidence.sh's own formula).
    """
    adj = _adjacency(edges)
    low_risk_nodes = [n for n, d in nodes.items() if _risk_index(d["highest_risk"]) <= _risk_index(low_risk_max)]
    high_risk_nodes = {n for n, d in nodes.items() if _risk_index(d["highest_risk"]) >= _risk_index(high_risk_min)}

    paths = []
    for start in low_risk_nodes:
        if not high_risk_nodes - {start}:
            continue
        # BFS from `start`, recording the first (shortest) path to each
        # reachable node.
        came_from = {start: None}
        queue = [start]
        while queue:
            current = queue.pop(0)
            for neighbor in adj.get(current, []):
                if neighbor in came_from:
                    continue
                came_from[neighbor] = current
                queue.append(neighbor)

        for target in high_risk_nodes:
            if target == start or target not in came_from:
                continue
            path = [target]
            node = target
            while came_from[node] is not None:
                node = came_from[node]
                path.append(node)
            path.reverse()
            path_risk = "LOW"
            for n in path:
                path_risk = _higher_risk(path_risk, nodes[n]["highest_risk"])
            paths.append({
                "from": start,
                "to": target,
                "path": path,
                "path_risk": path_risk,
            })

    return paths


def highest_risk_node(nodes):
    """Returns {"name": ..., "risk": ...} for the single highest-risk
    node (first one found at that risk level, in dict iteration order --
    a tie is not resolved further, since this module has no basis to
    rank two nodes at the identical highest risk against each other).
    Returns None for an empty graph.
    """
    if not nodes:
        return None
    best_name = None
    best_risk = "LOW"
    for name, data in nodes.items():
        if best_name is None or _risk_index(data["highest_risk"]) > _risk_index(best_risk):
            best_name = name
            best_risk = data["highest_risk"]
    return {"name": best_name, "risk": best_risk}


def graph_summary(graph):
    """graph (from build_graph) -> the full analysis block: counts,
    cycles, attack paths, and the single highest-risk node. This is the
    one function most callers actually want -- everything else in this
    module is available individually for direct unit testing.
    """
    nodes, edges = graph["nodes"], graph["edges"]
    return {
        "node_count": len(nodes),
        "edge_count": len(edges),
        "cycles": detect_cycles(edges),
        "attack_paths": find_attack_paths(nodes, edges),
        "highest_risk_node": highest_risk_node(nodes),
    }
