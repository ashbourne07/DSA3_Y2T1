# algorithms/graph.py
#
# ─────────────────────────────────────────────────────────────
# DSA CONCEPT: Graph (Adjacency List representation)
#
# USED FOR:
#   Representing the network/attack topology.
#   Nodes = network hosts (workstations, servers, databases).
#   Edges = connections or attack movements between hosts.
#
# WHY ADJACENCY LIST (not Adjacency Matrix)?
#   A matrix uses O(V²) space.
#   In a real network, most pairs of nodes are NOT directly connected.
#   The graph is therefore "sparse" — few edges relative to nodes.
#   Adjacency list uses O(V + E) space, which is much more efficient
#   for sparse graphs.
#
# SPACE COMPLEXITY: O(V + E)
#   V = number of vertices (network nodes)
#   E = number of edges (connections)
# ─────────────────────────────────────────────────────────────


class AttackGraph:
    """
    Directed graph using an adjacency list.

    The adjacency list is a Python dict (hash map):
      Key:   node ID (string, e.g. "192.168.1.10")
      Value: dict with node metadata and list of neighbours

    Example:
      graph.adj_list = {
          "192.168.1.10": {
              "label": "Attacker Workstation",
              "node_type": "workstation",
              "neighbours": [
                  {"to": "192.168.1.50", "edge_type": "attack", "event_type": "LOGIN_FAILED"}
              ]
          },
          "192.168.1.50": { ... }
      }
    """

    def __init__(self):
        # The adjacency list — a dict of dicts
        self.adj_list: dict = {}

    def add_node(self, node_id: str, label: str = "", node_type: str = "host"):
        """
        Add a node to the graph if it doesn't exist yet.

        Args:
            node_id:   unique identifier (usually an IP address)
            label:     human-readable name (optional)
            node_type: "workstation", "server", "database", "firewall", etc.
        """
        if node_id not in self.adj_list:
            self.adj_list[node_id] = {
                "label":      label or node_id,
                "node_type":  node_type,
                "neighbours": []    # list of edge dicts
            }

    def add_edge(self, from_node: str, to_node: str,
                 edge_type: str = "connection", event_type: str = ""):
        """
        Add a directed edge from from_node to to_node.
        Both nodes are created automatically if they don't exist.

        Args:
            from_node:  source node ID
            to_node:    destination node ID
            edge_type:  "attack", "lateral_movement", "normal", "data_transfer"
            event_type: the log event that created this edge (e.g. "LOGIN_FAILED")
        """
        # Ensure both nodes exist
        self.add_node(from_node)
        self.add_node(to_node)

        # Check for duplicate edge (same from→to with same event_type)
        existing_neighbours = self.adj_list[from_node]["neighbours"]
        for n in existing_neighbours:
            if n["to"] == to_node and n["event_type"] == event_type:
                return  # edge already exists

        # Add the directed edge
        self.adj_list[from_node]["neighbours"].append({
            "to":         to_node,
            "edge_type":  edge_type,
            "event_type": event_type,
        })

    def get_neighbours(self, node_id: str) -> list:
        """Return the list of neighbour dicts for a node."""
        if node_id not in self.adj_list:
            return []
        return self.adj_list[node_id]["neighbours"]

    def get_all_nodes(self) -> list:
        """Return all node IDs."""
        return list(self.adj_list.keys())

    def get_all_edges(self) -> list:
        """
        Return all edges as (from, to, edge_type) tuples.
        Useful for serialising the graph to JSON.
        """
        edges = []
        for node_id, data in self.adj_list.items():
            for neighbour in data["neighbours"]:
                edges.append({
                    "from":       node_id,
                    "to":         neighbour["to"],
                    "edge_type":  neighbour["edge_type"],
                    "event_type": neighbour["event_type"],
                })
        return edges

    def node_count(self) -> int:
        """Number of nodes (vertices) in the graph."""
        return len(self.adj_list)

    def edge_count(self) -> int:
        """Number of directed edges in the graph."""
        return sum(
            len(data["neighbours"])
            for data in self.adj_list.values()
        )

    def to_dict(self) -> dict:
        """
        Serialise the graph to a plain dict for MongoDB storage and API response.
        Format compatible with react-force-graph-2d on the frontend.
        """
        nodes = [
            {
                "id":        nid,
                "label":     data["label"],
                "node_type": data["node_type"],
            }
            for nid, data in self.adj_list.items()
        ]
        links = [
            {
                "source":     edge["from"],
                "target":     edge["to"],
                "edge_type":  edge["edge_type"],
                "event_type": edge["event_type"],
            }
            for edge in self.get_all_edges()
        ]
        return {"nodes": nodes, "links": links}

    @classmethod
    def from_logs(cls, log_events: list) -> "AttackGraph":
        """
        Build an AttackGraph directly from a list of log event dicts.

        Each log with a source_ip and destination_ip creates:
          - a node for source_ip
          - a node for destination_ip
          - a directed edge from source → destination

        Normal events and attack events both appear in the graph —
        this shows the full network topology.
        """
        graph = cls()

        # Classify node types based on common IP patterns in sample data
        # In a real system, this would come from a network inventory.
        def classify_node(ip: str) -> str:
            if ip.startswith("10.0.0"):
                return "external"
            if ip.endswith(".100"):
                return "database"
            if ip.endswith(".50") or ip.endswith(".20"):
                return "server"
            if ip.startswith("10.") or ip.startswith("172."):
                return "external"
            return "workstation"

        # Classify edge type based on event type
        attack_events = {
            "LOGIN_FAILED", "MALWARE_DETECTED", "SUSPICIOUS_PROCESS",
            "PRIVILEGE_ESCALATION", "LATERAL_MOVEMENT", "DATABASE_ACCESS",
            "DATA_EXFILTRATION", "PORT_SCAN", "UNUSUAL_LOGIN"
        }

        for log in log_events:
            src = log.get('source_ip', '')
            dst = log.get('destination_ip', '')
            evt = log.get('event_type', '')

            if not src or not dst:
                continue

            edge_type = "attack" if evt in attack_events else "normal"

            graph.add_node(src, label=src, node_type=classify_node(src))
            graph.add_node(dst, label=dst, node_type=classify_node(dst))
            graph.add_edge(src, dst, edge_type=edge_type, event_type=evt)

        return graph
