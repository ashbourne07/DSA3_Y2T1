# routers/graph.py
# Endpoints for the attack graph, BFS/DFS traversal, and choke points.

from fastapi import APIRouter, HTTPException
from database import get_collection
from config import COLLECTION_GRAPHS

router = APIRouter(prefix="/api/graph", tags=["Graph"])


@router.get("/")
async def get_graph():
    """
    Get the attack graph data for frontend visualisation.
    Returns nodes and links in react-force-graph-2d compatible format.
    """
    col  = get_collection(COLLECTION_GRAPHS)
    doc  = await col.find_one({}, {"_id": 0})

    if not doc:
        return {"message": "No graph data found. Import logs first.", "nodes": [], "links": []}

    return {
        "graph":       doc.get("graph_data", {}),
        "traversal":   doc.get("traversal", {}),
        "choke_points": doc.get("choke_points", {}),
    }


@router.get("/traversal")
async def get_traversal():
    """Get BFS and DFS traversal results."""
    col = get_collection(COLLECTION_GRAPHS)
    doc = await col.find_one({}, {"_id": 0})

    if not doc:
        return {"message": "No traversal data. Import logs first."}

    return doc.get("traversal", {})


@router.get("/choke-points")
async def get_choke_points():
    """
    Get articulation points (graphically critical nodes) and bridges.
    These are potential network choke points identified by Tarjan's algorithm.
    """
    col = get_collection(COLLECTION_GRAPHS)
    doc = await col.find_one({}, {"_id": 0})

    if not doc:
        return {"message": "No choke point data. Import logs first."}

    cp = doc.get("choke_points", {})
    return {
        "articulation_points": cp.get("articulation_points", []),
        "bridges":             cp.get("bridges", []),
        "ap_count":            cp.get("ap_count", 0),
        "bridge_count":        cp.get("bridge_count", 0),
        "node_details":        cp.get("node_details", {}),
        "note": (
            "Articulation points are graphically critical nodes whose removal "
            "would disconnect the graph. This is an academic demonstration "
            "of Tarjan's algorithm and does not constitute real security advice."
        )
    }


def _reconstruct_graph(graph_data: dict):
    from algorithms.graph import AttackGraph
    g = AttackGraph()
    for n in graph_data.get("nodes", []):
        nid = n.get("id") if isinstance(n, dict) else str(n)
        label = n.get("label", nid) if isinstance(n, dict) else nid
        ntype = n.get("node_type", "host") if isinstance(n, dict) else "host"
        g.add_node(nid, label=label, node_type=ntype)
    for l in graph_data.get("links", []):
        src = l["source"]["id"] if isinstance(l.get("source"), dict) else l.get("source")
        dst = l["target"]["id"] if isinstance(l.get("target"), dict) else l.get("target")
        if src and dst:
            g.add_edge(src, dst, edge_type=l.get("edge_type", "connection"), event_type=l.get("event_type", ""))
    return g


@router.get("/traverse")
async def run_traversal(start: str, type: str = "bfs"):
    """
    Run BFS or DFS dynamically from any selected start node.
    Returns step-by-step traversal order and state.
    """
    from algorithms.bfs_dfs import bfs, dfs
    col = get_collection(COLLECTION_GRAPHS)
    doc = await col.find_one({}, {"_id": 0})
    if not doc or not doc.get("graph_data"):
        raise HTTPException(status_code=404, detail="No graph data found. Import logs first.")

    g = _reconstruct_graph(doc["graph_data"])
    if start not in g.adj_list:
        raise HTTPException(status_code=400, detail=f"Node '{start}' not found in graph.")

    if type.lower() == "dfs":
        res = dfs(g, start)
    else:
        res = bfs(g, start)

    return {
        "start_node": start,
        "type": type.upper(),
        "result": res
    }


@router.get("/path")
async def get_path(start: str, end: str):
    """
    Calculate the BFS shortest path and all simple paths between any two nodes.
    Demonstrates BFS fewest hops and DFS path enumeration.
    """
    from algorithms.bfs_dfs import bfs_shortest_path, find_all_paths
    col = get_collection(COLLECTION_GRAPHS)
    doc = await col.find_one({}, {"_id": 0})
    if not doc or not doc.get("graph_data"):
        raise HTTPException(status_code=404, detail="No graph data found. Import logs first.")

    g = _reconstruct_graph(doc["graph_data"])
    shortest = bfs_shortest_path(g, start, end)
    all_paths = find_all_paths(g, start, end, max_depth=8)

    return {
        "start": start,
        "end": end,
        "shortest_path": shortest,
        "hop_count": max(0, len(shortest) - 1) if shortest else 0,
        "all_paths": all_paths,
        "all_paths_count": len(all_paths),
    }


@router.get("/simulate-cut")
async def simulate_cut(node: str):
    """
    Simulate what happens if a node (e.g. an articulation point) is removed/isolated.
    Demonstrates Tarjan's Articulation Point definition: removal increases connected components.
    """
    col = get_collection(COLLECTION_GRAPHS)
    doc = await col.find_one({}, {"_id": 0})
    if not doc or not doc.get("graph_data"):
        raise HTTPException(status_code=404, detail="No graph data found. Import logs first.")

    graph_data = doc["graph_data"]
    g = _reconstruct_graph(graph_data)
    all_nodes = g.get_all_nodes()

    if node not in all_nodes:
        raise HTTPException(status_code=400, detail=f"Node '{node}' not found in graph.")

    def get_components(excluded=None):
        active = [n for n in all_nodes if n != excluded]
        adj = {n: set() for n in active}
        for n in active:
            for neighbour in g.get_neighbours(n):
                t = neighbour["to"]
                if t != excluded and t in adj:
                    adj[n].add(t)
                    adj[t].add(n)
        visited = set()
        comps = []
        for n in active:
            if n not in visited:
                c = []
                queue = [n]
                visited.add(n)
                while queue:
                    curr = queue.pop(0)
                    c.append(curr)
                    for nxt in adj[curr]:
                        if nxt not in visited:
                            visited.add(nxt)
                            queue.append(nxt)
                comps.append(sorted(c))
        return comps

    initial_components = get_components(excluded=None)
    cut_components = get_components(excluded=node)

    # Check choke point status
    choke_points = doc.get("choke_points", {}).get("articulation_points", [])
    is_ap = node in choke_points

    return {
        "isolated_node": node,
        "is_articulation_point": is_ap,
        "initial_component_count": len(initial_components),
        "post_cut_component_count": len(cut_components),
        "graph_disconnected": len(cut_components) > len(initial_components),
        "components_before": initial_components,
        "components_after": cut_components,
        "explanation": (
            f"Removing '{node}' splits the network into {len(cut_components)} disconnected clusters. "
            f"This confirms '{node}' is {'an Articulation Point (Choke Point)' if is_ap else 'not an articulation point'}."
        )
    }

