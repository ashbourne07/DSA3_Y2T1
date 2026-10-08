# services/log_processor.py
#
# Parses the CSV log file, validates each row, and runs the full DSA pipeline.
# This is the entry point that connects all algorithm modules together.

import csv
import io
from datetime import datetime

from algorithms.hash_lookup import signature_table
from algorithms.kmp import find_attack_patterns_in_logs
from algorithms.graph import AttackGraph
from algorithms.bfs_dfs import bfs, dfs, bfs_shortest_path
from algorithms.articulation_points import find_articulation_points_and_bridges
from algorithms.priority_queue import get_prioritised_alerts
from services.alert_generator import generate_alerts_from_matches, deduplicate_alerts
from services.alert_correlator import correlate_alerts
from services.kill_chain_builder import build_all_kill_chains
from services.monitoring_optimizer import run_monitoring_analysis


REQUIRED_COLUMNS = {
    'log_id', 'timestamp', 'source_ip',
    'destination_ip', 'event_type', 'description', 'severity'
}

VALID_SEVERITIES = {'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'}


def parse_logs_from_csv(csv_content: str) -> tuple[list, list]:
    """
    Parse a CSV string into a list of log dicts.
    Validates each row and collects any errors.

    Args:
        csv_content: raw CSV text

    Returns:
        (valid_logs, errors)
        valid_logs: list of log dicts
        errors:     list of error message strings
    """
    valid_logs = []
    errors = []

    try:
        reader = csv.DictReader(io.StringIO(csv_content.strip()))
    except Exception as e:
        return [], [f"Failed to parse CSV: {str(e)}"]

    # Check required columns exist
    if reader.fieldnames is None:
        return [], ["CSV has no header row."]

    missing = REQUIRED_COLUMNS - set(reader.fieldnames)
    if missing:
        return [], [f"CSV is missing required columns: {missing}"]

    for row_num, row in enumerate(reader, start=2):
        # Strip whitespace from all values
        row = {k: v.strip() for k, v in row.items() if k}

        # Skip completely empty rows
        if not any(row.values()):
            continue

        # Validate required fields are not empty
        empty_fields = [col for col in REQUIRED_COLUMNS if not row.get(col)]
        if empty_fields:
            errors.append(f"Row {row_num}: missing values for {empty_fields}")
            continue

        # Validate severity
        if row.get('severity', '').upper() not in VALID_SEVERITIES:
            errors.append(
                f"Row {row_num}: invalid severity '{row.get('severity')}'. "
                f"Must be one of {VALID_SEVERITIES}."
            )
            row['severity'] = 'LOW'  # default instead of skipping

        # Normalise severity to uppercase
        row['severity']    = row['severity'].upper()
        row['event_type']  = row['event_type'].upper()

        valid_logs.append(row)

    return valid_logs, errors


def run_full_pipeline(logs: list) -> dict:
    """
    Run the complete DSA pipeline on a list of log dicts.

    Pipeline steps:
      1. Hash lookup  → classify each event type
      2. KMP          → detect attack patterns
      3. Alert gen    → create alert objects
      4. Dedup        → remove duplicate alerts
      5. Correlation  → group related alerts
      6. Kill chain   → reconstruct attack sequences
      7. Graph        → build attack graph
      8. BFS / DFS    → traverse graph
      9. Art. points  → find choke points
     10. Monitoring   → greedy coverage recommendation
     11. Priority Q   → sort alerts by severity

    Args:
        logs: list of validated log dicts

    Returns:
        pipeline_result: dict with all results for API response and DB storage
    """
    if not logs:
        return {"error": "No logs to process."}

    # ── Step 1: Hash lookup — classify all event types ──────
    for log in logs:
        category_info = signature_table.get_event_category(log['event_type'])
        log['category']      = category_info['category']
        log['is_suspicious'] = signature_table.is_suspicious_event(log['event_type'])

    # ── Step 2: KMP pattern matching ─────────────────────────
    all_signatures = signature_table.get_all_signatures()
    matches = find_attack_patterns_in_logs(logs, all_signatures)

    # ── Step 3: Alert generation ──────────────────────────────
    raw_alerts = generate_alerts_from_matches(matches, logs)

    # ── Step 4: Deduplication ─────────────────────────────────
    alerts = deduplicate_alerts(raw_alerts)

    # ── Step 5: Alert correlation ─────────────────────────────
    correlations = correlate_alerts(alerts)

    # ── Step 6: Kill chain reconstruction ────────────────────
    kill_chains = build_all_kill_chains(correlations, alerts)

    # ── Step 7: Build attack graph ────────────────────────────
    graph = AttackGraph.from_logs(logs)
    graph_data = graph.to_dict()

    # ── Step 8: BFS and DFS traversal ────────────────────────
    # Find the most common source IP as starting point
    source_ips = [log['source_ip'] for log in logs]
    start_node = max(set(source_ips), key=source_ips.count) if source_ips else None

    bfs_result = bfs(graph, start_node) if start_node else {}
    dfs_result = dfs(graph, start_node) if start_node else {}

    # Find shortest path from first attacker IP to any database node
    db_nodes   = [n for n in graph.get_all_nodes() if n.endswith('.100')]
    shortest_path = []
    if start_node and db_nodes:
        shortest_path = bfs_shortest_path(graph, start_node, db_nodes[0])

    # ── Step 9: Articulation points and bridges ───────────────
    ap_result = find_articulation_points_and_bridges(graph)

    # ── Step 10: Monitoring optimisation ──────────────────────
    monitoring_result = run_monitoring_analysis(graph, alerts)

    # ── Step 11: Priority queue ───────────────────────────────
    prioritised_alerts = get_prioritised_alerts(alerts)

    # ── Assemble final result ─────────────────────────────────
    return {
        "processed_at":     datetime.utcnow().isoformat(),
        "total_logs":        len(logs),
        "suspicious_logs":   sum(1 for l in logs if l.get('is_suspicious')),
        "total_alerts":      len(alerts),
        "total_correlations": len(correlations),
        "total_kill_chains": len(kill_chains),
        "alerts":            alerts,
        "correlations":      correlations,
        "kill_chains":       kill_chains,
        "graph":             graph_data,
        "traversal": {
            "start_node":     start_node,
            "bfs":            bfs_result,
            "dfs":            dfs_result,
            "shortest_path":  shortest_path,
        },
        "choke_points":      ap_result,
        "monitoring":        monitoring_result,
        "prioritised_alerts": prioritised_alerts,
    }
