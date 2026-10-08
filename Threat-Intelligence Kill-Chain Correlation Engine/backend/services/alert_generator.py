# services/alert_generator.py
#
# Generates Alert objects from KMP pattern matches.
# Uses the SignatureHashTable for O(1) severity/description lookup.
# Saves alerts to MongoDB.

from datetime import datetime
from algorithms.hash_lookup import signature_table


def generate_alerts_from_matches(matches: list, log_events: list) -> list:
    """
    Convert KMP pattern matches into Alert dicts.

    For each match result from find_attack_patterns_in_logs():
      - extract source/destination from the first matched log
      - use hash lookup to get signature details
      - assign a unique alert_id
      - build an Alert dict

    Args:
        matches:    output from find_attack_patterns_in_logs()
        log_events: the original list of log dicts (to get IP addresses)

    Returns:
        alerts: list of Alert dicts ready to be saved to MongoDB
    """
    # Build a quick log_id → log dict map for fast lookup
    # This is another hash map — O(1) access per log
    log_map = {log['log_id']: log for log in log_events}

    alerts = []
    alert_counter = 1

    for match in matches:
        sig = signature_table.get_signature_by_id(match['signature_id'])

        for i, log_id_group in enumerate(match['matched_log_ids']):
            # Get IP info from the first log in this match group
            first_log_id = log_id_group[0] if log_id_group else None
            first_log = log_map.get(first_log_id, {}) if first_log_id else {}

            last_log_id = log_id_group[-1] if log_id_group else None
            last_log = log_map.get(last_log_id, {}) if last_log_id else {}

            alert = {
                "alert_id":         f"A{alert_counter:03d}",
                "timestamp":        datetime.utcnow().isoformat(),
                "source_ip":        first_log.get('source_ip', 'unknown'),
                "destination_ip":   last_log.get('destination_ip', 'unknown'),
                "attack_type":      match['attack_type'],
                "severity":         match['severity'],
                "description":      match['description'],
                "related_log_ids":  log_id_group,
                "signature_id":     match['signature_id'],
                "kill_chain_stage": match['kill_chain_stage'],
            }
            alerts.append(alert)
            alert_counter += 1

    return alerts


def deduplicate_alerts(alerts: list) -> list:
    """
    Remove duplicate alerts.
    Two alerts are duplicates if they have the same source_ip,
    attack_type, and the same set of related_log_ids.

    This handles the edge case: running the pipeline twice should not
    create double the alerts.

    Returns: deduplicated list of alerts
    """
    seen = set()
    unique = []
    for alert in alerts:
        # Create a hashable key from the alert's identifying fields
        key = (
            alert['source_ip'],
            alert['attack_type'],
            tuple(sorted(alert['related_log_ids']))
        )
        if key not in seen:
            seen.add(key)
            unique.append(alert)
    return unique
