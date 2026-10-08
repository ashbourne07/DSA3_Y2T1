# services/alert_correlator.py
#
# Correlates related alerts into attack sequences.
#
# WHY DO WE NEED CORRELATION?
#   A single cyberattack generates many alerts — one for brute force,
#   one for malware, one for privilege escalation. Without correlation,
#   the analyst sees a flood of unconnected alerts. Correlation groups
#   them into a single meaningful attack sequence.
#
# HOW IT WORKS (simplified academic approach):
#   Two alerts are correlated if they share the same source_ip.
#   We use a Python dict (hash map) to group alerts by source_ip → O(n).
#   Each group is one "correlated attack sequence".
#
# This is a simplified academic implementation.
# A real SOC correlator uses timestamps, network topology, and ML.


def correlate_alerts(alerts: list) -> list:
    """
    Group alerts into correlated attack sequences.

    Strategy: alerts from the same source IP are grouped together.
    Within each group, alerts are ordered by their alert_id.

    Args:
        alerts: list of Alert dicts from alert_generator

    Returns:
        correlations: list of correlation dicts, each containing:
            - correlation_id:   e.g. "CORR001"
            - source_ip:        the common source
            - alert_ids:        list of alert_ids in this sequence
            - attack_types:     list of unique attack types seen
            - max_severity:     highest severity in this group
            - alert_count:      number of alerts
    """
    if not alerts:
        return []

    # Step 1: Group alerts by source_ip using a hash map — O(n)
    # Key:   source_ip string
    # Value: list of alert dicts with that source_ip
    groups: dict = {}
    for alert in alerts:
        src = alert['source_ip']
        if src not in groups:
            groups[src] = []
        groups[src].append(alert)

    # Severity rank for finding the max in a group
    severity_rank = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}

    correlations = []
    corr_counter = 1

    for source_ip, group_alerts in groups.items():
        # Sort alerts in this group by alert_id (preserves detection order)
        sorted_alerts = sorted(group_alerts, key=lambda a: a['alert_id'])

        # Find the highest severity in this group
        max_sev = max(
            sorted_alerts,
            key=lambda a: severity_rank.get(a['severity'], 0)
        )['severity']

        # Collect unique attack types in order seen
        seen_types = []
        for a in sorted_alerts:
            if a['attack_type'] not in seen_types:
                seen_types.append(a['attack_type'])

        # Collect all related log IDs across the whole sequence
        all_log_ids = []
        for a in sorted_alerts:
            for lid in a.get('related_log_ids', []):
                if lid not in all_log_ids:
                    all_log_ids.append(lid)

        # Collect kill chain stages in order
        stages_seen = []
        for a in sorted_alerts:
            stage = a.get('kill_chain_stage', '')
            if stage and stage not in stages_seen:
                stages_seen.append(stage)

        correlations.append({
            "correlation_id":   f"CORR{corr_counter:03d}",
            "source_ip":        source_ip,
            "alert_ids":        [a['alert_id'] for a in sorted_alerts],
            "attack_types":     seen_types,
            "kill_chain_stages": stages_seen,
            "max_severity":     max_sev,
            "alert_count":      len(sorted_alerts),
            "related_log_ids":  all_log_ids,
        })
        corr_counter += 1

    return correlations
