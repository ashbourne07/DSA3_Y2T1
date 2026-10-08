# services/kill_chain_builder.py
#
# Reconstructs the attack kill chain from correlated alerts.
#
# WHAT IS A KILL CHAIN?
#   A kill chain is the sequence of steps an attacker takes from
#   initial access all the way to their goal (data theft, etc.).
#   We map each alert's kill_chain_stage to the standard stages:
#
#   Reconnaissance → Initial Access → Execution →
#   Privilege Escalation → Lateral Movement → Collection → Exfiltration
#
# HOW IT WORKS:
#   For each correlation group, we look at which kill chain stages
#   were observed. We then build an ordered sequence of only the
#   stages that are PRESENT in the data — we never invent a stage.
#   Missing stages are marked as "Not Observed".
#
# This is a simplified academic implementation.

# The canonical order of kill chain stages used in this project
KILL_CHAIN_ORDER = [
    "Reconnaissance",
    "Initial Access",
    "Execution",
    "Privilege Escalation",
    "Lateral Movement",
    "Collection",
    "Exfiltration",
]


def build_kill_chain(correlation: dict, alerts: list) -> dict:
    """
    Build a kill chain record from one correlation group.

    Args:
        correlation: one correlation dict from alert_correlator
        alerts:      all alerts (to look up detail by alert_id)

    Returns:
        kill_chain dict containing:
            - kill_chain_id
            - correlation_id
            - source_ip
            - stages:  ordered list of stage dicts:
                { stage, status: "Observed"/"Not Observed", alert_ids }
            - observed_count: how many stages were observed
            - severity: max severity from correlation
    """
    # Build a hash map from alert_id → alert for fast lookups
    alert_map = {a['alert_id']: a for a in alerts}

    # Collect the stages that were actually seen in this correlation
    # Key: stage name → list of alert_ids that represent this stage
    stage_to_alerts: dict = {}
    for alert_id in correlation['alert_ids']:
        alert = alert_map.get(alert_id)
        if alert:
            stage = alert.get('kill_chain_stage', '')
            if stage:
                if stage not in stage_to_alerts:
                    stage_to_alerts[stage] = []
                stage_to_alerts[stage].append(alert_id)

    # Build the ordered stage list
    stages = []
    for stage_name in KILL_CHAIN_ORDER:
        if stage_name in stage_to_alerts:
            stages.append({
                "stage":     stage_name,
                "status":    "Observed",
                "alert_ids": stage_to_alerts[stage_name],
            })
        else:
            stages.append({
                "stage":     stage_name,
                "status":    "Not Observed",
                "alert_ids": [],
            })

    observed_count = sum(1 for s in stages if s['status'] == "Observed")

    return {
        "kill_chain_id":    f"KC{correlation['correlation_id'].replace('CORR', '')}",
        "correlation_id":   correlation['correlation_id'],
        "source_ip":        correlation['source_ip'],
        "stages":           stages,
        "observed_count":   observed_count,
        "total_stages":     len(KILL_CHAIN_ORDER),
        "severity":         correlation['max_severity'],
        "attack_types":     correlation['attack_types'],
    }


def build_all_kill_chains(correlations: list, alerts: list) -> list:
    """
    Build kill chains for all correlation groups.

    Args:
        correlations: output from alert_correlator.correlate_alerts()
        alerts:       all alerts

    Returns:
        list of kill chain dicts
    """
    return [build_kill_chain(corr, alerts) for corr in correlations]
