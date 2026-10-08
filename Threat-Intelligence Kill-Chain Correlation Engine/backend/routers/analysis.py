# routers/analysis.py
# Endpoints for kill chains, correlations, monitoring, and dashboard summary.

from fastapi import APIRouter
from database import get_collection
from config import (
    COLLECTION_ALERTS, COLLECTION_CORRELATIONS,
    COLLECTION_KILL_CHAINS, COLLECTION_GRAPHS, COLLECTION_ANALYSIS, COLLECTION_LOGS
)

router = APIRouter(prefix="/api/analysis", tags=["Analysis"])


@router.get("/correlations")
async def get_correlations():
    """Get all correlated attack sequences."""
    col   = get_collection(COLLECTION_CORRELATIONS)
    corrs = await col.find({}, {"_id": 0}).to_list(length=1000)
    return {"total": len(corrs), "correlations": corrs}


@router.get("/kill-chains")
async def get_kill_chains():
    """Get all reconstructed kill chains."""
    col    = get_collection(COLLECTION_KILL_CHAINS)
    chains = await col.find({}, {"_id": 0}).to_list(length=1000)
    return {"total": len(chains), "kill_chains": chains}


@router.get("/monitoring")
async def get_monitoring():
    """
    Get the greedy monitoring optimisation results.
    Shows recommended monitoring nodes and step-by-step coverage explanation.
    """
    col = get_collection(COLLECTION_ANALYSIS)
    doc = await col.find_one({}, {"_id": 0})

    if not doc:
        return {"message": "No monitoring data. Import logs first."}

    return doc


@router.get("/dashboard")
async def get_dashboard_summary():
    """
    Dashboard summary — all counts in one request.
    Used by the React Dashboard page.
    """
    logs_col  = get_collection(COLLECTION_LOGS)
    alert_col = get_collection(COLLECTION_ALERTS)
    corr_col  = get_collection(COLLECTION_CORRELATIONS)
    kc_col    = get_collection(COLLECTION_KILL_CHAINS)
    graph_col = get_collection(COLLECTION_GRAPHS)
    anal_col  = get_collection(COLLECTION_ANALYSIS)

    total_logs     = await logs_col.count_documents({})
    total_alerts   = await alert_col.count_documents({})
    total_corrs    = await corr_col.count_documents({})
    total_kc       = await kc_col.count_documents({})

    # Alert severity breakdown
    alerts = await alert_col.find({}, {"_id": 0, "severity": 1}).to_list(length=1000)
    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for a in alerts:
        sev = a.get('severity', 'LOW')
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    # Choke points
    graph_doc = await graph_col.find_one({}, {"_id": 0, "choke_points": 1})
    ap_count  = 0
    if graph_doc:
        ap_count = graph_doc.get("choke_points", {}).get("ap_count", 0)

    # Monitoring recommendation count
    anal_doc         = await anal_col.find_one({}, {"_id": 0, "monitoring_nodes": 1})
    monitoring_count = 0
    if anal_doc:
        monitoring_count = len(anal_doc.get("monitoring_nodes", []))

    return {
        "total_logs":          total_logs,
        "total_alerts":        total_alerts,
        "total_correlations":  total_corrs,
        "total_kill_chains":   total_kc,
        "severity_counts":     severity_counts,
        "choke_point_count":   ap_count,
        "monitoring_nodes_recommended": monitoring_count,
        "has_data":            total_logs > 0,
    }
