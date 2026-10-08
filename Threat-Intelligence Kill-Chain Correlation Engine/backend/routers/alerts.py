# routers/alerts.py
# Endpoints for reading alerts and priority-sorted alerts.

from fastapi import APIRouter, HTTPException
from database import get_collection
from algorithms.priority_queue import get_prioritised_alerts
from config import COLLECTION_ALERTS

router = APIRouter(prefix="/api/alerts", tags=["Alerts"])


@router.get("/")
async def get_alerts():
    """Get all alerts from MongoDB."""
    col    = get_collection(COLLECTION_ALERTS)
    alerts = await col.find({}, {"_id": 0}).to_list(length=1000)
    return {"total": len(alerts), "alerts": alerts}


@router.get("/priority")
async def get_prioritised():
    """
    Get all alerts sorted by priority using the max-heap priority queue.
    CRITICAL first → HIGH → MEDIUM → LOW.
    """
    col    = get_collection(COLLECTION_ALERTS)
    alerts = await col.find({}, {"_id": 0}).to_list(length=1000)

    if not alerts:
        return {"total": 0, "alerts": [], "message": "No alerts found. Import logs first."}

    sorted_alerts = get_prioritised_alerts(alerts)
    return {
        "total":  len(sorted_alerts),
        "alerts": sorted_alerts,
        "note":   "Sorted using max-heap priority queue. CRITICAL processed first."
    }


@router.get("/summary")
async def get_alert_summary():
    """Get a count of alerts grouped by severity."""
    col    = get_collection(COLLECTION_ALERTS)
    alerts = await col.find({}, {"_id": 0}).to_list(length=1000)

    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for a in alerts:
        sev = a.get('severity', 'LOW')
        counts[sev] = counts.get(sev, 0) + 1

    return {"severity_counts": counts, "total": len(alerts)}
