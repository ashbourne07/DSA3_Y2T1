# routers/logs.py
# Endpoints for importing and reading security logs.

from fastapi import APIRouter, HTTPException, UploadFile, File
from database import get_collection
from services.log_processor import parse_logs_from_csv, run_full_pipeline
from config import (
    COLLECTION_LOGS, COLLECTION_ALERTS, COLLECTION_CORRELATIONS,
    COLLECTION_KILL_CHAINS, COLLECTION_GRAPHS, COLLECTION_ANALYSIS
)
import os

router = APIRouter(prefix="/api/logs", tags=["Logs"])


@router.post("/import")
async def import_logs_from_csv(file: UploadFile = File(...)):
    """
    Import security logs from a CSV file.
    Parses the file, runs the full DSA pipeline,
    and saves all results to MongoDB.
    """
    if not file.filename.endswith('.csv'):
        raise HTTPException(status_code=400, detail="Only CSV files are accepted.")

    content = await file.read()
    csv_text = content.decode('utf-8')

    # Parse and validate
    logs, errors = parse_logs_from_csv(csv_text)

    if not logs:
        raise HTTPException(
            status_code=400,
            detail={"message": "No valid logs found.", "errors": errors}
        )

    # Clear previous data
    logs_col   = get_collection(COLLECTION_LOGS)
    alerts_col = get_collection(COLLECTION_ALERTS)
    corr_col   = get_collection(COLLECTION_CORRELATIONS)
    kc_col     = get_collection(COLLECTION_KILL_CHAINS)
    graph_col  = get_collection(COLLECTION_GRAPHS)
    anal_col   = get_collection(COLLECTION_ANALYSIS)

    await logs_col.delete_many({})
    await alerts_col.delete_many({})
    await corr_col.delete_many({})
    await kc_col.delete_many({})
    await graph_col.delete_many({})
    await anal_col.delete_many({})

    # Save logs
    await logs_col.insert_many(logs)

    # Run full pipeline
    result = run_full_pipeline(logs)

    # Save pipeline results to MongoDB
    if result.get('alerts'):
        await alerts_col.insert_many(result['alerts'])
    if result.get('correlations'):
        await corr_col.insert_many(result['correlations'])
    if result.get('kill_chains'):
        await kc_col.insert_many(result['kill_chains'])
    if result.get('graph'):
        await graph_col.insert_one({
            "graph_data": result['graph'],
            "traversal":  result.get('traversal', {}),
            "choke_points": result.get('choke_points', {}),
        })
    if result.get('monitoring'):
        await anal_col.insert_one(result['monitoring'])

    return {
        "message":     "Logs imported and pipeline executed successfully.",
        "total_logs":  result['total_logs'],
        "parse_errors": errors,
        "summary": {
            "suspicious_logs":    result['suspicious_logs'],
            "alerts_generated":   result['total_alerts'],
            "correlations":       result['total_correlations'],
            "kill_chains":        result['total_kill_chains'],
        }
    }


@router.post("/import-sample")
async def import_sample_logs():
    """
    Import the built-in sample_logs.csv for demo purposes.
    """
    sample_path = os.path.join(
        os.path.dirname(__file__), '..', 'data', 'sample_logs.csv'
    )
    if not os.path.exists(sample_path):
        raise HTTPException(status_code=404, detail="Sample logs file not found.")

    with open(sample_path, 'r') as f:
        csv_text = f.read()

    logs, errors = parse_logs_from_csv(csv_text)
    if not logs:
        raise HTTPException(status_code=500, detail={"message": "Failed to parse sample logs.", "errors": errors})

    # Clear previous data
    for col_name in [COLLECTION_LOGS, COLLECTION_ALERTS, COLLECTION_CORRELATIONS,
                     COLLECTION_KILL_CHAINS, COLLECTION_GRAPHS, COLLECTION_ANALYSIS]:
        await get_collection(col_name).delete_many({})

    await get_collection(COLLECTION_LOGS).insert_many(logs)

    result = run_full_pipeline(logs)

    if result.get('alerts'):
        await get_collection(COLLECTION_ALERTS).insert_many(result['alerts'])
    if result.get('correlations'):
        await get_collection(COLLECTION_CORRELATIONS).insert_many(result['correlations'])
    if result.get('kill_chains'):
        await get_collection(COLLECTION_KILL_CHAINS).insert_many(result['kill_chains'])
    if result.get('graph'):
        await get_collection(COLLECTION_GRAPHS).insert_one({
            "graph_data":   result['graph'],
            "traversal":    result.get('traversal', {}),
            "choke_points": result.get('choke_points', {}),
        })
    if result.get('monitoring'):
        await get_collection(COLLECTION_ANALYSIS).insert_one(result['monitoring'])

    return {
        "message":   "Sample logs imported successfully.",
        "total_logs": result['total_logs'],
        "summary": {
            "suspicious_logs":  result['suspicious_logs'],
            "alerts_generated": result['total_alerts'],
            "correlations":     result['total_correlations'],
            "kill_chains":      result['total_kill_chains'],
        }
    }


@router.get("/")
async def get_logs(limit: int = 100, skip: int = 0):
    """Get all imported logs from MongoDB."""
    col  = get_collection(COLLECTION_LOGS)
    logs = await col.find({}, {"_id": 0}).skip(skip).limit(limit).to_list(length=limit)
    total = await col.count_documents({})
    return {"total": total, "logs": logs}
