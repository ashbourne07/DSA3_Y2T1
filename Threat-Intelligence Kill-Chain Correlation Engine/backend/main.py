# main.py — FastAPI application entry point
#
# Threat-Intelligence Kill-Chain Correlation Engine
# DSA-3 College Project — Academic prototype.
# NOT a real production security tool.
#
# Run with:
#   cd backend
#   uvicorn main:app --reload

from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from routers import logs, alerts, graph, analysis


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Auto-load sample logs if database is empty so frontend always has data immediately
    try:
        from database import get_collection
        from config import COLLECTION_LOGS
        col = get_collection(COLLECTION_LOGS)
        count = await col.count_documents({})
        if count == 0:
            print("[STARTUP] No logs found in MongoDB — auto-loading sample logs...")
            from routers.logs import import_sample_logs
            await import_sample_logs()
            print("[STARTUP] Sample logs loaded successfully.")
    except Exception as e:
        print(f"[STARTUP WARNING] Could not auto-load sample logs: {e}")
    yield


app = FastAPI(
    title="Threat Kill-Chain Correlation Engine",
    description=(
        "DSA-3 College Project. Demonstrates Hashing, KMP Pattern Matching, "
        "Graph (Adjacency List), BFS, DFS, Articulation Points, "
        "Greedy Optimisation, and Priority Queue applied to security log analysis. "
        "Academic prototype — not a real SOC tool."
    ),
    version="1.0.0",
    lifespan=lifespan,
)

# Allow the React frontend (localhost:5173) to call this API
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register routers
app.include_router(logs.router)
app.include_router(alerts.router)
app.include_router(graph.router)
app.include_router(analysis.router)


@app.get("/")
def root():
    return {
        "project": "Threat Kill-Chain Correlation Engine",
        "version": "1.0.0",
        "status":  "running",
        "endpoints": {
            "import_sample": "POST /api/logs/import-sample",
            "import_csv":    "POST /api/logs/import",
            "logs":          "GET  /api/logs/",
            "alerts":        "GET  /api/alerts/",
            "priority":      "GET  /api/alerts/priority",
            "graph":         "GET  /api/graph/",
            "choke_points":  "GET  /api/graph/choke-points",
            "kill_chains":   "GET  /api/analysis/kill-chains",
            "correlations":  "GET  /api/analysis/correlations",
            "monitoring":    "GET  /api/analysis/monitoring",
            "dashboard":     "GET  /api/analysis/dashboard",
            "docs":          "GET  /docs",
        }
    }


@app.get("/api/health")
def health():
    return {"status": "ok"}
