# config.py — Application configuration
# MongoDB connection settings for the Threat Kill-Chain Correlation Engine

MONGO_URL = "mongodb://localhost:27017"
DB_NAME   = "threat_kill_chain"

# Collection names
COLLECTION_LOGS         = "logs"
COLLECTION_ALERTS       = "alerts"
COLLECTION_CORRELATIONS = "correlations"
COLLECTION_KILL_CHAINS  = "kill_chains"
COLLECTION_GRAPHS       = "graphs"
COLLECTION_ANALYSIS     = "analysis"
