# database.py — MongoDB async client using Motor
#
# Motor is the async MongoDB driver built for FastAPI.
# We create one client at startup and reuse it for all requests.
# This avoids creating a new connection on every API call.

import motor.motor_asyncio
from config import MONGO_URL, DB_NAME

# Single global client instance
client = motor.motor_asyncio.AsyncIOMotorClient(MONGO_URL)

# The database
db = client[DB_NAME]


def get_collection(name: str):
    """Return a MongoDB collection by name."""
    return db[name]
