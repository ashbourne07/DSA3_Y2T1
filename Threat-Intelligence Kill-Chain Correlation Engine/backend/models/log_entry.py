# models/log_entry.py
#
# LogEntry — represents one row from the security log CSV.
# We use Pydantic so FastAPI can automatically validate incoming data.

from pydantic import BaseModel, Field
from typing import Optional


class LogEntry(BaseModel):
    """
    A single security log entry.
    Matches the columns in sample_logs.csv.
    """
    log_id:         str            # e.g. "L001"
    timestamp:      str            # e.g. "2024-01-15 08:00:01"
    source_ip:      str            # e.g. "192.168.1.10"
    destination_ip: str            # e.g. "192.168.1.50"
    event_type:     str            # e.g. "LOGIN_FAILED"
    description:    str            # Human-readable description
    severity:       str            # LOW / MEDIUM / HIGH / CRITICAL


class LogEntryInDB(LogEntry):
    """
    LogEntry as stored in MongoDB.
    MongoDB adds an _id field; we use log_id as our identifier.
    """
    id: Optional[str] = Field(default=None, alias="_id")

    class Config:
        populate_by_name = True
