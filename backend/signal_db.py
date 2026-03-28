"""
signal_db.py — NSD v19 Signal History Database
Thread-safe SQLite persistence layer for RF detections.

Schema:
  detections(id, timestamp_utc, band, freq_mhz, power_db, noise_floor_db,
             snr_db, bandwidth_khz, protocol, threat_level, threat_score,
             simulated, session_id)

All writes go through a single writer thread via a queue to avoid
SQLite's "database is locked" errors under concurrent access.
Reads use a separate read-only connection per call (safe for SQLite WAL mode).
"""

import sqlite3
import threading
import queue
import logging
import csv
import io
import time
import uuid
from dataclasses import dataclass
from typing import List, Optional
from pathlib import Path

logger = logging.getLogger("nsd.signal_db")

_DDL = """
PRAGMA journal_mode=WAL;
PRAGMA synchronous=NORMAL;

CREATE TABLE IF NOT EXISTS detections (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp_utc   REAL    NOT NULL,
    band            TEXT    NOT NULL,
    freq_mhz        REAL    NOT NULL,
    power_db        REAL,
    noise_floor_db  REAL,
    snr_db          REAL,
    bandwidth_khz   REAL,
    protocol        TEXT,
    threat_level    TEXT,
    threat_score    INTEGER,
    simulated       INTEGER NOT NULL DEFAULT 0,
    session_id      TEXT    NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_timestamp ON detections(timestamp_utc DESC);
CREATE INDEX IF NOT EXISTS idx_band      ON detections(band);
CREATE INDEX IF NOT EXISTS idx_level     ON detections(threat_level);
"""

_INSERT_SQL = """
INSERT INTO detections
    (timestamp_utc, band, freq_mhz, power_db, noise_floor_db,
     snr_db, bandwidth_khz, protocol, threat_level, threat_score,
     simulated, session_id)
VALUES
    (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
"""


@dataclass
class DetectionRecord:
    id:             int
    timestamp_utc:  float
    band:           str
    freq_mhz:       float
    power_db:       Optional[float]
    noise_floor_db: Optional[float]
    snr_db:         Optional[float]
    bandwidth_khz:  Optional[float]
    protocol:       Optional[str]
    threat_level:   Optional[str]
    threat_score:   Optional[int]
    simulated:      bool
    session_id:     str

    def to_dict(self) -> dict:
        import datetime
        return {
            "id":             self.id,
            "timestamp_utc":  self.timestamp_utc,
            "timestamp_iso":  datetime.datetime.utcfromtimestamp(
                                  self.timestamp_utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "band":           self.band,
            "freq_mhz":       round(self.freq_mhz, 3),
            "power_db":       round(self.power_db, 1)       if self.power_db       is not None else None,
            "noise_floor_db": round(self.noise_floor_db, 1) if self.noise_floor_db is not None else None,
            "snr_db":         round(self.snr_db, 1)         if self.snr_db         is not None else None,
            "bandwidth_khz":  round(self.bandwidth_khz, 0)  if self.bandwidth_khz  is not None else None,
            "protocol":       self.protocol,
            "threat_level":   self.threat_level,
            "threat_score":   self.threat_score,
            "simulated":      self.simulated,
            "session_id":     self.session_id,
        }


class SignalDB:
    """
    Thread-safe SQLite wrapper.
    One writer thread drains a queue; reads open a fresh connection each time.
    """

    def __init__(self, db_path: str = "/home/chaostech-26/nsd-v19/data/signals.db"):
        self._db_path   = db_path
        self._session   = str(uuid.uuid4())[:8]
        self._queue: queue.Queue = queue.Queue(maxsize=1000)
        self._stop      = threading.Event()
        self._writer    = threading.Thread(target=self._writer_loop,
                                           name="nsd-db-writer", daemon=True)
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self._init_schema()
        self._writer.start()
        logger.info(f"SignalDB ready: {db_path} | session={self._session}")

    def _init_schema(self) -> None:
        conn = sqlite3.connect(self._db_path, timeout=10)
        try:
            conn.executescript(_DDL)
            conn.commit()
        finally:
            conn.close()

    def _writer_loop(self) -> None:
        conn = sqlite3.connect(self._db_path, timeout=10)
        conn.execute("PRAGMA journal_mode=WAL")
        try:
            while not self._stop.is_set():
                try:
                    row = self._queue.get(timeout=0.5)
                except queue.Empty:
                    continue
                try:
                    conn.execute(_INSERT_SQL, row)
                    conn.commit()
                except sqlite3.Error as e:
                    logger.error(f"DB write error: {e}")
                finally:
                    self._queue.task_done()
        finally:
            conn.close()

    def log_detection(self,
                      band:           str,
                      freq_mhz:       float,
                      power_db:       Optional[float],
                      noise_floor_db: Optional[float],
                      snr_db:         Optional[float],
                      bandwidth_khz:  Optional[float],
                      protocol:       Optional[str],
                      threat_level:   Optional[str],
                      threat_score:   Optional[int],
                      simulated:      bool = False) -> None:
        row = (
            time.time(), band, freq_mhz, power_db, noise_floor_db,
            snr_db, bandwidth_khz, protocol, threat_level, threat_score,
            1 if simulated else 0, self._session,
        )
        try:
            self._queue.put_nowait(row)
        except queue.Full:
            logger.warning("DB write queue full — detection dropped.")

    def get_recent(self, limit: int = 100,
                   real_only: bool = False) -> List[DetectionRecord]:
        conn = sqlite3.connect(self._db_path, timeout=5)
        conn.row_factory = sqlite3.Row
        try:
            where = "WHERE simulated = 0" if real_only else ""
            rows  = conn.execute(
                f"SELECT * FROM detections {where} "
                f"ORDER BY timestamp_utc DESC LIMIT ?", (limit,)
            ).fetchall()
            return [self._row_to_record(r) for r in rows]
        finally:
            conn.close()

    def get_stats(self) -> dict:
        conn = sqlite3.connect(self._db_path, timeout=5)
        try:
            total    = conn.execute("SELECT COUNT(*) FROM detections").fetchone()[0]
            session  = conn.execute(
                "SELECT COUNT(*) FROM detections WHERE session_id=?",
                (self._session,)).fetchone()[0]
            real     = conn.execute(
                "SELECT COUNT(*) FROM detections WHERE simulated=0").fetchone()[0]
            by_band  = conn.execute(
                "SELECT band, COUNT(*) as cnt FROM detections "
                "GROUP BY band ORDER BY cnt DESC").fetchall()
            by_level = conn.execute(
                "SELECT threat_level, COUNT(*) as cnt FROM detections "
                "WHERE threat_level IS NOT NULL "
                "GROUP BY threat_level ORDER BY cnt DESC").fetchall()
            oldest   = conn.execute(
                "SELECT MIN(timestamp_utc) FROM detections").fetchone()[0]
            return {
                "total_all_time":      total,
                "total_this_session":  session,
                "total_real":          real,
                "by_band":             {r[0]: r[1] for r in by_band},
                "by_threat_level":     {r[0]: r[1] for r in by_level},
                "oldest_timestamp":    oldest,
                "session_id":          self._session,
            }
        finally:
            conn.close()

    def export_csv(self, limit: int = 5000, real_only: bool = False) -> str:
        records = self.get_recent(limit=limit, real_only=real_only)
        buf = io.StringIO()
        fieldnames = [
            "id", "timestamp_iso", "band", "freq_mhz",
            "power_db", "noise_floor_db", "snr_db", "bandwidth_khz",
            "protocol", "threat_level", "threat_score", "simulated", "session_id"
        ]
        writer = csv.DictWriter(buf, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for r in records:
            writer.writerow(r.to_dict())
        return buf.getvalue()

    def stop(self) -> None:
        self._stop.set()
        self._writer.join(timeout=5)
        logger.info("SignalDB stopped.")

    @staticmethod
    def _row_to_record(row: sqlite3.Row) -> DetectionRecord:
        return DetectionRecord(
            id=row["id"],
            timestamp_utc=row["timestamp_utc"],
            band=row["band"],
            freq_mhz=row["freq_mhz"],
            power_db=row["power_db"],
            noise_floor_db=row["noise_floor_db"],
            snr_db=row["snr_db"],
            bandwidth_khz=row["bandwidth_khz"],
            protocol=row["protocol"],
            threat_level=row["threat_level"],
            threat_score=row["threat_score"],
            simulated=bool(row["simulated"]),
            session_id=row["session_id"],
        )
