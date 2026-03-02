# nsd_db.py — ChaosTech NSD SQLite persistence layer
import sqlite3, time, os

DB_PATH = os.path.join(os.path.dirname(__file__), 'nsd_data.db')

def get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with get_conn() as conn:
        conn.executescript('''
            CREATE TABLE IF NOT EXISTS scans (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                ts           REAL,
                band         TEXT,
                threat_count INTEGER,
                noise_floor  REAL,
                status       TEXT
            );
            CREATE TABLE IF NOT EXISTS threats (
                id         INTEGER PRIMARY KEY,
                freq_mhz   REAL,
                first_seen REAL,
                last_seen  REAL,
                band       TEXT,
                type       TEXT,
                peak_power REAL
            );
            CREATE TABLE IF NOT EXISTS system_events (
                id     INTEGER PRIMARY KEY AUTOINCREMENT,
                ts     REAL,
                event  TEXT,
                detail TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_scans_ts   ON scans(ts);
            CREATE INDEX IF NOT EXISTS idx_threats_ts ON threats(last_seen);
        ''')
    print(f"[DB] Initialized at {DB_PATH}")

def save_scan(band, threat_count, noise_floor, status):
    try:
        with get_conn() as conn:
            conn.execute(
                'INSERT INTO scans (ts, band, threat_count, noise_floor, status) VALUES (?,?,?,?,?)',
                (time.time(), band, threat_count, noise_floor, status)
            )
    except Exception as e:
        print(f"[DB] save_scan error: {e}")

def upsert_threat(threat_id, freq_mhz, band, t_type, power_db, first_seen):
    try:
        with get_conn() as conn:
            conn.execute('''
                INSERT INTO threats (id, freq_mhz, first_seen, last_seen, band, type, peak_power)
                VALUES (?,?,?,?,?,?,?)
                ON CONFLICT(id) DO UPDATE SET
                    last_seen  = excluded.last_seen,
                    peak_power = MAX(peak_power, excluded.peak_power)
            ''', (threat_id, freq_mhz, first_seen, time.time(), band, t_type, power_db))
    except Exception as e:
        print(f"[DB] upsert_threat error: {e}")

def load_max_threat_id():
    """Restore _next_threat_id after restart so IDs never reset to 1."""
    try:
        with get_conn() as conn:
            row = conn.execute('SELECT MAX(id) FROM threats').fetchone()
            return (row[0] or 0) + 1
    except:
        return 1

def log_event(event, detail=''):
    try:
        with get_conn() as conn:
            conn.execute(
                'INSERT INTO system_events (ts, event, detail) VALUES (?,?,?)',
                (time.time(), event, detail)
            )
    except Exception as e:
        print(f"[DB] log_event error: {e}")

def get_scan_history(n=50):
    try:
        with get_conn() as conn:
            rows = conn.execute(
                'SELECT ts, band, threat_count, noise_floor, status FROM scans ORDER BY ts DESC LIMIT ?', (n,)
            ).fetchall()
            return [dict(r) for r in rows]
    except:
        return []

def get_threat_history(n=100):
    try:
        with get_conn() as conn:
            rows = conn.execute(
                'SELECT * FROM threats ORDER BY last_seen DESC LIMIT ?', (n,)
            ).fetchall()
            return [dict(r) for r in rows]
    except:
        return []
