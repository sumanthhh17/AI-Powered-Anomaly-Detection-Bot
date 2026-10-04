import json
import sqlite3
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from .config import DB_PATH


def utc_now():
    return datetime.now(timezone.utc).isoformat(timespec='milliseconds')


class EventStore:
    def __init__(self, path=DB_PATH):
        self.path = path
        path.parent.mkdir(parents=True, exist_ok=True)
        with self.connect() as db:
            db.executescript('''
                PRAGMA journal_mode=WAL;
                CREATE TABLE IF NOT EXISTS sessions (
                    id TEXT PRIMARY KEY, mode TEXT NOT NULL, status TEXT NOT NULL,
                    started_at TEXT NOT NULL, ended_at TEXT, error TEXT);
                CREATE TABLE IF NOT EXISTS events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT, session_id TEXT NOT NULL,
                    observed_at TEXT NOT NULL, flow_started_at TEXT,
                    source_ip TEXT, destination_ip TEXT, source_port INTEGER,
                    destination_port INTEGER, protocol TEXT, dataset_label TEXT,
                    score REAL NOT NULL, anomaly INTEGER NOT NULL, reason TEXT,
                    inference_ms REAL NOT NULL, features TEXT NOT NULL,
                    FOREIGN KEY(session_id) REFERENCES sessions(id));
                CREATE INDEX IF NOT EXISTS events_session ON events(session_id, id);
                CREATE INDEX IF NOT EXISTS events_time ON events(session_id, observed_at);
            ''')

    @contextmanager
    def connect(self):
        db = sqlite3.connect(self.path, timeout=15)
        db.row_factory = sqlite3.Row
        db.execute('PRAGMA foreign_keys=ON')
        try:
            yield db
            db.commit()
        except Exception:
            db.rollback()
            raise
        finally:
            db.close()

    def create_session(self, mode, status='running'):
        sid = uuid.uuid4().hex
        with self.connect() as db:
            db.execute('INSERT INTO sessions(id,mode,status,started_at) VALUES (?,?,?,?)',
                       (sid, mode, status, utc_now()))
        return sid

    def set_status(self, sid, status, error=None):
        ended = utc_now() if status in ['completed', 'stopped', 'error'] else None
        with self.connect() as db:
            db.execute('UPDATE sessions SET status=?, ended_at=?, error=? WHERE id=?',
                       (status, ended, error, sid))

    def add(self, sid, records):
        now = utc_now()
        rows = [(sid, r.get('observed_at', now), r.get('flow_started_at'), r.get('source_ip'),
                 r.get('destination_ip'), r.get('source_port'), r.get('destination_port'),
                 r.get('protocol'), r.get('dataset_label'), r['score'], int(r['anomaly']),
                 r['reason'], r['inference_ms'], json.dumps(r['features'])) for r in records]
        with self.connect() as db:
            db.executemany('''INSERT INTO events(session_id,observed_at,flow_started_at,source_ip,
                              destination_ip,source_port,destination_port,protocol,dataset_label,
                              score,anomaly,reason,inference_ms,features)
                              VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)''', rows)

    def sessions(self):
        with self.connect() as db:
            return [dict(row) for row in db.execute('SELECT * FROM sessions ORDER BY started_at DESC, rowid DESC LIMIT 50')]

    def snapshot(self, sid=None, limit=300):
        with self.connect() as db:
            db.execute('BEGIN')
            session = db.execute('SELECT * FROM sessions WHERE id=?', (sid,)).fetchone() if sid else db.execute(
                'SELECT * FROM sessions ORDER BY started_at DESC, rowid DESC LIMIT 1').fetchone()
            if session is None:
                return dict(session=None, total=0, flagged=0, average_ms=0, events=[], timeline=[], sources=[], labels=0,
                            true_positive=0, false_positive=0, false_negative=0, true_negative=0)
            sid = session['id']
            stats = dict(db.execute('''SELECT COUNT(*) AS total, COALESCE(SUM(anomaly),0) AS flagged,
                         COALESCE(AVG(inference_ms),0) AS average_ms,
                         SUM(CASE WHEN dataset_label IS NOT NULL THEN 1 ELSE 0 END) AS labels,
                         SUM(CASE WHEN dataset_label IS NOT NULL AND upper(dataset_label)!='BENIGN' AND anomaly=1 THEN 1 ELSE 0 END) AS true_positive,
                         SUM(CASE WHEN upper(dataset_label)='BENIGN' AND anomaly=1 THEN 1 ELSE 0 END) AS false_positive,
                         SUM(CASE WHEN dataset_label IS NOT NULL AND upper(dataset_label)!='BENIGN' AND anomaly=0 THEN 1 ELSE 0 END) AS false_negative,
                         SUM(CASE WHEN upper(dataset_label)='BENIGN' AND anomaly=0 THEN 1 ELSE 0 END) AS true_negative
                         FROM events WHERE session_id=?''', (sid,)).fetchone())
            rows = [dict(r) for r in db.execute('SELECT * FROM events WHERE session_id=? ORDER BY id DESC LIMIT ?', (sid, limit))]
            for row in rows:
                row['features'] = json.loads(row['features'])
            timeline = [dict(r) for r in db.execute('''SELECT substr(observed_at,1,19) AS time, COUNT(*) AS total,
                         SUM(anomaly) AS flagged FROM events WHERE session_id=?
                         GROUP BY substr(observed_at,1,19) ORDER BY time DESC LIMIT 120''', (sid,))][::-1]
            sources = [dict(r) for r in db.execute('''SELECT source_ip, COUNT(*) AS flagged FROM events
                       WHERE session_id=? AND anomaly=1 AND source_ip IS NOT NULL GROUP BY source_ip
                       ORDER BY flagged DESC LIMIT 5''', (sid,))]
            return dict(session=dict(session), events=rows, timeline=timeline, sources=sources,
                        **{k: (v or 0) for k, v in stats.items()})

    def export(self, sid):
        with self.connect() as db:
            return [dict(r) for r in db.execute('SELECT * FROM events WHERE session_id=? ORDER BY id', (sid,))]
