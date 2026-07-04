"""
SysGuard AI — Metrics Store
SQLite-based historical data engine.
Saves snapshots, serves trends, predicts disk full date.
"""

import sqlite3
import json
import threading
import time
from datetime import datetime, timedelta
from pathlib import Path


DB_PATH = Path(__file__).parent / "metrics.db"


class MetricsStore:
    """
    Thread-safe SQLite store for system metrics.
    Two tables:
      - snapshots     : full JSON snapshot (for deep queries)
      - metrics_summary : denormalized key values (for fast trend queries)
    """

    def __init__(self, db_path=None):
        self.db_path = str(db_path or DB_PATH)
        self._lock = threading.Lock()
        self._init_db()

    def _connect(self):
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self):
        with self._lock:
            conn = self._connect()
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS snapshots (
                    id        INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT    NOT NULL,
                    data      TEXT    NOT NULL
                );

                CREATE TABLE IF NOT EXISTS metrics_summary (
                    id            INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp     TEXT    NOT NULL,
                    cpu_percent   REAL,
                    ram_percent   REAL,
                    ram_used_gb   REAL,
                    disk_percent  REAL,
                    disk_used_gb  REAL,
                    swap_percent  REAL,
                    process_count INTEGER,
                    zombie_count  INTEGER,
                    health_score  INTEGER
                );

                CREATE INDEX IF NOT EXISTS idx_summary_ts
                    ON metrics_summary(timestamp);

                CREATE INDEX IF NOT EXISTS idx_snapshots_ts
                    ON snapshots(timestamp);
            """)
            conn.commit()
            conn.close()

    # ─── WRITE ───────────────────────────────────────────────────────────────

    def save_snapshot(self, snapshot: dict, health_score: int = 0):
        """
        Save a full snapshot + extract key metrics into summary table.
        Call this every 30-60 seconds from the Streamlit app.
        """
        ts = datetime.now().isoformat()

        cpu_pct   = snapshot.get("cpu", {}).get("percent", 0)
        ram       = snapshot.get("ram", {})
        ram_pct   = ram.get("percent", 0)
        ram_gb    = ram.get("used_gb", 0)
        swap_pct  = ram.get("swap_percent", 0)

        disk      = snapshot.get("disk", [{}])
        root      = next((d for d in disk if d.get("mountpoint") == "/"),
                         disk[0] if disk else {})
        disk_pct  = root.get("percent", 0)
        disk_gb   = root.get("used_gb", 0)

        procs     = snapshot.get("processes", {})
        proc_cnt  = procs.get("total_count", 0)
        zombie    = procs.get("total_zombie", 0)

        with self._lock:
            conn = self._connect()
            conn.execute(
                "INSERT INTO snapshots (timestamp, data) VALUES (?, ?)",
                (ts, json.dumps(snapshot))
            )
            conn.execute("""
                INSERT INTO metrics_summary
                    (timestamp, cpu_percent, ram_percent, ram_used_gb,
                     disk_percent, disk_used_gb, swap_percent,
                     process_count, zombie_count, health_score)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (ts, cpu_pct, ram_pct, ram_gb,
                  disk_pct, disk_gb, swap_pct,
                  proc_cnt, zombie, health_score))
            conn.commit()
            conn.close()

    # ─── READ ────────────────────────────────────────────────────────────────

    def get_trend(self, metric: str, hours: int = 24) -> dict:
        """
        Returns time-series data for a single metric.
        metric: 'cpu_percent' | 'ram_percent' | 'disk_percent' |
                'swap_percent' | 'health_score'
        Returns: {"timestamps": [...], "values": [...]}
        """
        valid = {"cpu_percent", "ram_percent", "disk_percent",
                 "swap_percent", "health_score", "zombie_count"}
        if metric not in valid:
            return {"timestamps": [], "values": []}

        since = (datetime.now() - timedelta(hours=hours)).isoformat()

        with self._lock:
            conn = self._connect()
            rows = conn.execute(f"""
                SELECT timestamp, {metric}
                FROM metrics_summary
                WHERE timestamp > ?
                ORDER BY timestamp ASC
            """, (since,)).fetchall()
            conn.close()

        timestamps = [r["timestamp"] for r in rows]
        values     = [r[metric] for r in rows]
        return {"timestamps": timestamps, "values": values}

    def get_latest(self, n: int = 1) -> list:
        """Return the n most recent summary rows"""
        with self._lock:
            conn = self._connect()
            rows = conn.execute("""
                SELECT * FROM metrics_summary
                ORDER BY timestamp DESC
                LIMIT ?
            """, (n,)).fetchall()
            conn.close()
        return [dict(r) for r in rows]

    def get_stats(self, hours: int = 24) -> dict:
        """
        Min / max / avg for key metrics over the last N hours.
        Useful for showing 'today you peaked at X'.
        """
        since = (datetime.now() - timedelta(hours=hours)).isoformat()
        with self._lock:
            conn = self._connect()
            row = conn.execute("""
                SELECT
                    COUNT(*)           AS samples,
                    ROUND(AVG(cpu_percent), 1)  AS cpu_avg,
                    ROUND(MAX(cpu_percent), 1)  AS cpu_max,
                    ROUND(AVG(ram_percent), 1)  AS ram_avg,
                    ROUND(MAX(ram_percent), 1)  AS ram_max,
                    ROUND(AVG(disk_percent), 1) AS disk_avg,
                    ROUND(MAX(disk_percent), 1) AS disk_max,
                    ROUND(AVG(health_score), 0) AS score_avg,
                    ROUND(MIN(health_score), 0) AS score_min,
                    SUM(zombie_count)           AS zombie_total
                FROM metrics_summary
                WHERE timestamp > ?
            """, (since,)).fetchone()
            conn.close()
        return dict(row) if row else {}

    # ─── PREDICTION ──────────────────────────────────────────────────────────

    def predict_disk_full(self) -> dict:
        """
        Linear regression on disk usage over last 7 days.
        Returns days until full, growth rate, confidence.
        """
        result = {
            "available": False,
            "days_until_full": None,
            "growth_gb_per_day": 0,
            "current_percent": 0,
            "confidence": "low",
            "message": ""
        }

        trend = self.get_trend("disk_percent", hours=168)  # 7 days
        if len(trend["values"]) < 10:
            result["message"] = "Not enough data yet. Needs ~10 samples (5+ minutes)."
            return result

        timestamps = trend["timestamps"]
        values     = trend["values"]

        # Convert timestamps to hours since first reading
        t0 = datetime.fromisoformat(timestamps[0])
        x  = [(datetime.fromisoformat(ts) - t0).total_seconds() / 3600
              for ts in timestamps]
        y  = values

        # Simple linear regression
        n    = len(x)
        x_m  = sum(x) / n
        y_m  = sum(y) / n
        num  = sum((xi - x_m) * (yi - y_m) for xi, yi in zip(x, y))
        den  = sum((xi - x_m) ** 2 for xi in x)

        if den == 0:
            result["message"] = "Disk usage is perfectly stable — no growth detected."
            result["available"] = True
            result["current_percent"] = round(y_m, 1)
            return result

        slope_per_hour = num / den   # % per hour
        slope_per_day  = slope_per_hour * 24

        current = values[-1]
        result["current_percent"] = round(current, 1)
        result["available"] = True

        if slope_per_hour <= 0:
            result["message"] = "Disk usage is stable or decreasing. No concern."
            result["growth_gb_per_day"] = 0
            return result

        hours_to_full = (100 - current) / slope_per_hour
        days_to_full  = hours_to_full / 24

        result["days_until_full"]    = round(days_to_full, 1)
        result["growth_gb_per_day"]  = round(slope_per_day, 2)
        result["confidence"]         = ("high" if n > 100
                                        else "medium" if n > 30
                                        else "low")

        if days_to_full < 7:
            result["message"] = (f"⚠️ Disk full in ~{days_to_full:.0f} days "
                                 f"at current growth rate.")
        elif days_to_full < 30:
            result["message"] = (f"Disk growing at {slope_per_day:.2f}%/day. "
                                 f"Full in ~{days_to_full:.0f} days.")
        else:
            result["message"] = (f"Disk growth is slow. "
                                 f"At current rate, full in ~{days_to_full:.0f} days.")

        return result

    # ─── ANOMALY ─────────────────────────────────────────────────────────────

    def detect_anomalies(self, metric: str = "ram_percent",
                          hours: int = 2) -> dict:
        """
        Z-score anomaly detection over the last N hours.
        Compares recent values against the 24h baseline.
        """
        baseline = self.get_trend(metric, hours=24)
        recent   = self.get_trend(metric, hours=hours)

        result = {
            "metric": metric,
            "anomaly_detected": False,
            "current_value": 0,
            "baseline_avg": 0,
            "z_score": 0,
            "message": ""
        }

        if len(baseline["values"]) < 10 or not recent["values"]:
            result["message"] = "Not enough baseline data yet."
            return result

        import math
        vals   = baseline["values"]
        mean   = sum(vals) / len(vals)
        std    = math.sqrt(sum((v - mean) ** 2 for v in vals) / len(vals))
        current = recent["values"][-1]

        result["current_value"] = round(current, 1)
        result["baseline_avg"]  = round(mean, 1)

        if std == 0:
            result["message"] = f"{metric} is perfectly stable."
            return result

        z = abs(current - mean) / std
        result["z_score"] = round(z, 2)

        if z > 3.0:
            result["anomaly_detected"] = True
            result["message"] = (f"🔴 Strong anomaly: {metric} is {current:.1f}% "
                                 f"(baseline avg {mean:.1f}%, z={z:.1f})")
        elif z > 2.0:
            result["anomaly_detected"] = True
            result["message"] = (f"🟡 Anomaly detected: {metric} is {current:.1f}% "
                                 f"(baseline avg {mean:.1f}%, z={z:.1f})")
        else:
            result["message"] = (f"🟢 {metric} normal: {current:.1f}% "
                                 f"(baseline avg {mean:.1f}%)")

        return result

    # ─── MAINTENANCE ─────────────────────────────────────────────────────────

    def cleanup_old_data(self, keep_days: int = 7):
        """Delete records older than keep_days. Call weekly."""
        cutoff = (datetime.now() - timedelta(days=keep_days)).isoformat()
        with self._lock:
            conn = self._connect()
            conn.execute("DELETE FROM snapshots WHERE timestamp < ?", (cutoff,))
            conn.execute("DELETE FROM metrics_summary WHERE timestamp < ?", (cutoff,))
            conn.commit()
            conn.close()

    def get_db_size(self) -> str:
        """Return human-readable DB file size"""
        path = Path(self.db_path)
        if path.exists():
            size = path.stat().st_size
            if size < 1024:
                return f"{size} B"
            elif size < 1024 * 1024:
                return f"{size/1024:.1f} KB"
            else:
                return f"{size/1024/1024:.1f} MB"
        return "0 B"

    def get_record_count(self) -> int:
        with self._lock:
            conn = self._connect()
            count = conn.execute(
                "SELECT COUNT(*) FROM metrics_summary"
            ).fetchone()[0]
            conn.close()
        return count


# ─── Background Saver ────────────────────────────────────────────────────────

class BackgroundSaver:
    """
    Runs in a daemon thread.
    Saves a snapshot every `interval` seconds.
    Usage:
        saver = BackgroundSaver(store, snapshot_fn, interval=30)
        saver.start()
    """

    def __init__(self, store: MetricsStore, snapshot_fn,
                 health_fn=None, interval: int = 30):
        self.store       = store
        self.snapshot_fn = snapshot_fn
        self.health_fn   = health_fn
        self.interval    = interval
        self._thread     = None
        self._running    = False

    def start(self):
        if self._running:
            return
        self._running = True
        self._thread  = threading.Thread(
            target=self._loop, daemon=True, name="SysGuardSaver"
        )
        self._thread.start()

    def stop(self):
        self._running = False

    def _loop(self):
        while self._running:
            try:
                snap  = self.snapshot_fn()
                score = self.health_fn(snap) if self.health_fn else 0
                self.store.save_snapshot(snap, health_score=score)
            except Exception:
                pass
            time.sleep(self.interval)
