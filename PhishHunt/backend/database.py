import sqlite3
import os
import json
from datetime import datetime

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATABASE_PATH = os.path.join(BASE_DIR, "phishhunt.db")


def init_database():
    conn = sqlite3.connect(DATABASE_PATH)

    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scan_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT NOT NULL,
            final_result TEXT NOT NULL,
            ml_prediction TEXT,
            ml_confidence REAL,
            risk_score INTEGER,
            security_decision TEXT,
            security_indicators TEXT,
            timestamp TEXT NOT NULL
        )
    """)

    conn.commit()
    conn.close()


def save_scan(
    url,
    final_result,
    ml_prediction,
    ml_confidence,
    risk_score,
    security_decision,
    security_indicators
):
    conn = sqlite3.connect(DATABASE_PATH)

    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO scan_history (
            url,
            final_result,
            ml_prediction,
            ml_confidence,
            risk_score,
            security_decision,
            security_indicators,
            timestamp
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        url,
        final_result,
        ml_prediction,
        ml_confidence,
        risk_score,
        security_decision,
        json.dumps(security_indicators),
        datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    ))

    conn.commit()
    conn.close()


def get_history():
    conn = sqlite3.connect(DATABASE_PATH)

    conn.row_factory = sqlite3.Row

    cursor = conn.cursor()

    cursor.execute("""
        SELECT *
        FROM scan_history
        ORDER BY id DESC
    """)

    rows = cursor.fetchall()

    conn.close()

    history = []

    for row in rows:
        item = dict(row)

        try:
            item["security_indicators"] = json.loads(
                item["security_indicators"]
            )
        except:
            item["security_indicators"] = []

        history.append(item)

    return history