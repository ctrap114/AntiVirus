#!/usr/bin/env python3
"""
Simple Cuckoo submission example for EverbloomSecurity.

Usage: python tools/cuckoo_submit.py /path/to/suspicious.exe

This script demonstrates:
- submitting a file to Cuckoo via HTTP API
- storing a mapping from local scan id to cuckoo task id in a small sqlite DB
- polling for report completion (simple loop)
"""

import sys
import time
import requests
import sqlite3
from pathlib import Path

CUCKOO_URL = "http://127.0.0.1:8000"
API_KEY = "your_cuckoo_api_key"
DB_PATH = "tools/cuckoo_tasks.db"


def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("CREATE TABLE IF NOT EXISTS tasks(scan_id TEXT PRIMARY KEY, task_id INTEGER, status TEXT)")
    conn.commit()
    return conn


def submit_sample(path: Path, scan_id: str):
    url = f"{CUCKOO_URL}/tasks/create/file"
    headers = {"Authorization": f"Bearer {API_KEY}"}
    with path.open("rb") as fh:
        files = {"file": (path.name, fh)}
        r = requests.post(url, files=files, headers=headers)
        r.raise_for_status()
        payload = r.json()
        task_id = payload.get("task_id") or payload.get("task", {}).get("id")
        return int(task_id)


def poll_report(task_id: int, timeout=600):
    url = f"{CUCKOO_URL}/tasks/view/{task_id}"
    headers = {"Authorization": f"Bearer {API_KEY}"}
    start = time.time()
    while time.time() - start < timeout:
        r = requests.get(url, headers=headers)
        r.raise_for_status()
        payload = r.json()
        # payload structure depends on Cuckoo version; look for 'task' and 'status'
        status = payload.get("task", {}).get("status") or payload.get("task", {}).get("state")
        if status in ("reported", "completed"):
            return True, payload
        time.sleep(5)
    return False, None


def main():
    if len(sys.argv) < 2:
        print("Usage: cuckoo_submit.py /path/to/sample")
        return
    path = Path(sys.argv[1])
    if not path.exists():
        print("File not found")
        return

    conn = init_db()
    scan_id = f"scan-{int(time.time())}"
    try:
        task_id = submit_sample(path, scan_id)
        conn.execute("INSERT OR REPLACE INTO tasks(scan_id, task_id, status) VALUES (?, ?, ?)", (scan_id, task_id, "pending"))
        conn.commit()
        print(f"Submitted {path} as task {task_id}")
        ok, report = poll_report(task_id)
        if ok:
            conn.execute("UPDATE tasks SET status = ? WHERE scan_id = ?", ("completed", scan_id))
            conn.commit()
            print("Report available:")
            print(report)
        else:
            print("Report not ready within timeout")
    except Exception as e:
        print("Submission failed:", e)
    finally:
        conn.close()


if __name__ == "__main__":
    main()
