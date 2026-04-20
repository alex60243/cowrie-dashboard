import json
import os
import glob
from datetime import datetime
from collections import defaultdict
from flask import Flask, jsonify, render_template, abort

app = Flask(__name__)

LOGS_DIR = os.environ.get("LOGS_DIR", "/logs")


def parse_logs():
    """Parse all Cowrie JSON log files and return structured session data."""
    sessions = {}
    events = []

    log_pattern = os.path.join(LOGS_DIR, "cowrie.json*")
    log_files = sorted(glob.glob(log_pattern))

    for log_file in log_files:
        try:
            with open(log_file, "r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        event = json.loads(line)
                        events.append(event)
                    except json.JSONDecodeError:
                        continue
        except OSError:
            continue

    # Build sessions from events
    for event in events:
        session_id = event.get("session")
        if not session_id:
            continue

        ev_type = event.get("eventid", "")
        timestamp = event.get("timestamp", "")
        src_ip = event.get("src_ip", "unknown")

        if session_id not in sessions:
            sessions[session_id] = {
                "id": session_id,
                "src_ip": src_ip,
                "username": "",
                "password": "",
                "start_time": timestamp,
                "end_time": timestamp,
                "commands": [],
                "login_success": False,
                "login_attempts": [],
                "files_downloaded": [],
                "duration": 0,
            }

        sess = sessions[session_id]

        # Update end time
        if timestamp > sess["end_time"]:
            sess["end_time"] = timestamp

        if ev_type == "cowrie.login.success":
            sess["username"] = event.get("username", "")
            sess["password"] = event.get("password", "")
            sess["login_success"] = True
            sess["login_attempts"].append(
                {
                    "username": event.get("username", ""),
                    "password": event.get("password", ""),
                    "success": True,
                    "time": timestamp,
                }
            )

        elif ev_type == "cowrie.login.failed":
            sess["login_attempts"].append(
                {
                    "username": event.get("username", ""),
                    "password": event.get("password", ""),
                    "success": False,
                    "time": timestamp,
                }
            )
            # Set primary creds from first failed attempt if no success
            if not sess["username"]:
                sess["username"] = event.get("username", "")
                sess["password"] = event.get("password", "")

        elif ev_type in ("cowrie.command.input", "cowrie.command.failed"):
            sess["commands"].append(
                {
                    "command": event.get("input", ""),
                    "time": timestamp,
                    "success": ev_type == "cowrie.command.input",
                }
            )

        elif ev_type in ("cowrie.session.file_download", "cowrie.session.file_upload"):
            sess["files_downloaded"].append(
                {
                    "url": event.get("url", event.get("filename", "")),
                    "shasum": event.get("shasum", ""),
                    "time": timestamp,
                }
            )

    # Calculate duration for each session
    for sess in sessions.values():
        try:
            fmt = "%Y-%m-%dT%H:%M:%S.%f%z"
            start = datetime.fromisoformat(sess["start_time"])
            end = datetime.fromisoformat(sess["end_time"])
            sess["duration"] = int((end - start).total_seconds())
        except Exception:
            sess["duration"] = 0

    return list(sessions.values())


def compute_stats(sessions):
    unique_ips = set(s["src_ip"] for s in sessions)
    total_commands = sum(len(s["commands"]) for s in sessions)
    logins_success = sum(1 for s in sessions if s["login_success"])

    username_count = defaultdict(int)
    password_count = defaultdict(int)
    ip_count = defaultdict(int)

    for sess in sessions:
        for attempt in sess["login_attempts"]:
            if attempt["username"]:
                username_count[attempt["username"]] += 1
            if attempt["password"]:
                password_count[attempt["password"]] += 1
        ip_count[sess["src_ip"]] += 1

    top_usernames = sorted(username_count.items(), key=lambda x: x[1], reverse=True)[:10]
    top_passwords = sorted(password_count.items(), key=lambda x: x[1], reverse=True)[:10]
    top_ips = sorted(ip_count.items(), key=lambda x: x[1], reverse=True)[:10]

    return {
        "total_sessions": len(sessions),
        "unique_ips": len(unique_ips),
        "total_commands": total_commands,
        "successful_logins": logins_success,
        "top_usernames": [{"value": k, "count": v} for k, v in top_usernames],
        "top_passwords": [{"value": k, "count": v} for k, v in top_passwords],
        "top_ips": [{"value": k, "count": v} for k, v in top_ips],
    }


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/sessions")
def api_sessions():
    sessions = parse_logs()
    # Return summary (no commands detail for list view)
    summary = []
    for s in sessions:
        summary.append(
            {
                "id": s["id"],
                "src_ip": s["src_ip"],
                "username": s["username"],
                "password": s["password"],
                "start_time": s["start_time"],
                "end_time": s["end_time"],
                "duration": s["duration"],
                "num_commands": len(s["commands"]),
                "num_attempts": len(s["login_attempts"]),
                "login_success": s["login_success"],
                "files_downloaded": len(s["files_downloaded"]),
            }
        )
    summary.sort(key=lambda x: x["start_time"], reverse=True)
    return jsonify(summary)


@app.route("/api/sessions/<session_id>")
def api_session_detail(session_id):
    sessions = parse_logs()
    for sess in sessions:
        if sess["id"] == session_id:
            return jsonify(sess)
    abort(404)


@app.route("/api/stats")
def api_stats():
    sessions = parse_logs()
    return jsonify(compute_stats(sessions))


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
