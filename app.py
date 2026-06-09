"""PayPal BA 链提取网站 —— Flask 后端"""
from __future__ import annotations

import json
import os
import queue
import sys
import threading
import time
import uuid
from datetime import datetime

from flask import Flask, Response, jsonify, render_template, request, stream_with_context

from extractor import PayPalChainExtractor, load_config

app = Flask(__name__)
cfg = load_config()

# ─── 全局状态 ───
jobs: dict[str, dict] = {}
stats = {
    "visitors": 0,
    "pplink_success": 0,
    "signup_success": 0,
    "active_jobs": 0,
    "start_time": time.time(),
    "sale_sms_in_use": 0,
    "sale_sms_capacity": 22,
    "sale_sms_waiting": 0,
}


class JobManager:
    def __init__(self, job_id: str):
        self.job_id = job_id
        self.queue: queue.Queue[dict] = queue.Queue()
        self.result: dict | None = None
        self.otp_needed = threading.Event()
        self.otp_value: str | None = None

    def emit(self, event_type: str, data: dict | None = None):
        d = dict(data or {})
        d["type"] = event_type
        self.queue.put(d)

    def log_msg(self, level: str, msg: str):
        self.emit("log", {"msg": msg, "level": level})


@app.route("/")
def index():
    stats["visitors"] += 1
    return render_template("index.html")


@app.route("/api/config")
def api_config():
    return jsonify({"auth_required": False, "redact": False})


@app.route("/api/stats")
def api_stats():
    return jsonify({
        "visitors": stats["visitors"],
        "pplink_success": stats["pplink_success"],
        "signup_success": stats["signup_success"],
        "active_jobs": stats["active_jobs"],
        "uptime_sec": int(time.time() - stats["start_time"]),
        "sale_sms_in_use": stats["sale_sms_in_use"],
        "sale_sms_capacity": stats["sale_sms_capacity"],
        "sale_sms_waiting": stats["sale_sms_waiting"],
    })


@app.route("/api/check-proxy", methods=["POST"])
def check_proxy():
    data = request.get_json(force=True) or {}
    proxy_url = str(data.get("proxy", "")).strip()
    if not proxy_url:
        return jsonify({"ok": False, "error": "代理为空"}), 400
    try:
        from curl_cffi import requests as cr
        s = cr.Session(impersonate="chrome131")
        s.proxies = {"http": proxy_url, "https": proxy_url}
        t0 = time.time()
        resp = s.get("https://httpbin.org/ip", timeout=15)
        latency = int((time.time() - t0) * 1000)
        ip_data = resp.json() if resp.status_code == 200 else {}
        origin = ip_data.get("origin", "").split(",")[0].strip()
        s.close()
        return jsonify({"ok": True, "ip": origin, "latency_ms": latency, "country": "?", "city": "?", "org": ""})
    except Exception as e:
        return jsonify({"ok": False, "error": f"{type(e).__name__}: {e}"})


@app.route("/api/jobs", methods=["POST"])
def create_job():
    data = request.get_json(force=True) or {}
    access_token = str(data.get("input", "")).strip()
    jp_proxy = str(data.get("proxy_jp", cfg.get("jp_proxy", ""))).strip() or None
    us_proxy = str(data.get("proxy", cfg.get("us_proxy", ""))).strip() or None

    if not access_token:
        return jsonify({"detail": "请输入 ChatGPT access_token 或 JWT"}), 400

    job_id = uuid.uuid4().hex[:12]
    mgr = JobManager(job_id)
    jobs[job_id] = {"manager": mgr, "thread": None, "status": "running"}

    stats["active_jobs"] = sum(1 for j in jobs.values() if j["status"] == "running")

    def run_job():
        def log_cb(level: str, msg: str):
            mgr.log_msg(level, msg)

        extractor = PayPalChainExtractor(log_cb, jp_proxy=jp_proxy, us_proxy=us_proxy)
        result = extractor.run(access_token)
        mgr.result = result
        mgr.emit("result", {"result": result})
        if result.get("success"):
            stats["pplink_success"] += 1
        mgr.emit("done", {})
        jobs[job_id]["status"] = "done"
        stats["active_jobs"] = sum(1 for j in jobs.values() if j["status"] == "running")

    t = threading.Thread(target=run_job, daemon=True)
    jobs[job_id]["thread"] = t
    t.start()

    return jsonify({"job_id": job_id})


@app.route("/api/jobs/<job_id>/events")
def job_events(job_id):
    job = jobs.get(job_id)
    if not job:
        return jsonify({"detail": "job not found"}), 404

    mgr = job["manager"]

    def generate():
        deadline = time.time() + 600  # 10 分钟超时
        while time.time() < deadline:
            try:
                event = mgr.queue.get(timeout=1.0)
                yield f"data: {json.dumps(event, ensure_ascii=False)}\n\n"
                if event.get("type") == "done":
                    yield "event: timeout\ndata: stream closed\n\n"
                    return
            except queue.Empty:
                if job.get("status") == "done":
                    yield "event: timeout\ndata: stream closed\n\n"
                    return
                yield ": keepalive\n\n"
                continue

    return Response(
        stream_with_context(generate()),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
            "Access-Control-Allow-Origin": "*",
        },
    )


@app.route("/api/jobs/<job_id>/otp", methods=["POST"])
def job_otp(job_id):
    job = jobs.get(job_id)
    if not job:
        return jsonify({"detail": "job not found"}), 404
    data = request.get_json(force=True) or {}
    pin = str(data.get("pin", "")).strip()
    job["manager"].otp_value = pin
    job["manager"].otp_needed.set()
    return jsonify({"ok": True})


def main():
    port = int(os.environ.get("PORT", 5050))
    debug = os.environ.get("DEBUG", "").lower() in ("1", "true", "yes")
    print(f"\n  PayPal BA 链网站已启动")
    print(f"  访问: http://0.0.0.0:{port}")
    print(f"  按 Ctrl+C 停止\n")
    app.run(host="0.0.0.0", port=port, debug=debug, threaded=True)


if __name__ == "__main__":
    main()