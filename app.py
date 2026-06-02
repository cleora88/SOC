from __future__ import annotations

import asyncio
import json
import random
import re
import time
import uuid
from collections import Counter, deque
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, PlainTextResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

import database
from connectors import normalize_connector
from intelligence import correlate_alerts, explain_alert, markdown_report, mitre_summary
from model_service import HybridModelService


APP_DIR = Path(__file__).parent
MAX_ALERTS = 500


class AlertIn(BaseModel):
    source: str = Field(default="simulator", examples=["wazuh", "suricata", "splunk"])
    timestamp: str | None = None
    alert_id: str | None = None
    rule_name: str = ""
    event_type: str = ""
    severity: int | str | None = None
    source_ip: str | None = None
    destination_ip: str | None = None
    username: str | None = None
    hostname: str | None = None
    destination_port: int | None = None
    protocol: str | None = None
    asset_criticality: str | None = "medium"
    log_message: str = ""
    raw_event: dict[str, Any] = Field(default_factory=dict)


class StatusUpdate(BaseModel):
    status: str


class NoteIn(BaseModel):
    note: str


@dataclass
class NormalizedAlert:
    id: str
    source: str
    timestamp: str
    alert_id: str
    rule_name: str
    event_type: str
    severity: int
    source_ip: str | None
    destination_ip: str | None
    username: str | None
    hostname: str | None
    destination_port: int | None
    protocol: str | None
    asset_criticality: str
    log_message: str
    raw_event: dict[str, Any] = field(default_factory=dict)


@dataclass
class ClassifiedAlert:
    id: str
    status: str
    source: str
    timestamp: str
    alert_id: str
    rule_name: str
    event_type: str
    severity: int
    source_ip: str | None
    destination_ip: str | None
    username: str | None
    hostname: str | None
    destination_port: int | None
    protocol: str | None
    asset_criticality: str
    log_message: str
    raw_event: dict[str, Any]
    category: str
    confidence: float
    priority: str
    risk_score: int
    mitre_attack: str
    explanation: str
    recommended_action: str
    model_used: str
    processing_ms: int
    created_at: str
    updated_at: str


class SocClassifier:
    """Lightweight real-time classifier placeholder for an ML service.

    The interface is intentionally model-shaped: replace classify() with a
    LightGBM/XGBoost pipeline once labeled SOC data is available.
    """

    CATEGORY_PATTERNS = {
        "brute_force": [
            "failed login",
            "authentication failure",
            "password spraying",
            "brute force",
            "multiple login",
            "invalid user",
        ],
        "phishing": [
            "phishing",
            "malicious link",
            "credential harvest",
            "spoofed sender",
            "suspicious email",
        ],
        "malware": [
            "malware",
            "ransomware",
            "trojan",
            "payload",
            "suspicious process",
            "powershell encoded",
            "virus",
        ],
        "reconnaissance": [
            "port scan",
            "scan",
            "nmap",
            "recon",
            "enumeration",
            "sweep",
            "probing",
        ],
        "privilege_escalation": [
            "privilege escalation",
            "admin group",
            "sudo",
            "uac",
            "new administrator",
            "root access",
        ],
        "data_exfiltration": [
            "exfiltration",
            "large upload",
            "data transfer",
            "unusual outbound",
            "sensitive file",
            "dns tunneling",
        ],
        "suspicious_login": [
            "impossible travel",
            "new location",
            "suspicious login",
            "mfa denied",
            "unusual sign-in",
        ],
        "false_positive": [
            "known scanner",
            "test alert",
            "maintenance",
            "health check",
            "benign",
            "allowed activity",
        ],
    }

    MITRE = {
        "brute_force": "T1110",
        "phishing": "T1566",
        "malware": "T1204",
        "reconnaissance": "T1595",
        "privilege_escalation": "T1068",
        "data_exfiltration": "T1041",
        "suspicious_login": "T1078",
        "false_positive": "N/A",
        "other": "T1087",
    }

    ACTIONS = {
        "brute_force": "Temporarily block the source IP, review failed authentication events, and verify whether the targeted account was compromised.",
        "phishing": "Quarantine the message, block related URLs or senders, and check whether any user submitted credentials.",
        "malware": "Isolate the affected host, collect process and file evidence, and run endpoint containment or remediation.",
        "reconnaissance": "Rate-limit or block the source, review exposed services, and correlate with later exploitation attempts.",
        "privilege_escalation": "Review account and group changes, preserve host evidence, and revoke suspicious elevated permissions.",
        "data_exfiltration": "Inspect outbound traffic, identify transferred data, and restrict the source account or host while investigating.",
        "suspicious_login": "Verify the login with the user, reset credentials if needed, and review MFA and session activity.",
        "false_positive": "Validate the source context and tune the detection rule if the activity is confirmed benign.",
        "other": "Review the raw event, correlate with related alerts, and escalate if suspicious behavior continues.",
    }

    def classify(self, alert: NormalizedAlert) -> dict[str, Any]:
        text = " ".join(
            [
                alert.rule_name,
                alert.event_type,
                alert.log_message,
                str(alert.destination_port or ""),
                str(alert.protocol or ""),
            ]
        ).lower()

        scores = Counter()
        for category, patterns in self.CATEGORY_PATTERNS.items():
            for pattern in patterns:
                if pattern in text:
                    scores[category] += 2 if len(pattern.split()) > 1 else 1

        if alert.destination_port in {22, 3389, 445} and "login" in text:
            scores["brute_force"] += 2
        if alert.destination_port in {25, 465, 587}:
            scores["phishing"] += 1
        if alert.destination_port in {53} and ("large" in text or "tunnel" in text):
            scores["data_exfiltration"] += 2

        category = scores.most_common(1)[0][0] if scores else "other"
        raw_score = scores[category] if scores else 1
        confidence = min(0.97, 0.48 + raw_score * 0.11)

        risk_score = self._risk_score(alert, category, confidence)
        priority = self._priority(risk_score)

        return {
            "category": category,
            "confidence": round(confidence, 2),
            "priority": priority,
            "risk_score": risk_score,
            "mitre_attack": self.MITRE[category],
            "explanation": self._explain(alert, category, confidence, risk_score),
            "recommended_action": self.ACTIONS[category],
        }

    def _risk_score(self, alert: NormalizedAlert, category: str, confidence: float) -> int:
        category_weight = {
            "data_exfiltration": 28,
            "privilege_escalation": 25,
            "malware": 24,
            "brute_force": 18,
            "suspicious_login": 17,
            "phishing": 16,
            "reconnaissance": 12,
            "other": 8,
            "false_positive": -12,
        }[category]
        asset_weight = {"critical": 18, "high": 14, "medium": 8, "low": 3}.get(
            alert.asset_criticality.lower(), 8
        )
        user_weight = 10 if (alert.username or "").lower() in {"admin", "administrator", "root"} else 0
        base = int(alert.severity * 6 + confidence * 20 + category_weight + asset_weight + user_weight)
        return max(0, min(100, base))

    def _priority(self, risk_score: int) -> str:
        if risk_score >= 80:
            return "critical"
        if risk_score >= 60:
            return "high"
        if risk_score >= 35:
            return "medium"
        return "low"

    def _explain(self, alert: NormalizedAlert, category: str, confidence: float, risk_score: int) -> str:
        subject = alert.hostname or alert.destination_ip or "the monitored asset"
        origin = alert.source_ip or "an unknown source"
        label = category.replace("_", " ")
        return (
            f"The alert was categorized as {label} because the rule, event type, and log text contain indicators "
            f"matching this behavior. The event involves {origin} targeting {subject}, with a model confidence "
            f"of {confidence:.2f} and a calculated risk score of {risk_score}."
        )


app = FastAPI(title="AI SOC Alert Classifier", version="1.0.0")
app.mount("/static", StaticFiles(directory=APP_DIR / "static"), name="static")

alert_queue: asyncio.Queue[NormalizedAlert] = asyncio.Queue()
classified_alerts: deque[ClassifiedAlert] = deque(maxlen=MAX_ALERTS)
subscribers: set[asyncio.Queue[dict[str, Any]]] = set()
rule_classifier = SocClassifier()
classifier = HybridModelService(rule_classifier)
simulator_task: asyncio.Task | None = None
VALID_STATUSES = {"new", "in_review", "escalated", "closed", "false_positive"}


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def normalize_alert(payload: AlertIn) -> NormalizedAlert:
    severity = payload.severity if payload.severity is not None else 3
    if isinstance(severity, str):
        severity = {"low": 2, "medium": 5, "high": 8, "critical": 10}.get(severity.lower(), 3)

    return NormalizedAlert(
        id=str(uuid.uuid4()),
        source=payload.source,
        timestamp=payload.timestamp or now_iso(),
        alert_id=payload.alert_id or f"ALERT-{uuid.uuid4().hex[:8].upper()}",
        rule_name=payload.rule_name,
        event_type=payload.event_type,
        severity=max(0, min(10, int(severity))),
        source_ip=payload.source_ip,
        destination_ip=payload.destination_ip,
        username=payload.username,
        hostname=payload.hostname,
        destination_port=payload.destination_port,
        protocol=payload.protocol,
        asset_criticality=payload.asset_criticality or "medium",
        log_message=payload.log_message,
        raw_event=payload.raw_event,
    )


async def publish(event: dict[str, Any]) -> None:
    for subscriber in list(subscribers):
        try:
            subscriber.put_nowait(event)
        except asyncio.QueueFull:
            subscribers.discard(subscriber)


async def worker() -> None:
    while True:
        alert = await alert_queue.get()
        started = time.perf_counter()
        result = classifier.classify(alert)
        processing_ms = int((time.perf_counter() - started) * 1000)
        classified = ClassifiedAlert(
            **asdict(alert),
            status="new",
            **result,
            processing_ms=processing_ms,
            created_at=now_iso(),
            updated_at=now_iso(),
        )
        classified_alerts.appendleft(classified)
        database.save_alert(asdict(classified))
        payload = asdict(classified)
        await publish({"type": "classified_alert", "data": payload})
        await publish({"type": "stats", "data": dashboard_stats()})
        alert_queue.task_done()


def dashboard_stats() -> dict[str, Any]:
    values = database.stats()
    values["queue_depth"] = alert_queue.qsize()
    return values


@app.on_event("startup")
async def startup() -> None:
    database.init_db()
    asyncio.create_task(worker())


@app.get("/")
async def index() -> FileResponse:
    return FileResponse(APP_DIR / "static" / "index.html")


@app.post("/api/alerts")
async def ingest_alert(payload: AlertIn) -> dict[str, Any]:
    alert = normalize_alert(payload)
    await alert_queue.put(alert)
    await publish({"type": "queued_alert", "data": asdict(alert)})
    return {"status": "queued", "id": alert.id, "queue_depth": alert_queue.qsize()}


@app.get("/api/alerts")
async def get_alerts(
    limit: int = 100,
    priority: str | None = None,
    category: str | None = None,
    source: str | None = None,
    status: str | None = None,
    mitre_attack: str | None = None,
    q: str | None = None,
) -> dict[str, Any]:
    limit = max(1, min(limit, MAX_ALERTS))
    filters = {
        "priority": priority,
        "category": category,
        "source": source,
        "status": status,
        "mitre_attack": mitre_attack,
        "q": q,
    }
    return {"alerts": database.list_alerts(filters, limit)}


@app.get("/api/alerts/{alert_id}")
async def get_alert(alert_id: str) -> dict[str, Any]:
    alert = database.get_alert(alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    alert["notes"] = database.get_notes(alert_id)
    alert["llm_explanation"] = explain_alert(alert)
    return alert


@app.patch("/api/alerts/{alert_id}/status")
async def update_status(alert_id: str, payload: StatusUpdate) -> dict[str, Any]:
    if payload.status not in VALID_STATUSES:
        raise HTTPException(status_code=400, detail=f"Status must be one of {sorted(VALID_STATUSES)}")
    alert = database.update_alert_status(alert_id, payload.status, now_iso())
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    await publish({"type": "updated_alert", "data": alert})
    await publish({"type": "stats", "data": dashboard_stats()})
    return alert


@app.post("/api/alerts/{alert_id}/notes")
async def add_alert_note(alert_id: str, payload: NoteIn) -> dict[str, str]:
    if not database.get_alert(alert_id):
        raise HTTPException(status_code=404, detail="Alert not found")
    database.add_note(alert_id, payload.note, now_iso())
    return {"status": "created"}


@app.get("/api/alerts/{alert_id}/report")
async def export_report(alert_id: str) -> PlainTextResponse:
    alert = database.get_alert(alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    return PlainTextResponse(markdown_report(alert, database.get_notes(alert_id)), media_type="text/markdown")


@app.post("/api/connectors/{source}")
async def ingest_connector(source: str, payload: dict[str, Any]) -> dict[str, Any]:
    normalized = normalize_connector(source, payload)
    return await ingest_alert(AlertIn(**normalized))


@app.get("/api/stats")
async def get_stats() -> dict[str, Any]:
    return dashboard_stats()


@app.get("/api/model")
async def model_info() -> dict[str, Any]:
    info = classifier.info()
    info["categories"] = list(rule_classifier.CATEGORY_PATTERNS.keys()) + ["other"]
    return info


@app.get("/api/mitre")
async def get_mitre() -> dict[str, Any]:
    alerts = database.list_alerts({}, MAX_ALERTS)
    return {"techniques": mitre_summary(alerts)}


@app.get("/api/incidents")
async def get_incidents() -> dict[str, Any]:
    alerts = database.list_alerts({}, MAX_ALERTS)
    return {"incidents": correlate_alerts(alerts)}


@app.get("/api/events")
async def events(request: Request) -> StreamingResponse:
    subscriber: asyncio.Queue[dict[str, Any]] = asyncio.Queue(maxsize=100)
    subscribers.add(subscriber)

    async def event_stream():
        try:
            yield f"data: {json.dumps({'type': 'stats', 'data': dashboard_stats()})}\n\n"
            while not await request.is_disconnected():
                try:
                    event = await asyncio.wait_for(subscriber.get(), timeout=15)
                    yield f"data: {json.dumps(event)}\n\n"
                    yield f"data: {json.dumps({'type': 'stats', 'data': dashboard_stats()})}\n\n"
                except asyncio.TimeoutError:
                    yield f"data: {json.dumps({'type': 'heartbeat', 'data': dashboard_stats()})}\n\n"
        finally:
            subscribers.discard(subscriber)

    return StreamingResponse(event_stream(), media_type="text/event-stream")


SAMPLES = [
    {
        "source": "wazuh",
        "rule_name": "Multiple failed SSH login attempts",
        "event_type": "failed_login",
        "severity": 8,
        "source_ip": "185.199.108.42",
        "destination_ip": "10.10.3.14",
        "username": "admin",
        "hostname": "bank-core-auth-01",
        "destination_port": 22,
        "protocol": "ssh",
        "asset_criticality": "critical",
        "log_message": "18 failed login attempts detected for admin user from same source IP",
    },
    {
        "source": "suricata",
        "rule_name": "ET SCAN Nmap Scripting Engine User-Agent Detected",
        "event_type": "network_scan",
        "severity": 5,
        "source_ip": "45.83.12.19",
        "destination_ip": "10.10.9.22",
        "hostname": "insurance-web-02",
        "destination_port": 443,
        "protocol": "tcp",
        "asset_criticality": "medium",
        "log_message": "Possible nmap scan and service enumeration against public web server",
    },
    {
        "source": "sentinel",
        "rule_name": "Impossible travel sign-in",
        "event_type": "suspicious_login",
        "severity": 7,
        "source_ip": "102.90.41.7",
        "destination_ip": "10.10.5.21",
        "username": "finance.manager",
        "hostname": "aad-tenant",
        "asset_criticality": "high",
        "log_message": "User authenticated from a new location minutes after another successful login",
    },
    {
        "source": "splunk",
        "rule_name": "Large outbound data transfer",
        "event_type": "network_anomaly",
        "severity": 9,
        "source_ip": "10.10.7.18",
        "destination_ip": "91.240.118.90",
        "username": "claims_ops",
        "hostname": "insurance-files-01",
        "destination_port": 443,
        "protocol": "https",
        "asset_criticality": "critical",
        "log_message": "Large upload of sensitive file archive to external host outside business hours",
    },
    {
        "source": "elastic",
        "rule_name": "PowerShell encoded command execution",
        "event_type": "endpoint_detection",
        "severity": 8,
        "source_ip": "10.10.4.73",
        "destination_ip": "10.10.4.73",
        "username": "it.support",
        "hostname": "bank-workstation-114",
        "asset_criticality": "high",
        "log_message": "Suspicious process launched powershell encoded payload from temporary directory",
    },
    {
        "source": "wazuh",
        "rule_name": "Known scanner health check",
        "event_type": "benign_monitoring",
        "severity": 1,
        "source_ip": "10.10.1.50",
        "destination_ip": "10.10.9.22",
        "username": "monitoring",
        "hostname": "insurance-web-02",
        "destination_port": 443,
        "protocol": "https",
        "asset_criticality": "low",
        "log_message": "Known scanner health check from allowed activity during maintenance window",
    },
    {
        "source": "sentinel",
        "rule_name": "Allowed activity from backup service",
        "event_type": "maintenance_event",
        "severity": 2,
        "source_ip": "10.10.2.15",
        "destination_ip": "10.10.7.18",
        "username": "backup_service",
        "hostname": "insurance-files-01",
        "destination_port": 445,
        "protocol": "smb",
        "asset_criticality": "low",
        "log_message": "Allowed activity from backup service confirmed as benign maintenance transfer",
    },
    {
        "source": "splunk",
        "rule_name": "Test alert from detection engineering",
        "event_type": "test_alert",
        "severity": 1,
        "source_ip": "10.10.8.30",
        "destination_ip": "10.10.8.31",
        "username": "soc_engineer",
        "hostname": "soc-lab-host",
        "destination_port": 8080,
        "protocol": "http",
        "asset_criticality": "low",
        "log_message": "Test alert generated by detection engineering and confirmed benign",
    },
]

SAMPLE_WEIGHTS = [2, 2, 2, 2, 2, 4, 4, 3]


async def simulation_loop() -> None:
    while True:
        sample = dict(random.choices(SAMPLES, weights=SAMPLE_WEIGHTS, k=1)[0])
        sample["source_ip"] = sample.get("source_ip") or f"192.168.1.{random.randint(2, 254)}"
        sample["timestamp"] = now_iso()
        await alert_queue.put(normalize_alert(AlertIn(**sample)))
        await asyncio.sleep(random.uniform(1.2, 3.2))


@app.post("/api/simulator/start")
async def start_simulator() -> dict[str, str]:
    global simulator_task
    if simulator_task and not simulator_task.done():
        return {"status": "already_running"}
    simulator_task = asyncio.create_task(simulation_loop())
    return {"status": "started"}


@app.post("/api/simulator/stop")
async def stop_simulator() -> dict[str, str]:
    global simulator_task
    if not simulator_task or simulator_task.done():
        return {"status": "already_stopped"}
    simulator_task.cancel()
    return {"status": "stopped"}


@app.post("/api/demo/burst")
async def demo_burst(count: int = 8) -> dict[str, Any]:
    count = max(1, min(count, 30))
    for _ in range(count):
        sample = dict(random.choices(SAMPLES, weights=SAMPLE_WEIGHTS, k=1)[0])
        sample["timestamp"] = now_iso()
        if sample.get("source_ip"):
            sample["source_ip"] = re.sub(r"\d+$", str(random.randint(2, 254)), sample["source_ip"])
        await alert_queue.put(normalize_alert(AlertIn(**sample)))
    return {"status": "queued", "count": count, "queue_depth": alert_queue.qsize()}


@app.post("/api/demo/incident")
async def demo_incident() -> dict[str, Any]:
    attacker_ip = f"185.199.108.{random.randint(2, 254)}"
    sequence = [
        {
            "source": "suricata",
            "rule_name": "Nmap port scan detected",
            "event_type": "network_scan",
            "severity": 5,
            "source_ip": attacker_ip,
            "destination_ip": "10.10.9.22",
            "hostname": "insurance-web-02",
            "destination_port": 443,
            "protocol": "tcp",
            "asset_criticality": "medium",
            "log_message": "Port scan and service enumeration detected from same source IP",
        },
        {
            "source": "wazuh",
            "rule_name": "Multiple failed SSH login attempts",
            "event_type": "failed_login",
            "severity": 8,
            "source_ip": attacker_ip,
            "destination_ip": "10.10.3.14",
            "username": "admin",
            "hostname": "bank-core-auth-01",
            "destination_port": 22,
            "protocol": "ssh",
            "asset_criticality": "critical",
            "log_message": "Multiple failed login attempts detected for admin user from same source IP",
        },
        {
            "source": "elastic",
            "rule_name": "Suspicious process after remote login",
            "event_type": "endpoint_detection",
            "severity": 8,
            "source_ip": attacker_ip,
            "destination_ip": "10.10.4.73",
            "username": "it.support",
            "hostname": "bank-workstation-114",
            "asset_criticality": "high",
            "log_message": "Suspicious process launched powershell encoded payload after remote authentication",
        },
    ]
    for item in sequence:
        item["timestamp"] = now_iso()
        await alert_queue.put(normalize_alert(AlertIn(**item)))
    return {"status": "queued", "incident_source_ip": attacker_ip, "count": len(sequence)}


@app.delete("/api/alerts")
async def clear_alerts() -> dict[str, str]:
    classified_alerts.clear()
    database.clear_alerts()
    await publish({"type": "stats", "data": dashboard_stats()})
    return {"status": "cleared"}
