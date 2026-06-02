# AI-Powered Real-Time SOC Alert Classifier

Prototype PFA application for real-time SOC alert classification and prioritization.

The app receives alerts from SIEM/IDS/EDR-style sources, normalizes them into a common schema, sends them through an async queue, classifies them with a model-shaped inference service, assigns a risk score, maps the result to MITRE ATT&CK, and streams the result to a live dashboard.

## Architecture

```text
Threat Source / SIEM Connector
        ↓
FastAPI Ingestion API
        ↓
Async Alert Queue
        ↓
AI Classification Worker
        ↓
Risk Scoring + MITRE Mapping + Analyst Recommendation
        ↓
Live Dashboard
```

## Run

```bash
uvicorn app:app --reload --host 127.0.0.1 --port 8000
```

Open:

```text
http://127.0.0.1:8000
```

## API

Send an alert:

```bash
curl -X POST http://127.0.0.1:8000/api/alerts \
  -H "Content-Type: application/json" \
  -d '{
    "source": "qradar",
    "rule_name": "Multiple failed VPN login attempts",
    "event_type": "failed_login",
    "severity": 8,
    "source_ip": "196.92.10.44",
    "destination_ip": "10.20.3.12",
    "username": "admin",
    "hostname": "bank-vpn-gateway-01",
    "destination_port": 443,
    "protocol": "https",
    "asset_criticality": "critical",
    "log_message": "Multiple failed login attempts detected for admin user from same source IP"
  }'
```

Useful endpoints:

- `POST /api/alerts` queues a new alert for classification.
- `GET /api/alerts` returns classified alerts.
- `GET /api/stats` returns dashboard counters.
- `GET /api/events` streams live classified alerts.
- `POST /api/demo/burst?count=8` generates demo alerts.
- `POST /api/simulator/start` starts live demo alert generation.
- `POST /api/simulator/stop` stops live demo alert generation.

## Model Notes

The current classifier is a deterministic prototype with the same interface you would use for an ML model. This lets the app run without a labeled dataset.

For the final PFA implementation, replace `SocClassifier.classify()` with:

```text
TF-IDF / Sentence Transformer features
        +
structured alert features
        ↓
LightGBM or XGBoost multi-class classifier
```

Recommended production split:

- LightGBM/XGBoost: fast alert classification.
- Rules engine: repeatable risk scoring and priority assignment.
- LLM: analyst explanation and recommended response.

## Universal Alert Schema

The app is SIEM-agnostic. Splunk, QRadar, Sentinel, Wazuh, Suricata, Elastic, and other tools can be connected by writing small adapters that transform vendor-specific alert fields into this schema:

```json
{
  "source": "qradar",
  "timestamp": "2026-06-02T12:00:00Z",
  "alert_id": "ALERT-001",
  "rule_name": "Multiple failed VPN login attempts",
  "event_type": "failed_login",
  "severity": 8,
  "source_ip": "196.92.10.44",
  "destination_ip": "10.20.3.12",
  "username": "admin",
  "hostname": "bank-vpn-gateway-01",
  "destination_port": 443,
  "protocol": "https",
  "asset_criticality": "critical",
  "log_message": "Multiple failed login attempts detected for admin user from same source IP",
  "raw_event": {}
}
```
# SOC
