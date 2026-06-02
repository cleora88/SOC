from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime, timezone
from typing import Any


MITRE_TECHNIQUES = {
    "T1110": {"name": "Brute Force", "tactic": "Credential Access"},
    "T1566": {"name": "Phishing", "tactic": "Initial Access"},
    "T1204": {"name": "User Execution", "tactic": "Execution"},
    "T1595": {"name": "Active Scanning", "tactic": "Reconnaissance"},
    "T1068": {"name": "Exploitation for Privilege Escalation", "tactic": "Privilege Escalation"},
    "T1041": {"name": "Exfiltration Over C2 Channel", "tactic": "Exfiltration"},
    "T1078": {"name": "Valid Accounts", "tactic": "Defense Evasion"},
    "T1087": {"name": "Account Discovery", "tactic": "Discovery"},
    "N/A": {"name": "Not mapped", "tactic": "Benign or informational"},
}


def mitre_summary(alerts: list[dict[str, Any]]) -> list[dict[str, Any]]:
    counts = Counter(alert["mitre_attack"] for alert in alerts)
    return [
        {
            "technique": technique,
            "name": MITRE_TECHNIQUES.get(technique, {}).get("name", "Unknown technique"),
            "tactic": MITRE_TECHNIQUES.get(technique, {}).get("tactic", "Unknown"),
            "count": count,
        }
        for technique, count in counts.most_common()
    ]


def correlate_alerts(alerts: list[dict[str, Any]]) -> list[dict[str, Any]]:
    by_source = defaultdict(list)
    for alert in alerts:
        if alert.get("source_ip"):
            by_source[alert["source_ip"]].append(alert)

    incidents = []
    for source_ip, grouped in by_source.items():
        if len(grouped) < 2:
            continue
        categories = sorted({alert["category"] for alert in grouped})
        risk = max(alert["risk_score"] for alert in grouped)
        priorities = sorted({alert["priority"] for alert in grouped})
        if len(categories) > 1 or risk >= 80:
            incidents.append(
                {
                    "id": f"INC-{abs(hash(source_ip)) % 100000:05d}",
                    "source_ip": source_ip,
                    "alert_count": len(grouped),
                    "categories": categories,
                    "highest_risk": risk,
                    "priorities": priorities,
                    "summary": f"{source_ip} generated {len(grouped)} related alerts across {', '.join(categories)}.",
                    "latest_seen": grouped[0]["created_at"],
                }
            )
    return sorted(incidents, key=lambda item: item["highest_risk"], reverse=True)


def explain_alert(alert: dict[str, Any]) -> dict[str, str]:
    category = alert["category"].replace("_", " ")
    asset = alert.get("hostname") or alert.get("destination_ip") or "the affected asset"
    source = alert.get("source_ip") or "an unknown source"
    return {
        "analyst_summary": f"This is a {alert['priority']} priority {category} alert involving {source} and {asset}.",
        "attack_scenario": f"The activity may represent {category} behavior mapped to {alert['mitre_attack']}. Review whether it is isolated or part of a larger sequence.",
        "investigation_steps": "Check related alerts, authentication activity, endpoint telemetry, network flows, and recent changes involving the same user, host, or IP.",
        "containment_steps": alert.get("recommended_action") or "Escalate to a SOC analyst for containment decision.",
    }


def markdown_report(alert: dict[str, Any], notes: list[dict[str, Any]]) -> str:
    generated = datetime.now(timezone.utc).isoformat()
    note_text = "\n".join(f"- {note['created_at']}: {note['note']}" for note in notes) or "- No analyst notes yet."
    return f"""# SOC Incident Report

Generated: {generated}

## Alert Summary

- Alert ID: {alert['alert_id']}
- Internal ID: {alert['id']}
- Status: {alert['status']}
- Priority: {alert['priority']}
- Category: {alert['category']}
- Risk Score: {alert['risk_score']}
- Confidence: {alert['confidence']}
- MITRE ATT&CK: {alert['mitre_attack']}

## Entities

- Source IP: {alert.get('source_ip') or '-'}
- Destination IP: {alert.get('destination_ip') or '-'}
- Hostname: {alert.get('hostname') or '-'}
- Username: {alert.get('username') or '-'}
- Source Tool: {alert['source']}

## Detection

- Rule: {alert.get('rule_name') or '-'}
- Event Type: {alert.get('event_type') or '-'}
- Message: {alert.get('log_message') or '-'}

## AI Explanation

{alert.get('explanation') or '-'}

## Recommended Action

{alert.get('recommended_action') or '-'}

## Analyst Notes

{note_text}
"""
