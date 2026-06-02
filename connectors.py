from __future__ import annotations

from typing import Any


SEVERITY_TEXT = {"informational": 1, "low": 2, "medium": 5, "high": 8, "critical": 10}


def _pick(data: dict[str, Any], *keys: str, default: Any = None) -> Any:
    for key in keys:
        value = data
        for part in key.split("."):
            if isinstance(value, list) and part.isdigit():
                index = int(part)
                if index >= len(value):
                    value = None
                    break
                value = value[index]
            elif isinstance(value, dict) and part in value:
                value = value[part]
            else:
                value = None
                break
        if value not in (None, ""):
            return value
    return default


def _severity(value: Any) -> int:
    if isinstance(value, int):
        return max(0, min(10, value))
    if isinstance(value, float):
        return max(0, min(10, int(value)))
    if isinstance(value, str):
        if value.isdigit():
            return max(0, min(10, int(value)))
        return SEVERITY_TEXT.get(value.lower(), 3)
    return 3


def normalize_connector(source: str, payload: dict[str, Any]) -> dict[str, Any]:
    source = source.lower()
    adapters = {
        "splunk": splunk,
        "qradar": qradar,
        "sentinel": sentinel,
        "wazuh": wazuh,
        "suricata": suricata,
        "elastic": elastic,
    }
    adapter = adapters.get(source, generic)
    normalized = adapter(payload)
    normalized["source"] = source
    normalized["raw_event"] = payload
    return normalized


def generic(data: dict[str, Any]) -> dict[str, Any]:
    return {
        "timestamp": _pick(data, "timestamp", "@timestamp", "time"),
        "alert_id": _pick(data, "alert_id", "id", "event.id"),
        "rule_name": _pick(data, "rule_name", "name", "rule.name", "signature", default="Generic security alert"),
        "event_type": _pick(data, "event_type", "type", "event.type", "event.category", default="security_event"),
        "severity": _severity(_pick(data, "severity", "level", "risk_score")),
        "source_ip": _pick(data, "source_ip", "src_ip", "source.ip", "src"),
        "destination_ip": _pick(data, "destination_ip", "dest_ip", "destination.ip", "dst"),
        "username": _pick(data, "username", "user.name", "user", "account"),
        "hostname": _pick(data, "hostname", "host.name", "host", "computer"),
        "destination_port": _pick(data, "destination_port", "dest_port", "destination.port", "dpt"),
        "protocol": _pick(data, "protocol", "network.protocol", "proto"),
        "asset_criticality": _pick(data, "asset_criticality", "asset.criticality", default="medium"),
        "log_message": _pick(data, "log_message", "message", "description", default=""),
    }


def splunk(data: dict[str, Any]) -> dict[str, Any]:
    result = generic(data)
    result.update(
        {
            "timestamp": _pick(data, "_time", "time", default=result["timestamp"]),
            "rule_name": _pick(data, "search_name", "rule_name", "signature", default=result["rule_name"]),
            "event_type": _pick(data, "sourcetype", "event_type", default=result["event_type"]),
            "log_message": _pick(data, "_raw", "message", default=result["log_message"]),
        }
    )
    return result


def qradar(data: dict[str, Any]) -> dict[str, Any]:
    result = generic(data)
    result.update(
        {
            "alert_id": _pick(data, "offense_id", "id", default=result["alert_id"]),
            "rule_name": _pick(data, "offense_source", "description", "rule_name", default=result["rule_name"]),
            "event_type": _pick(data, "event_name", "category", default=result["event_type"]),
            "severity": _severity(_pick(data, "magnitude", "severity", default=result["severity"])),
            "source_ip": _pick(data, "source_address", "source_ip", default=result["source_ip"]),
            "destination_ip": _pick(data, "destination_address", "destination_ip", default=result["destination_ip"]),
        }
    )
    return result


def sentinel(data: dict[str, Any]) -> dict[str, Any]:
    result = generic(data)
    result.update(
        {
            "alert_id": _pick(data, "SystemAlertId", "id", default=result["alert_id"]),
            "rule_name": _pick(data, "AlertName", "DisplayName", default=result["rule_name"]),
            "event_type": _pick(data, "AlertType", "ProviderName", default=result["event_type"]),
            "severity": _severity(_pick(data, "AlertSeverity", "Severity", default=result["severity"])),
            "log_message": _pick(data, "Description", "CompromisedEntity", default=result["log_message"]),
        }
    )
    return result


def wazuh(data: dict[str, Any]) -> dict[str, Any]:
    result = generic(data)
    result.update(
        {
            "rule_name": _pick(data, "rule.description", "rule.name", default=result["rule_name"]),
            "event_type": _pick(data, "rule.groups.0", "decoder.name", default=result["event_type"]),
            "severity": _severity(_pick(data, "rule.level", default=result["severity"])),
            "source_ip": _pick(data, "data.srcip", "srcip", default=result["source_ip"]),
            "destination_ip": _pick(data, "data.dstip", "dstip", default=result["destination_ip"]),
            "username": _pick(data, "data.srcuser", "data.dstuser", "username", default=result["username"]),
            "hostname": _pick(data, "agent.name", default=result["hostname"]),
        }
    )
    return result


def suricata(data: dict[str, Any]) -> dict[str, Any]:
    result = generic(data)
    result.update(
        {
            "rule_name": _pick(data, "alert.signature", default=result["rule_name"]),
            "event_type": _pick(data, "event_type", default="network_detection"),
            "severity": _severity(_pick(data, "alert.severity", default=result["severity"])),
            "source_ip": _pick(data, "src_ip", default=result["source_ip"]),
            "destination_ip": _pick(data, "dest_ip", default=result["destination_ip"]),
            "destination_port": _pick(data, "dest_port", default=result["destination_port"]),
            "protocol": _pick(data, "proto", default=result["protocol"]),
            "log_message": _pick(data, "alert.category", "alert.signature", default=result["log_message"]),
        }
    )
    return result


def elastic(data: dict[str, Any]) -> dict[str, Any]:
    result = generic(data)
    result.update(
        {
            "rule_name": _pick(data, "kibana.alert.rule.name", "signal.rule.name", default=result["rule_name"]),
            "event_type": _pick(data, "event.kind", "event.category", default=result["event_type"]),
            "severity": _severity(_pick(data, "kibana.alert.severity", "event.severity", default=result["severity"])),
        }
    )
    return result
