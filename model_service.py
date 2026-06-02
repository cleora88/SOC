from __future__ import annotations

import pickle
from pathlib import Path
from typing import Any, Protocol


MODEL_PATH = Path(__file__).parent / "models" / "soc_classifier.pkl"


class AlertLike(Protocol):
    rule_name: str
    event_type: str
    log_message: str
    severity: int
    source_ip: str | None
    destination_ip: str | None
    username: str | None
    hostname: str | None
    destination_port: int | None
    protocol: str | None
    asset_criticality: str


class HybridModelService:
    def __init__(self, fallback: Any):
        self.fallback = fallback
        self.pipeline = None
        self.loaded_path: str | None = None
        self.load()

    def load(self) -> None:
        if not MODEL_PATH.exists():
            return
        with MODEL_PATH.open("rb") as file:
            self.pipeline = pickle.load(file)
        self.loaded_path = str(MODEL_PATH)

    def classify(self, alert: AlertLike) -> dict[str, Any]:
        if not self.pipeline:
            result = self.fallback.classify(alert)
            result["model_used"] = "rule-fallback"
            return result

        features = {
            "text": " ".join([alert.rule_name, alert.event_type, alert.log_message]),
            "severity": alert.severity,
            "destination_port": alert.destination_port or 0,
            "protocol": alert.protocol or "",
            "asset_criticality": alert.asset_criticality,
        }
        category = self.pipeline.predict([features])[0]
        confidence = 0.75
        if hasattr(self.pipeline, "predict_proba"):
            proba = self.pipeline.predict_proba([features])[0]
            confidence = float(max(proba))

        result = self.fallback.classify(alert)
        result["category"] = category
        result["confidence"] = round(confidence, 2)
        result["model_used"] = "trained-ml"
        return result

    def info(self) -> dict[str, Any]:
        return {
            "classifier": "Hybrid SOC classifier",
            "active_model": "trained sklearn pipeline" if self.pipeline else "rule-fallback",
            "model_path": self.loaded_path,
            "production_target": "LightGBM or XGBoost multi-class classifier",
            "role": "Fast alert classification with rule fallback; LLM layer can enrich explanations.",
        }
