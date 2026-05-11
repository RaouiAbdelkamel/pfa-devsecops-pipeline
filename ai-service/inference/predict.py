"""
API FastAPI d'inférence pour le module IA du pipeline DevSecOps.

Rôle dans le PFE :
- recevoir des alertes issues de Semgrep, Trivy, Checkov, Snyk ou OWASP ZAP ;
- estimer si une alerte est un faux positif probable ;
- calculer un score de risque de 0 à 1 ;
- retourner une recommandation exploitable par le pipeline : BLOCK, REVIEW ou ALLOW ;
- fournir une explication simple, compatible avec un dashboard.
"""

import os
import logging
from typing import Any, Dict, List, Optional

import joblib
import numpy as np
import shap
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

BASE_DIR = os.path.dirname(os.path.dirname(__file__))
MODEL_DIR = os.path.join(BASE_DIR, "model")
MODEL_PATH = os.path.join(MODEL_DIR, "model.pkl")
SCALER_PATH = os.path.join(MODEL_DIR, "scaler.pkl")
EXPLAINER_PATH = os.path.join(MODEL_DIR, "explainer.pkl")

FALSE_POSITIVE_THRESHOLD = float(os.getenv("FP_THRESHOLD", "0.55"))
BLOCK_RISK_THRESHOLD = float(os.getenv("BLOCK_THRESHOLD", "0.75"))
REVIEW_RISK_THRESHOLD = float(os.getenv("REVIEW_THRESHOLD", "0.45"))
ALLOW_CONFIDENCE_THRESHOLD = float(os.getenv("ALLOW_CONFIDENCE", "0.70"))

FEATURE_NAMES = [
    "severity_level",
    "cvss_score",
    "cwe_id_confidence",
    "lines_of_code_affected",
    "function_complexity",
    "is_third_party_lib",
    "has_test_coverage",
    "file_age_days",
    "number_of_contributors",
    "previous_similar_vulns",
]

app = FastAPI(
    title="Security AI Model API",
    description="API IA pour la priorisation des vulnérabilités et le filtrage des faux positifs",
    version="1.1.0",
)

model = None
scaler = None
explainer = None


class VulnerabilityAlert(BaseModel):
    alert_id: str = Field(..., description="Identifiant unique de l'alerte")
    tool: str = Field(..., description="semgrep, sonarqube, snyk, trivy, checkov, zapproxy")
    rule_id: str = Field(..., description="Identifiant de règle, CWE ou CVE")
    severity: str = Field(..., description="low, medium, high, critical")
    file_path: str = Field(..., description="Fichier ou ressource concernée")
    line_number: int = Field(1, ge=1, description="Ligne concernée")
    message: str = Field(..., description="Description de l'alerte")
    cvss_score: Optional[float] = Field(5.0, ge=0, le=10)
    cwe_id: Optional[str] = None
    lines_affected: Optional[int] = Field(1, ge=1)
    function_complexity: Optional[int] = Field(1, ge=1)
    is_third_party: Optional[bool] = False
    has_test: Optional[bool] = False
    file_age_days: Optional[int] = Field(30, ge=0)
    contributors_count: Optional[int] = Field(1, ge=1)
    similar_vulns_count: Optional[int] = Field(0, ge=0)

    model_config = {
        "json_schema_extra": {
            "example": {
                "alert_id": "semgrep-001",
                "tool": "semgrep",
                "rule_id": "python.lang.security.audit.sql-injection",
                "severity": "high",
                "file_path": "app/app.py",
                "line_number": 18,
                "message": "Potential SQL injection",
                "cvss_score": 8.2,
                "cwe_id": "CWE-89",
                "lines_affected": 4,
                "function_complexity": 3,
                "is_third_party": False,
                "has_test": False,
                "file_age_days": 7,
                "contributors_count": 1,
                "similar_vulns_count": 1,
            }
        }
    }


class RiskScore(BaseModel):
    alert_id: str
    is_false_positive: bool
    risk_score: float = Field(..., ge=0, le=1)
    confidence: float = Field(..., ge=0, le=1)
    recommendation: str
    explanation: Optional[Dict[str, Any]] = None


class BatchPredictionRequest(BaseModel):
    alerts: List[VulnerabilityAlert]


@app.on_event("startup")
async def startup_event():
    """Chargement du modèle au démarrage. L'API reste utilisable avec fallback si aucun modèle n'est présent."""
    global model, scaler, explainer

    if os.path.exists(MODEL_PATH):
        model = joblib.load(MODEL_PATH)
        logger.info("Modèle chargé: %s", MODEL_PATH)
    else:
        logger.warning("Aucun model.pkl trouvé. Fallback heuristique activé.")

    if os.path.exists(SCALER_PATH):
        scaler = joblib.load(SCALER_PATH)
        logger.info("Scaler chargé: %s", SCALER_PATH)
    else:
        logger.warning("Aucun scaler.pkl trouvé. Les features ne seront pas normalisées.")

    if os.path.exists(EXPLAINER_PATH):
        try:
            explainer = joblib.load(EXPLAINER_PATH)
            logger.info("Explainer SHAP chargé: %s", EXPLAINER_PATH)
        except Exception as exc:
            logger.warning("Explainer SHAP non chargé: %s", exc)


def severity_to_level(severity: str) -> int:
    return {"low": 0, "medium": 1, "moderate": 1, "high": 2, "critical": 3}.get(severity.lower(), 1)


def extract_cwe_confidence(cwe_id: Optional[str], rule_id: str = "", message: str = "") -> float:
    text = f"{cwe_id or ''} {rule_id} {message}".lower()
    known_patterns = ["cwe-89", "sql", "cwe-79", "xss", "cwe-78", "command", "shell", "cwe-94", "cwe-798", "secret"]
    return 0.85 if any(p in text for p in known_patterns) else (0.60 if cwe_id else 0.35)


def prepare_raw_features(alert: VulnerabilityAlert) -> np.ndarray:
    severity_level = severity_to_level(alert.severity)
    cvss_score = float(alert.cvss_score if alert.cvss_score is not None else default_cvss_from_severity(severity_level))
    cwe_confidence = extract_cwe_confidence(alert.cwe_id, alert.rule_id, alert.message)

    raw = np.array([[ 
        severity_level,
        cvss_score,
        cwe_confidence,
        float(alert.lines_affected or 1),
        float(alert.function_complexity or 1),
        1.0 if alert.is_third_party else 0.0,
        1.0 if alert.has_test else 0.0,
        float(alert.file_age_days or 0),
        float(alert.contributors_count or 1),
        float(alert.similar_vulns_count or 0),
    ]], dtype=float)
    return raw


def prepare_model_features(alert: VulnerabilityAlert) -> np.ndarray:
    raw = prepare_raw_features(alert)
    if scaler is not None:
        return scaler.transform(raw)
    return raw


def default_cvss_from_severity(severity_level: int) -> float:
    return [2.5, 5.0, 7.5, 9.2][max(0, min(3, severity_level))]


def heuristic_probability_false_positive(alert: VulnerabilityAlert) -> float:
    """Fallback déterministe si aucun modèle entraîné n'est disponible."""
    raw = prepare_raw_features(alert)[0]
    severity, cvss, cwe_conf, _, complexity, third_party, has_test, age, contributors, previous = raw

    fp_prob = 0.35
    if severity >= 2:
        fp_prob -= 0.18
    if severity == 3:
        fp_prob -= 0.15
    if cvss >= 7:
        fp_prob -= 0.20
    if cwe_conf >= 0.8:
        fp_prob -= 0.12
    if previous >= 1:
        fp_prob -= 0.08

    if severity <= 1:
        fp_prob += 0.15
    if cvss < 4:
        fp_prob += 0.20
    if has_test == 1:
        fp_prob += 0.10
    if contributors >= 10:
        fp_prob += 0.12
    if age >= 365:
        fp_prob += 0.06
    if third_party == 1:
        fp_prob += 0.06
    if complexity >= 10 and severity <= 1:
        fp_prob += 0.08

    return float(np.clip(fp_prob, 0.02, 0.95))


def make_explanation(alert: VulnerabilityAlert, model_features: np.ndarray, is_fp_prob: float) -> Dict[str, Any]:
    raw_features = prepare_raw_features(alert)

    explanation: Dict[str, Any] = {
        "method": "heuristic" if model is None else "model",
        "features": {FEATURE_NAMES[i]: float(raw_features[0, i]) for i in range(len(FEATURE_NAMES))},
        "false_positive_probability": float(is_fp_prob),
        "risk_interpretation": "risk_score = 1 - probability(false_positive)",
    }

    if explainer is not None and model is not None:
        try:
            shap_values = explainer.shap_values(model_features)
            # RandomForest binaire : shap_values peut être une liste [classe0, classe1]
            if isinstance(shap_values, list):
                values = shap_values[1][0]
                base_value = explainer.expected_value[1] if isinstance(explainer.expected_value, (list, np.ndarray)) else explainer.expected_value
            else:
                arr = np.asarray(shap_values)
                values = arr[0, :, 1] if arr.ndim == 3 else arr[0]
                base_value = np.asarray(explainer.expected_value).ravel()[-1]

            explanation["method"] = "SHAP"
            explanation["base_value"] = float(np.asarray(base_value).ravel()[0])
            explanation["feature_importance"] = {FEATURE_NAMES[i]: float(values[i]) for i in range(len(FEATURE_NAMES))}
            explanation["top_features"] = sorted(
                [{"feature": FEATURE_NAMES[i], "impact": float(values[i])} for i in range(len(FEATURE_NAMES))],
                key=lambda item: abs(item["impact"]),
                reverse=True,
            )[:5]
        except Exception as exc:
            explanation["shap_warning"] = str(exc)

    return explanation


def compute_prediction(alert: VulnerabilityAlert) -> RiskScore:
    model_features = prepare_model_features(alert)

    if model is not None:
        try:
            probabilities = model.predict_proba(model_features)[0]
            is_fp_prob = float(probabilities[1])
            confidence = float(max(probabilities))
        except Exception as exc:
            logger.warning("Erreur modèle, fallback heuristique: %s", exc)
            is_fp_prob = heuristic_probability_false_positive(alert)
            confidence = float(max(is_fp_prob, 1 - is_fp_prob))
    else:
        is_fp_prob = heuristic_probability_false_positive(alert)
        confidence = float(max(is_fp_prob, 1 - is_fp_prob))

    is_false_positive = is_fp_prob >= FALSE_POSITIVE_THRESHOLD
    risk_score = float(np.clip(1.0 - is_fp_prob, 0.0, 1.0))

    if is_false_positive and confidence >= ALLOW_CONFIDENCE_THRESHOLD:
        recommendation = "ALLOW"
    elif risk_score >= BLOCK_RISK_THRESHOLD:
        recommendation = "BLOCK"
    elif risk_score >= REVIEW_RISK_THRESHOLD:
        recommendation = "REVIEW"
    else:
        recommendation = "ALLOW"

    return RiskScore(
        alert_id=alert.alert_id,
        is_false_positive=bool(is_false_positive),
        risk_score=risk_score,
        confidence=confidence,
        recommendation=recommendation,
        explanation=make_explanation(alert, model_features, is_fp_prob),
    )


@app.get("/health")
async def health():
    return {
        "status": "healthy",
        "model_loaded": model is not None,
        "scaler_loaded": scaler is not None,
        "explainer_available": explainer is not None,
        "mode": "ml_model" if model is not None else "heuristic_fallback",
    }


@app.post("/predict", response_model=RiskScore)
async def predict(alert: VulnerabilityAlert):
    try:
        return compute_prediction(alert)
    except Exception as exc:
        logger.exception("Erreur de prédiction")
        raise HTTPException(status_code=500, detail=str(exc))


@app.post("/predict-batch", response_model=List[RiskScore])
async def predict_batch(request: BatchPredictionRequest):
    return [compute_prediction(alert) for alert in request.alerts]


@app.post("/explain")
async def explain(alert: VulnerabilityAlert):
    result = compute_prediction(alert)
    return {
        "alert_id": result.alert_id,
        "risk_score": result.risk_score,
        "recommendation": result.recommendation,
        "explanation": result.explanation,
    }


@app.get("/model-stats")
async def model_stats():
    return {
        "model_type": type(model).__name__ if model is not None else "heuristic_fallback",
        "feature_count": len(FEATURE_NAMES),
        "features": FEATURE_NAMES,
        "classes": ["true_positive", "false_positive"],
        "scaler_loaded": scaler is not None,
        "explainer_available": explainer is not None,
        "thresholds": {
            "false_positive_threshold": FALSE_POSITIVE_THRESHOLD,
            "block_risk_threshold": BLOCK_RISK_THRESHOLD,
            "review_risk_threshold": REVIEW_RISK_THRESHOLD,
        },
    }


@app.get("/")
async def root():
    return {
        "name": "Security AI Model API",
        "version": "1.1.0",
        "project": "PFE DevSecOps Pipeline",
        "endpoints": ["GET /health", "POST /predict", "POST /predict-batch", "POST /explain", "GET /model-stats", "GET /docs"],
    }
