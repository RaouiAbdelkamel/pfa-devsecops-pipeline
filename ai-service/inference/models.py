"""
Modèle de données et classes pour l'API AI de sécurité.
"""

from enum import Enum
from typing import Optional, Dict, Any, List
from dataclasses import dataclass, asdict
from pydantic import BaseModel, Field


class SeverityLevel(str, Enum):
    """Niveaux de sévérité"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class SecurityTool(str, Enum):
    """Outils de sécurité supportés"""
    SEMGREP = "semgrep"
    SONARQUBE = "sonarqube"
    SNYK = "snyk"
    TRIVY = "trivy"
    ZAPPROXY = "zapproxy"


class Recommendation(str, Enum):
    """Recommandations du modèle IA"""
    BLOCK = "BLOCK"  # Bloquer le déploiement
    REVIEW = "REVIEW"  # Examiner manuellement
    ALLOW = "ALLOW"  # Autoriser


# ============================================================================
# MODÈLES PYDANTIC POUR VALIDATION ET DOCUMENTATION
# ============================================================================

class VulnerabilityAlert(BaseModel):
    """
    Alerte de vulnérabilité d'un scanner de sécurité.
    
    Attributs:
        alert_id: Identifiant unique de l'alerte
        tool: Outil qui a généré l'alerte
        rule_id: ID de la règle/CVE
        severity: Niveau de sévérité (low, medium, high, critical)
        file_path: Chemin du fichier vulnérable
        line_number: Numéro de ligne
        message: Description de la vulnérabilité
        cvss_score: Score CVSS v3.1 (0-10)
        cwe_id: Identifiant CWE
    """
    alert_id: str = Field(..., description="Identifiant unique de l'alerte")
    tool: str = Field(..., description="Outil de sécurité (semgrep, snyk, etc.)")
    rule_id: str = Field(..., description="ID de la règle ou CVE")
    severity: str = Field(..., description="Sévérité: low, medium, high, critical")
    file_path: str = Field(..., description="Chemin du fichier vulnérable")
    line_number: int = Field(..., ge=1, description="Numéro de ligne")
    message: str = Field(..., description="Description de la vulnérabilité")
    cvss_score: Optional[float] = Field(
        default=5.0, 
        ge=0, 
        le=10,
        description="Score CVSS (0-10)"
    )
    cwe_id: Optional[str] = Field(
        default=None, 
        description="CWE ID (ex: CWE-89)"
    )
    
    # Features additionnels pour améliorer la prédiction
    lines_affected: Optional[int] = Field(
        default=1, 
        ge=1,
        description="Nombre de lignes affectées"
    )
    function_complexity: Optional[int] = Field(
        default=1, 
        ge=1,
        description="Complexité cyclomatique"
    )
    is_third_party: Optional[bool] = Field(
        default=False, 
        description="Est une dépendance externe?"
    )
    has_test: Optional[bool] = Field(
        default=False, 
        description="Fichier couvert par des tests?"
    )
    file_age_days: Optional[int] = Field(
        default=30, 
        ge=0,
        description="Âge du fichier en jours"
    )
    contributors_count: Optional[int] = Field(
        default=1, 
        ge=1,
        description="Nombre de contributeurs"
    )
    similar_vulns_count: Optional[int] = Field(
        default=0, 
        ge=0,
        description="Vulnérabilités antérieures similaires"
    )

    class Config:
        schema_extra = {
            "example": {
                "alert_id": "semgrep-001",
                "tool": "semgrep",
                "rule_id": "python.lang.security.injection.sql",
                "severity": "high",
                "file_path": "app/models.py",
                "line_number": 45,
                "message": "Potential SQL injection",
                "cvss_score": 8.2,
                "cwe_id": "CWE-89",
                "lines_affected": 15,
                "function_complexity": 7,
                "is_third_party": False,
                "has_test": True,
                "file_age_days": 30,
                "contributors_count": 5,
                "similar_vulns_count": 1
            }
        }


class RiskScore(BaseModel):
    """
    Résultat de la prédiction du modèle IA.
    
    Attributs:
        alert_id: ID de l'alerte originale
        is_false_positive: True si probablement un faux positif
        risk_score: Score de risque (0-1, où 1=très critique)
        confidence: Confiance du modèle (0-1)
        recommendation: Action recommandée (BLOCK, REVIEW, ALLOW)
        explanation: Explication SHAP (optionnel)
    """
    alert_id: str = Field(..., description="ID de l'alerte")
    is_false_positive: bool = Field(..., description="Est un faux positif?")
    risk_score: float = Field(
        ..., 
        ge=0, 
        le=1,
        description="Score de risque (0=très faible, 1=critique)"
    )
    confidence: float = Field(
        ..., 
        ge=0, 
        le=1,
        description="Confiance du modèle (0-1)"
    )
    recommendation: str = Field(
        ..., 
        description="Recommandation (BLOCK, REVIEW, ALLOW)"
    )
    explanation: Optional[Dict[str, Any]] = Field(
        default=None, 
        description="Explication SHAP détaillée"
    )

    class Config:
        schema_extra = {
            "example": {
                "alert_id": "semgrep-001",
                "is_false_positive": False,
                "risk_score": 0.85,
                "confidence": 0.92,
                "recommendation": "BLOCK",
                "explanation": {
                    "method": "SHAP",
                    "base_value": 0.45,
                    "feature_importance": {
                        "severity_level": 0.25,
                        "cvss_score": 0.20
                    }
                }
            }
        }


class BatchPredictionRequest(BaseModel):
    """Requête de prédiction batch"""
    alerts: List[VulnerabilityAlert] = Field(
        ..., 
        description="Liste des alertes à traiter"
    )


class ModelStats(BaseModel):
    """Statistiques du modèle"""
    model_type: str
    n_estimators: int
    feature_count: int
    features: List[str]
    classes: List[int]
    explainer_available: bool


class HealthStatus(BaseModel):
    """Statut de santé de l'API"""
    status: str
    model_loaded: bool
    explainer_available: bool


# ============================================================================
# DATA CLASSES POUR USAGE INTERNE
# ============================================================================

@dataclass
class ModelMetrics:
    """Métriques de performance du modèle"""
    accuracy: float
    roc_auc: float
    precision: float
    recall: float
    f1_score: float
    false_positive_rate: float
    
    def to_dict(self) -> Dict[str, float]:
        return asdict(self)


@dataclass
class TrainingConfig:
    """Configuration d'entraînement"""
    n_estimators: int = 100
    max_depth: int = 15
    min_samples_split: int = 5
    min_samples_leaf: int = 2
    test_size: float = 0.2
    random_state: int = 42
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
