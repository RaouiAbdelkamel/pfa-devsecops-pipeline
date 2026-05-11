"""
Configuration de l'API AI pour le pipeline DevSecOps.
"""

import os
from dotenv import load_dotenv

load_dotenv()

# ============================================================================
# CONFIGURATION API
# ============================================================================

# Informations de l'application
APP_NAME = "Security AI Model API"
APP_VERSION = "1.0.0"
APP_DESCRIPTION = "API d'inférence pour le filtrage intelligent des faux positifs SAST/DAST/SCA"

# Mode debug
DEBUG = os.getenv("DEBUG", "False").lower() == "true"

# ============================================================================
# CONFIGURATION MODÈLE
# ============================================================================

# Chemins des fichiers
MODEL_DIR = os.path.join(os.path.dirname(__file__), "..", "model")
MODEL_PATH = os.path.join(MODEL_DIR, "model.pkl")
SCALER_PATH = os.path.join(MODEL_DIR, "scaler.pkl")
EXPLAINER_PATH = os.path.join(MODEL_DIR, "explainer.pkl")
METRICS_PATH = os.path.join(MODEL_DIR, "metrics.json")

# ============================================================================
# CONFIGURATION PRÉDICTION
# ============================================================================

# Seuils de décision
FALSE_POSITIVE_THRESHOLD = float(os.getenv("FP_THRESHOLD", "0.5"))
BLOCK_RISK_THRESHOLD = float(os.getenv("BLOCK_THRESHOLD", "0.8"))
REVIEW_RISK_THRESHOLD = float(os.getenv("REVIEW_THRESHOLD", "0.6"))

# Confiance minimale pour une décision
MIN_CONFIDENCE_THRESHOLD = float(os.getenv("MIN_CONFIDENCE", "0.5"))

# Délai d'inférence maximum (ms)
MAX_INFERENCE_TIME_MS = int(os.getenv("MAX_INFERENCE_TIME", "500"))

# ============================================================================
# CONFIGURATION LOGGING
# ============================================================================

LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")
LOG_FORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"

# ============================================================================
# CONFIGURATION CACHE
# ============================================================================

ENABLE_CACHE = os.getenv("ENABLE_CACHE", "True").lower() == "true"
CACHE_TTL_SECONDS = int(os.getenv("CACHE_TTL", "3600"))

# ============================================================================
# FEATURES ENGINEERING
# ============================================================================

FEATURE_NAMES = [
    "severity_level",           # 0: Low, 1: Medium, 2: High, 3: Critical
    "cvss_score",               # 0-10
    "cwe_id_confidence",        # 0-1
    "lines_of_code_affected",   # Nombre de lignes
    "function_complexity",      # Complexité cyclomatique
    "is_third_party_lib",       # 0 ou 1
    "has_test_coverage",        # 0 ou 1
    "file_age_days",            # Jours
    "number_of_contributors",   # Nombre
    "previous_similar_vulns"    # Compte
]

FEATURE_RANGES = {
    "severity_level": (0, 3),
    "cvss_score": (0, 10),
    "cwe_id_confidence": (0, 1),
    "lines_of_code_affected": (1, 1000),
    "function_complexity": (1, 50),
    "is_third_party_lib": (0, 1),
    "has_test_coverage": (0, 1),
    "file_age_days": (0, 3650),
    "number_of_contributors": (1, 100),
    "previous_similar_vulns": (0, 10)
}

# ============================================================================
# EXPLAINABILITY CONFIGURATION
# ============================================================================

# Générer les explications SHAP par défaut?
GENERATE_EXPLANATIONS_BY_DEFAULT = os.getenv("GEN_EXPLANATIONS", "True").lower() == "true"

# Nombre maximum de features à afficher dans l'explication
TOP_FEATURES_COUNT = int(os.getenv("TOP_FEATURES", "5"))

# ============================================================================
# PERFORMANCE TUNING
# ============================================================================

# Nombre de workers Uvicorn
WORKERS = int(os.getenv("WORKERS", "4"))

# Batch size pour le processing parallèle
BATCH_SIZE = int(os.getenv("BATCH_SIZE", "32"))

# Nombre de threads pour les opérations CPU-bound
NUM_THREADS = int(os.getenv("NUM_THREADS", "4"))
