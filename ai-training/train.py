"""
Entraînement du modèle IA de priorisation des vulnérabilités pour le PFE DevSecOps.

Objectif :
- classifier une alerte comme vrai positif ou faux positif probable ;
- calculer un score de risque exploitable par le pipeline CI/CD ;
- sauvegarder model.pkl, scaler.pkl, explainer.pkl et metrics.json.

Usage :
    cd ai-training
    python train.py --output ../ai-service/model --samples 1500
"""

import argparse
import json
import logging
import os
from datetime import datetime

import joblib
import numpy as np
import pandas as pd
import shap
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

FEATURE_NAMES = [
    "severity_level",          # 0=low, 1=medium, 2=high, 3=critical
    "cvss_score",              # 0-10
    "cwe_id_confidence",       # 0-1
    "lines_of_code_affected",  # nb lignes
    "function_complexity",     # complexité cyclomatique estimée
    "is_third_party_lib",      # 0/1
    "has_test_coverage",       # 0/1
    "file_age_days",           # ancienneté du fichier
    "number_of_contributors",  # nb contributeurs
    "previous_similar_vulns",  # historique d'alertes similaires
]

TARGET_NAMES = {
    0: "True Positive",
    1: "False Positive",
}


def generate_synthetic_dataset(n_samples: int = 1500, random_state: int = 42):
    """Génère un dataset synthétique cohérent avec un PFE DevSecOps."""
    rng = np.random.default_rng(random_state)
    X = np.zeros((n_samples, len(FEATURE_NAMES)), dtype=float)

    X[:, 0] = rng.integers(0, 4, n_samples)          # severity
    X[:, 1] = rng.uniform(0.5, 10.0, n_samples)      # CVSS
    X[:, 2] = rng.uniform(0.2, 1.0, n_samples)       # CWE confidence
    X[:, 3] = rng.integers(1, 120, n_samples)        # lines affected
    X[:, 4] = rng.integers(1, 15, n_samples)         # complexity
    X[:, 5] = rng.integers(0, 2, n_samples)          # third-party
    X[:, 6] = rng.integers(0, 2, n_samples)          # tests
    X[:, 7] = rng.integers(0, 730, n_samples)        # file age
    X[:, 8] = rng.integers(1, 25, n_samples)         # contributors
    X[:, 9] = rng.integers(0, 8, n_samples)          # previous vulns

    y = np.zeros(n_samples, dtype=int)

    for i in range(n_samples):
        fp_prob = 0.25

        # Les alertes critiques/high et CVSS élevé sont plus probablement des vrais positifs.
        if X[i, 0] >= 2:
            fp_prob -= 0.20
        if X[i, 1] >= 7:
            fp_prob -= 0.20
        if X[i, 2] >= 0.75:
            fp_prob -= 0.10
        if X[i, 9] >= 2:
            fp_prob -= 0.10

        # Les alertes low/medium, faible CVSS, code mature et couvert par tests sont plus souvent du bruit.
        if X[i, 0] <= 1:
            fp_prob += 0.15
        if X[i, 1] < 4:
            fp_prob += 0.25
        if X[i, 6] == 1:
            fp_prob += 0.10
        if X[i, 8] >= 10:
            fp_prob += 0.15
        if X[i, 7] >= 365:
            fp_prob += 0.08
        if X[i, 5] == 1:
            fp_prob += 0.08

        fp_prob += rng.uniform(-0.08, 0.08)
        fp_prob = float(np.clip(fp_prob, 0.03, 0.95))
        y[i] = 1 if rng.random() < fp_prob else 0

    return X, y


def load_dataset(filepath: str):
    df = pd.read_csv(filepath)
    missing = [c for c in FEATURE_NAMES + ["label"] if c not in df.columns]
    if missing:
        raise ValueError(f"Colonnes manquantes dans le dataset: {missing}")
    X = df[FEATURE_NAMES].astype(float).values
    y = df["label"].astype(int).values
    return X, y


def train_model(X, y, test_size=0.2, random_state=42):
    logger.info("Entraînement RandomForestClassifier...")

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=test_size, random_state=random_state, stratify=y
    )

    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    model = RandomForestClassifier(
        n_estimators=120,
        max_depth=12,
        min_samples_split=5,
        min_samples_leaf=2,
        class_weight="balanced",
        random_state=random_state,
        n_jobs=-1,
    )
    model.fit(X_train_scaled, y_train)

    y_pred = model.predict(X_test_scaled)
    y_proba = model.predict_proba(X_test_scaled)

    metrics = {
        "accuracy": float(np.mean(y_pred == y_test)),
        "roc_auc": float(roc_auc_score(y_test, y_proba[:, 1])),
        "classification_report": classification_report(y_test, y_pred, output_dict=True, zero_division=0),
        "confusion_matrix": confusion_matrix(y_test, y_pred).tolist(),
        "n_train_samples": int(len(X_train)),
        "n_test_samples": int(len(X_test)),
        "n_features": int(X.shape[1]),
        "feature_names": FEATURE_NAMES,
        "target_names": TARGET_NAMES,
        "training_date": datetime.now().isoformat(),
    }

    logger.info("Accuracy: %.4f", metrics["accuracy"])
    logger.info("ROC-AUC: %.4f", metrics["roc_auc"])
    logger.info("\n%s", classification_report(y_test, y_pred, target_names=list(TARGET_NAMES.values()), zero_division=0))

    return model, scaler, X_train_scaled, X_test_scaled, y_test, y_proba, metrics


def create_explainer(model, X_train_scaled):
    """Crée un explainer SHAP compatible avec RandomForest."""
    try:
        background = X_train_scaled[: min(200, len(X_train_scaled))]
        explainer = shap.TreeExplainer(model, data=background)
        logger.info("Explainer SHAP créé.")
        return explainer
    except Exception as exc:
        logger.warning("Explainer SHAP non créé: %s", exc)
        return None


def save_outputs(model, scaler, explainer, metrics, output_dir):
    os.makedirs(output_dir, exist_ok=True)

    model_path = os.path.join(output_dir, "model.pkl")
    scaler_path = os.path.join(output_dir, "scaler.pkl")
    metrics_path = os.path.join(output_dir, "metrics.json")

    joblib.dump(model, model_path)
    joblib.dump(scaler, scaler_path)

    if explainer is not None:
        joblib.dump(explainer, os.path.join(output_dir, "explainer.pkl"))

    metrics["feature_importance"] = dict(zip(FEATURE_NAMES, model.feature_importances_.astype(float).tolist()))
    with open(metrics_path, "w", encoding="utf-8") as f:
        json.dump(metrics, f, indent=2, ensure_ascii=False)

    logger.info("Modèle sauvegardé: %s", model_path)
    logger.info("Scaler sauvegardé: %s", scaler_path)
    logger.info("Métriques sauvegardées: %s", metrics_path)
    return model_path


def main():
    parser = argparse.ArgumentParser(description="Entraîner le modèle IA DevSecOps")
    parser.add_argument("--dataset", default=None, help="CSV réel optionnel")
    parser.add_argument("--output", default="../ai-service/model", help="Dossier de sortie")
    parser.add_argument("--samples", type=int, default=1500, help="Nb exemples synthétiques")
    args = parser.parse_args()

    if args.dataset and os.path.exists(args.dataset):
        logger.info("Chargement du dataset réel: %s", args.dataset)
        X, y = load_dataset(args.dataset)
    else:
        logger.info("Aucun dataset réel fourni: génération synthétique contrôlée.")
        X, y = generate_synthetic_dataset(args.samples)

    model, scaler, X_train_scaled, X_test_scaled, y_test, y_proba, metrics = train_model(X, y)
    explainer = create_explainer(model, X_train_scaled)
    model_path = save_outputs(model, scaler, explainer, metrics, args.output)

    fp_precision = metrics["classification_report"].get("1", {}).get("precision", 0)
    fp_recall = metrics["classification_report"].get("1", {}).get("recall", 0)

    logger.info("=" * 70)
    logger.info("ENTRAÎNEMENT TERMINÉ")
    logger.info("Modèle: %s", model_path)
    logger.info("Accuracy: %.4f | ROC-AUC: %.4f", metrics["accuracy"], metrics["roc_auc"])
    logger.info("Détection FP - precision: %.4f | recall: %.4f", fp_precision, fp_recall)
    logger.info("Réduction estimée des faux positifs: objectif projet >= 30%%")
    logger.info("=" * 70)


if __name__ == "__main__":
    main()
