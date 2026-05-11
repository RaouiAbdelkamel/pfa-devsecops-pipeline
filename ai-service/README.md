# AI Security Model - Documentation

## Structure du projet

```
ai-service/           # Service d'inférence (API FastAPI)
├── Dockerfile        # Image Docker du service
├── requirements.txt  # Dépendances Python
├── model/
│   ├── model.pkl     # Modèle Random Forest (généré après entraînement)
│   ├── scaler.pkl    # StandardScaler (généré après entraînement)
│   ├── explainer.pkl # SHAP Explainer (généré après entraînement)
│   └── metrics.json  # Métriques du modèle
└── inference/
    └── predict.py    # API FastAPI pour l'inférence

ai-training/         # Script d'entraînement
├── requirements.txt  # Dépendances d'entraînement
└── train.py         # Script d'entraînement du modèle
```

## Installation & Configuration

### 1. Entraîner le modèle

#### Option A : Dataset synthétique (par défaut)
```bash
cd ai-training/
pip install -r requirements.txt
python train.py --samples 1000 --output ../ai-service/model
```

#### Option B : Utiliser un dataset réel (CSV)
```bash
python train.py --dataset vulnerabilities.csv --output ../ai-service/model
```

Format du CSV attendu:
```csv
severity_level,cvss_score,cwe_id_confidence,lines_of_code_affected,function_complexity,is_third_party_lib,has_test_coverage,file_age_days,number_of_contributors,previous_similar_vulns,label
2,5.5,0.8,10,5,0,1,30,3,0,0
3,8.2,0.9,25,8,1,0,15,5,2,1
```

**Label:**
- `0` = True Positive (vulnérabilité réelle)
- `1` = False Positive (faux positif)

### 2. Démarrer l'API d'inférence

#### Localement
```bash
cd ai-service/
pip install -r requirements.txt
python -m uvicorn inference.predict:app --reload --port 8000
```

#### Avec Docker
```bash
cd ai-service/
docker build -t security-ai-api:latest .
docker run -p 8000:8000 security-ai-api:latest
```

#### Avec Docker Compose (depuis le root du projet)
```bash
docker-compose up -d ai-service
```

## Utilisation de l'API

### 1. Prédiction simple

**Endpoint:** `POST /predict`

```bash
curl -X POST "http://localhost:8000/predict" \
  -H "Content-Type: application/json" \
  -d '{
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
    "is_third_party": false,
    "has_test": true,
    "file_age_days": 30,
    "contributors_count": 5,
    "similar_vulns_count": 1
  }'
```

**Réponse:**
```json
{
  "alert_id": "semgrep-001",
  "is_false_positive": false,
  "risk_score": 0.85,
  "confidence": 0.92,
  "recommendation": "BLOCK",
  "explanation": {
    "method": "SHAP",
    "base_value": 0.45,
    "feature_importance": {
      "severity_level": 0.25,
      "cvss_score": 0.20,
      "cwe_id_confidence": 0.15,
      ...
    },
    "top_features": [
      ["severity_level", 0.25],
      ["cvss_score", 0.20],
      ["cwe_id_confidence", 0.15]
    ]
  }
}
```

### 2. Prédiction en batch

**Endpoint:** `POST /predict-batch`

```bash
curl -X POST "http://localhost:8000/predict-batch" \
  -H "Content-Type: application/json" \
  -d '{
    "alerts": [
      { "alert_id": "alert-1", ... },
      { "alert_id": "alert-2", ... },
      { "alert_id": "alert-3", ... }
    ]
  }'
```

### 3. Expliquer une prédiction

**Endpoint:** `POST /explain`

Retourne une explication détaillée SHAP avec l'impact de chaque feature.

### 4. Statistiques du modèle

**Endpoint:** `GET /model-stats`

```bash
curl http://localhost:8000/model-stats
```

```json
{
  "model_type": "RandomForestClassifier",
  "n_estimators": 100,
  "feature_count": 10,
  "features": ["severity_level", "cvss_score", ...],
  "explainer_available": true
}
```

### 5. Health Check

**Endpoint:** `GET /health`

```bash
curl http://localhost:8000/health
```

## Intégration dans le pipeline CI/CD

### Exemple GitHub Actions

```yaml
- name: Run AI Filter
  run: |
    # Exécuter les scans (SAST, SCA, DAST)
    # Récupérer les résultats JSON
    
    # Appeler l'API AI pour chaque alerte
    curl -X POST "http://localhost:8000/predict-batch" \
      -H "Content-Type: application/json" \
      -d @scan_results.json > ai_filtered_results.json
    
    # Parser les résultats et bloquer si BLOCK recommendations
    python scripts/check_ai_results.py ai_filtered_results.json
```

## Architecture du modèle

### Model: Random Forest

- **Estimateurs:** 100 arbres de décision
- **Profondeur max:** 15
- **Class Weight:** Balanced (gère le déséquilibre)
- **Features:** 10 features d'entrée

### Features d'entrée

1. **severity_level** (0-3): Low, Medium, High, Critical
2. **cvss_score** (0-10): Score CVSS v3.1
3. **cwe_id_confidence** (0-1): Confiance de la classification CWE
4. **lines_of_code_affected** (1-∞): Nombre de lignes affectées
5. **function_complexity** (1-∞): Complexité cyclomatique
6. **is_third_party_lib** (0/1): Dépendance externe?
7. **has_test_coverage** (0/1): Code testé?
8. **file_age_days** (0-∞): Ancienneté du fichier
9. **number_of_contributors** (1-∞): Nombre de contributeurs
10. **previous_similar_vulns** (0-∞): Vulnérabilités antérieures similaires

### Explainability: SHAP

- **TreeExplainer:** Fast estimation pour Random Forest
- **Feature Impact:** Montre comment chaque feature affecte la prédiction
- **LIME Fallback:** Alternative si SHAP indisponible

## Optimisation & Performance

### Réduction des faux positifs

**Résultats attendus:**
- Réduction: ~35% des faux positifs
- Precision: >90% pour les vrais positifs
- Recall: >85% pour détecter les vrais positifs

### Latence d'inférence

- **Single prediction:** <100ms
- **Batch (100 alertes):** <500ms
- **Avec SHAP explanation:** <200ms

### Optimisations

1. **Normalisation:** StandardScaler sur features numériques
2. **Parallélisation:** `n_jobs=-1` pendant l'entraînement
3. **Caching:** Modèle chargé une fois au démarrage
4. **Lazy SHAP:** Explications générées à la demande

## Monitoring & Maintenance

### Métriques de suivi

- **Accuracy:** Proportion de prédictions correctes
- **ROC-AUC:** Performance globale (0-1, 1=parfait)
- **Confusion Matrix:** TP, TN, FP, FN
- **Feature Importance:** Quelles features sont les plus influentes

### Re-entraînement

Quand ré-entraîner le modèle:
- Tous les mois avec nouvelles données
- Après changement d'outils (nouvelles règles Semgrep, etc.)
- Si dégradation des performances >5%

## Troubleshooting

### Erreur: "Modèle non disponible"
- Lancer `python ai-training/train.py` d'abord
- Vérifier que `model.pkl` existe dans `ai-service/model/`

### Prédictions incorrectes
- Vérifier les features d'entrée (range valide)
- Ré-entraîner avec dataset plus représentatif
- Ajuster les seuils dans `predict.py` (ligne ~120)

### Performance lente
- Réduire `n_samples` pendant l'entraînement
- Désactiver SHAP pour la latence (<100ms)
- Utiliser batch prediction au lieu de single

## Références

- [scikit-learn Random Forest](https://scikit-learn.org/stable/modules/generated/sklearn.ensemble.RandomForestClassifier.html)
- [SHAP Documentation](https://shap.readthedocs.io/)
- [FastAPI Documentation](https://fastapi.tiangolo.com/)
- [OWASP CWE List](https://cwe.mitre.org/)
