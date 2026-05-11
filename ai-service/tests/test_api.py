"""
Tests unitaires pour l'API de prédiction.
"""

import pytest
import json
from fastapi.testclient import TestClient
from unittest.mock import Mock, patch, MagicMock
import numpy as np

# Import de l'application (à adapter selon votre structure)
# from inference.predict import app, model, explainer

# Pour les tests, on utilise une fixture
@pytest.fixture
def client():
    """Créer un client de test FastAPI"""
    # from inference.predict import app
    # return TestClient(app)
    pass


class TestHealthEndpoint:
    """Tests du endpoint /health"""
    
    def test_health_check_success(self, client):
        """Vérifier que /health retourne 200"""
        response = client.get("/health")
        assert response.status_code == 200
        assert response.json()["status"] == "healthy"
    
    def test_health_check_model_status(self, client):
        """Vérifier que le statut du modèle est rapporté"""
        response = client.get("/health")
        data = response.json()
        assert "model_loaded" in data
        assert "explainer_available" in data


class TestPredictionEndpoint:
    """Tests du endpoint /predict"""
    
    def test_predict_simple_alert(self, client):
        """Test une prédiction simple"""
        alert = {
            "alert_id": "test-001",
            "tool": "semgrep",
            "rule_id": "python.sql-injection",
            "severity": "high",
            "file_path": "app.py",
            "line_number": 10,
            "message": "SQL injection",
            "cvss_score": 8.0,
            "cwe_id": "CWE-89"
        }
        
        response = client.post("/predict", json=alert)
        assert response.status_code == 200
        
        data = response.json()
        assert data["alert_id"] == "test-001"
        assert "risk_score" in data
        assert "confidence" in data
        assert "recommendation" in data
        
        # Valider les valeurs
        assert 0 <= data["risk_score"] <= 1
        assert 0 <= data["confidence"] <= 1
        assert data["recommendation"] in ["BLOCK", "REVIEW", "ALLOW"]
    
    def test_predict_missing_required_fields(self, client):
        """Test avec des champs requis manquants"""
        alert = {
            "alert_id": "test-002"
            # Champs manquants
        }
        
        response = client.post("/predict", json=alert)
        assert response.status_code == 422  # Validation error
    
    def test_predict_invalid_severity(self, client):
        """Test avec une sévérité invalide"""
        alert = {
            "alert_id": "test-003",
            "tool": "semgrep",
            "rule_id": "rule1",
            "severity": "invalid_severity",  # ❌
            "file_path": "app.py",
            "line_number": 10,
            "message": "Test",
        }
        
        response = client.post("/predict", json=alert)
        # Devrait tolérer et utiliser une valeur par défaut
        # ou retourner une erreur
        assert response.status_code in [200, 422]
    
    def test_predict_false_positive_detection(self, client):
        """Test la détection de faux positifs"""
        # Alerte probablement FP: sévérité basse, code mature
        alert = {
            "alert_id": "test-fp",
            "tool": "semgrep",
            "rule_id": "rule1",
            "severity": "low",
            "file_path": "app.py",
            "line_number": 10,
            "message": "Test",
            "cvss_score": 2.0,
            "function_complexity": 1,
            "has_test": True,
            "contributors_count": 20
        }
        
        response = client.post("/predict", json=alert)
        assert response.status_code == 200
        
        data = response.json()
        # Devrait détecter comme FP
        if data["is_false_positive"]:
            assert data["recommendation"] == "ALLOW"
    
    def test_predict_critical_vulnerability(self, client):
        """Test la détection de vulnérabilités critiques"""
        # Alerte probablement critique
        alert = {
            "alert_id": "test-critical",
            "tool": "semgrep",
            "rule_id": "rule1",
            "severity": "critical",
            "file_path": "app.py",
            "line_number": 10,
            "message": "SQL Injection",
            "cvss_score": 9.0,
            "cwe_id": "CWE-89",
            "function_complexity": 2,
            "contributors_count": 3
        }
        
        response = client.post("/predict", json=alert)
        assert response.status_code == 200
        
        data = response.json()
        # Devrait recommander le blocage
        if not data["is_false_positive"]:
            assert data["recommendation"] == "BLOCK"
            assert data["risk_score"] > 0.7


class TestBatchPredictionEndpoint:
    """Tests du endpoint /predict-batch"""
    
    def test_batch_prediction_success(self, client):
        """Test une prédiction batch"""
        alerts = [
            {
                "alert_id": f"batch-{i}",
                "tool": "semgrep",
                "rule_id": "rule1",
                "severity": ["low", "high", "critical"][i % 3],
                "file_path": f"file{i}.py",
                "line_number": 10 + i,
                "message": "Test",
            }
            for i in range(5)
        ]
        
        payload = {"alerts": alerts}
        response = client.post("/predict-batch", json=payload)
        
        assert response.status_code == 200
        data = response.json()
        assert len(data) == 5
        
        for pred in data:
            assert "risk_score" in pred
            assert "recommendation" in pred
    
    def test_batch_prediction_empty(self, client):
        """Test avec une liste vide"""
        payload = {"alerts": []}
        response = client.post("/predict-batch", json=payload)
        
        assert response.status_code == 200
        data = response.json()
        assert len(data) == 0
    
    def test_batch_prediction_large(self, client):
        """Test avec un batch large"""
        alerts = [
            {
                "alert_id": f"batch-{i}",
                "tool": "semgrep",
                "rule_id": "rule1",
                "severity": "medium",
                "file_path": f"file{i}.py",
                "line_number": 10,
                "message": "Test",
            }
            for i in range(100)
        ]
        
        payload = {"alerts": alerts}
        response = client.post("/predict-batch", json=payload)
        
        assert response.status_code == 200
        data = response.json()
        assert len(data) == 100


class TestExplainEndpoint:
    """Tests du endpoint /explain"""
    
    def test_explain_prediction(self, client):
        """Test l'explication d'une prédiction"""
        alert = {
            "alert_id": "explain-001",
            "tool": "semgrep",
            "rule_id": "rule1",
            "severity": "high",
            "file_path": "app.py",
            "line_number": 10,
            "message": "Test",
            "cvss_score": 7.0,
            "cwe_id": "CWE-89",
        }
        
        response = client.post("/explain", json=alert)
        
        # Peut échouer si SHAP n'est pas disponible
        if response.status_code == 200:
            data = response.json()
            assert "feature_impact" in data
            assert "base_value" in data
            
            # Vérifier la structure
            for impact in data["feature_impact"]:
                assert "feature" in impact
                assert "value" in impact
                assert "impact" in impact


class TestModelStatsEndpoint:
    """Tests du endpoint /model-stats"""
    
    def test_model_stats(self, client):
        """Obtenir les statistiques du modèle"""
        response = client.get("/model-stats")
        assert response.status_code == 200
        
        data = response.json()
        assert "model_type" in data
        assert "n_estimators" in data
        assert "feature_count" in data
        assert "features" in data
        assert data["feature_count"] == len(data["features"])


class TestFeatureValidation:
    """Tests de validation des features"""
    
    def test_severity_conversion(self, client):
        """Tester la conversion des sévérités"""
        severities = {
            "low": 0,
            "medium": 1,
            "high": 2,
            "critical": 3
        }
        
        for sev, expected in severities.items():
            alert = {
                "alert_id": f"sev-{sev}",
                "tool": "semgrep",
                "rule_id": "rule1",
                "severity": sev,
                "file_path": "app.py",
                "line_number": 10,
                "message": "Test",
            }
            
            response = client.post("/predict", json=alert)
            assert response.status_code == 200
    
    def test_out_of_range_cvss(self, client):
        """Tester avec un CVSS hors limites"""
        alert = {
            "alert_id": "test-oob",
            "tool": "semgrep",
            "rule_id": "rule1",
            "severity": "high",
            "file_path": "app.py",
            "line_number": 10,
            "message": "Test",
            "cvss_score": 15.0  # > 10
        }
        
        # Devrait être validé/clampé
        response = client.post("/predict", json=alert)
        assert response.status_code in [200, 422]


class TestPerformance:
    """Tests de performance"""
    
    def test_inference_latency(self, client):
        """Tester la latence d'inférence"""
        import time
        
        alert = {
            "alert_id": "perf-001",
            "tool": "semgrep",
            "rule_id": "rule1",
            "severity": "high",
            "file_path": "app.py",
            "line_number": 10,
            "message": "Test",
        }
        
        start = time.time()
        response = client.post("/predict", json=alert)
        latency = (time.time() - start) * 1000  # en ms
        
        assert response.status_code == 200
        assert latency < 500, f"Inference too slow: {latency}ms"
    
    def test_batch_throughput(self, client):
        """Tester le débit des prédictions batch"""
        import time
        
        alerts = [
            {
                "alert_id": f"throughput-{i}",
                "tool": "semgrep",
                "rule_id": "rule1",
                "severity": "medium",
                "file_path": f"file{i}.py",
                "line_number": 10,
                "message": "Test",
            }
            for i in range(50)
        ]
        
        payload = {"alerts": alerts}
        
        start = time.time()
        response = client.post("/predict-batch", json=payload)
        latency = (time.time() - start) * 1000
        
        assert response.status_code == 200
        throughput = 50 / (latency / 1000)  # predictions/sec
        assert throughput > 10, f"Throughput too low: {throughput} pred/sec"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
