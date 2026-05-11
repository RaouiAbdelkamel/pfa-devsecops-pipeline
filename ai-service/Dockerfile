FROM python:3.11-slim

WORKDIR /app

# Installer les dépendances système nécessaires pour scikit-learn et SHAP
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copier les requirements et installer les dépendances
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copier le code et le modèle
COPY inference/ ./inference/
COPY model/ ./model/

# Exposer le port
EXPOSE 8000

# Lancer l'API FastAPI
CMD ["uvicorn", "inference.predict:app", "--host", "0.0.0.0", "--port", "8000"]
