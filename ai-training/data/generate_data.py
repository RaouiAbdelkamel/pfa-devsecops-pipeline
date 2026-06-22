import json
import random

random.seed(42)

RULES = [
    {"id": "python.lang.security.audit.dangerous-subprocess-use", "category": "injection", "fp_rate": 0.15},
    {"id": "python.flask.security.xss.audit.direct-use-of-jinja2", "category": "xss", "fp_rate": 0.20},
    {"id": "python.lang.security.audit.sqli.sqlalchemy-execute-raw", "category": "sqli", "fp_rate": 0.10},
    {"id": "python.lang.security.insecure-hash-algorithms.md5", "category": "crypto", "fp_rate": 0.60},
    {"id": "python.lang.security.insecure-hash-algorithms.sha1", "category": "crypto", "fp_rate": 0.55},
    {"id": "python.lang.security.audit.hardcoded-password", "category": "secrets", "fp_rate": 0.30},
    {"id": "python.flask.security.insecure-deserialization", "category": "deserialization", "fp_rate": 0.12},
    {"id": "python.lang.correctness.useless-eqeq", "category": "correctness", "fp_rate": 0.85},
    {"id": "python.lang.security.audit.exec-detected", "category": "injection", "fp_rate": 0.25},
    {"id": "python.lang.security.audit.formatted-sql-query", "category": "sqli", "fp_rate": 0.08},
    {"id": "custom.juice-shop.missing-auth-check", "category": "auth", "fp_rate": 0.05},
    {"id": "custom.juice-shop.exposed-admin-route", "category": "auth", "fp_rate": 0.10},
    {"id": "custom.juice-shop.unsafe-redirect", "category": "redirect", "fp_rate": 0.20},
]

SEVERITIES = ["ERROR", "WARNING", "INFO"]
CONFIDENCES = ["HIGH", "MEDIUM", "LOW"]
FILES = [
    "app/routes/user.py", "app/routes/admin.py", "app/models/db.py",
    "app/utils/crypto.py", "app/api/auth.py", "app/services/payment.py",
    "app/helpers/sanitize.py", "tests/test_auth.py",
]

def generate_alert(rule):
    severity = random.choices(SEVERITIES, weights=[0.3, 0.5, 0.2])[0]
    confidence = random.choices(CONFIDENCES, weights=[0.4, 0.4, 0.2])[0]
    start_line = random.randint(10, 300)
    end_line = start_line + random.randint(1, 10)
    filepath = random.choice(FILES)
    in_test = "test" in filepath

    base_score = 1.0 - rule["fp_rate"]
    if severity == "ERROR": base_score += 0.15
    if severity == "INFO": base_score -= 0.20
    if confidence == "HIGH": base_score += 0.10
    if confidence == "LOW": base_score -= 0.15
    if in_test: base_score -= 0.25
    if rule["category"] in ("injection", "sqli", "auth"): base_score += 0.10
    base_score = max(0.05, min(0.98, base_score))
    label = 1 if random.random() < base_score else 0

    return {
        "check_id": rule["id"],
        "category": rule["category"],
        "path": filepath,
        "start": {"line": start_line, "col": random.randint(1, 40)},
        "end": {"line": end_line, "col": random.randint(1, 80)},
        "extra": {
            "severity": severity,
            "message": f"Potential {rule['category']} vulnerability at line {start_line}",
            "metadata": {
                "confidence": confidence,
                "cwe": f"CWE-{random.choice([78, 79, 89, 327, 330, 601])}",
                "fix": "Use parameterized queries" if rule["category"] == "sqli" else None,
            },
        },
        "label": label,
    }

alerts = []
for _ in range(220):
    rule = random.choice(RULES)
    alerts.append(generate_alert(rule))

vp = [a for a in alerts if a["label"] == 1]
fp = [a for a in alerts if a["label"] == 0]
print(f"Vrais positifs : {len(vp)}")
print(f"Faux positifs  : {len(fp)}")
print(f"Total          : {len(alerts)}")

with open("labeled_alerts.json", "w", encoding="utf-8") as f:
    json.dump(alerts, f, indent=2, ensure_ascii=False)

print("Dataset genere : labeled_alerts.json")
