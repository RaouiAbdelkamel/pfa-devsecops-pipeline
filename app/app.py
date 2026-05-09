from flask import Flask, request
import sqlite3
import os
import subprocess

app = Flask(__name__)

@app.route("/")
def home():
    return "Application vulnérable - PFE DevSecOps"

@app.route("/login")
def login():
    username = request.args.get("username", "")
    password = request.args.get("password", "")

    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()

    # Vulnérabilité SQL Injection volontaire
    query = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'"
    cursor.execute(query)

    result = cursor.fetchall()
    conn.close()

    return {"result": str(result)}

@app.route("/ping")
def ping():
    host = request.args.get("host", "127.0.0.1")

    # Vulnérabilité Command Injection volontaire
    output = subprocess.check_output("ping -n 1 " + host, shell=True)

    return output.decode(errors="ignore")

@app.route("/secret")
def secret():
    # Secret volontairement vulnérable pour démonstration
    api_key = "AWS_SECRET_ACCESS_KEY_DEMO_123456789"
    return {"api_key": api_key}

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
