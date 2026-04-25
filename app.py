
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
import re
import os

app = Flask(__name__)
CORS(app)

def simple_model(text):
    score = 0

    scam_keywords = ["payment", "fee", "urgent", "limited seats", "earn money", "guaranteed"]
    email_pattern = r"[^@]+@[^@]+\.[^@]+"

    for word in scam_keywords:
        if word in text.lower():
            score += 15

    # Fake email detection
    emails = re.findall(email_pattern, text)
    for email in emails:
        if "gmail.com" not in email and "yahoo.com" not in email:
            score += 20

    if score > 60:
        risk = "HIGH"
    elif score > 30:
        risk = "MEDIUM"
    else:
        risk = "LOW"

    return risk, score

@app.route("/")
def index():
    return send_from_directory(".", "index.html")

@app.route("/index.html")
def index_html():
    return send_from_directory(".", "index.html")

@app.route("/analyze", methods=["POST"])
def analyze():
    data = request.json
    text = data.get("message", "")

    risk, score = simple_model(text)

    return jsonify({
        "risk": risk,
        "score": score
    })

if __name__ == "__main__":
    app.run(debug=True)
