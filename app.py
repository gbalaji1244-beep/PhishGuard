from flask import Flask, request, jsonify, render_template
from urllib.parse import urlparse
import re

app = Flask(__name__)


def analyze_url(url):
    score = 0
    reasons = []

    if not url.startswith("https://"):
        score += 20
        reasons.append("URL does not use HTTPS")

    if len(url) > 75:
        score += 15
        reasons.append("URL is unusually long")

    if "@" in url:
        score += 25
        reasons.append("URL contains @ symbol")

    parsed = urlparse(url)
    domain = parsed.netloc

    if re.match(r"^\d+\.\d+\.\d+\.\d+$", domain):
        score += 30
        reasons.append("URL uses an IP address")

    keywords = [
        "login", "verify", "account",
        "password", "update", "bank"
    ]

    for word in keywords:
        if word in url.lower():
            score += 5
            reasons.append(f"Suspicious keyword: {word}")

    if domain.count(".") > 3:
        score += 15
        reasons.append("Too many subdomains")

    score = min(score, 100)

    if score >= 60:
        risk = "HIGH RISK"
    elif score >= 30:
        risk = "SUSPICIOUS"
    else:
        risk = "SAFE"

    return {
        "url": url,
        "score": score,
        "risk": risk,
        "reasons": reasons
    }


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/api/analyze", methods=["POST"])
def analyze():
    data = request.get_json()
    url = data.get("url", "").strip()

    if not url:
        return jsonify({"error": "Please enter a URL"}), 400

    result = analyze_url(url)
    return jsonify(result)


if __name__ == "__main__":
    app.run(debug=True)