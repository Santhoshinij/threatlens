"""ThreatLens - Flask web app.

Run: python app.py
Then open http://127.0.0.1:5000

Submitted text is not stored by this application.
URLs are analysed as text; the app does not visit them.
"""
import json
import os
import time

import joblib
import numpy as np
from flask import Flask, jsonify, render_template, request

from features import (
    extract_url_features,
    find_urls,
    message_signals,
    normalize_url,
    url_signals,
)

BASE = os.path.dirname(os.path.abspath(__file__))
MODEL_DIR = os.path.join(BASE, "models")
MAX_MESSAGE = 5000
MAX_URL = 2048

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 64 * 1024

_models = {}
ASSET_VERSION = str(int(time.time()))


def _saved_sklearn_version():
    try:
        with open(os.path.join(MODEL_DIR, "metrics.json")) as f:
            return json.load(f).get("sklearn_version")
    except (OSError, ValueError):
        return None


def ensure_models():
    """Prepare models if missing or built with another sklearn version."""
    import sklearn

    model_files = ("message_model.joblib", "url_model.joblib")
    missing = not all(
        os.path.exists(os.path.join(MODEL_DIR, name))
        for name in model_files
    )

    if missing or _saved_sklearn_version() != sklearn.__version__:
        print(
            "ThreatLens: preparing models for scikit-learn",
            sklearn.__version__,
            "..."
        )
        import train_model
        train_model.train_all()
        print("ThreatLens: models ready.")


@app.context_processor
def inject_asset_version():
    return {"asset_v": ASSET_VERSION}


@app.after_request
def no_cache(resp):
    """Prevent browsers from reusing old pages or analysis responses."""
    if request.path == "/" or request.path.startswith(
        ("/api", "/check", "/result")
    ):
        resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate"
        resp.headers["Pragma"] = "no-cache"
        resp.headers["Expires"] = "0"
    return resp


def models():
    """Load the trained models once per server process."""
    if not _models:
        ensure_models()

        try:
            _models["message"] = joblib.load(
                os.path.join(MODEL_DIR, "message_model.joblib")
            )
            _models["url"] = joblib.load(
                os.path.join(MODEL_DIR, "url_model.joblib")
            )
        except FileNotFoundError as e:
            raise RuntimeError(
                "Models not found. Run `python train_model.py` first."
            ) from e

    return _models


def verdict_for(score: float, kind: str) -> dict:
    noun = "phishing link" if kind == "url" else "scam message"

    if score >= 0.65:
        return {
            "level": "danger",
            "label": f"Likely {noun}",
            "advice": [
                "Do not click, reply, or share any code or password.",
                "Contact the organisation using the number on its official "
                "website or card.",
                "Report it at cybercrime.gov.in or call 1930 in India.",
            ],
        }

    if score >= 0.35:
        return {
            "level": "warning",
            "label": "Suspicious",
            "advice": [
                "Treat this with caution until you can verify the sender.",
                "Do not enter personal or payment details.",
                "Check the claim through the official app or website, "
                "not through this message.",
            ],
        }

    return {
        "level": "safe",
        "label": "Likely safe",
        "advice": [
            "No strong warning signs were found, but no checker is perfect.",
            "Avoid sharing OTPs, PINs, or passwords with anyone who "
            "contacts you first.",
        ],
    }


def url_probability(url: str) -> float:
    """Get the URL model's scam probability."""
    features = np.array([extract_url_features(url)], dtype=float)
    probability = models()["url"].predict_proba(features)[0][1]
    return float(probability)


def hybrid_url_score(probability: float, signals) -> float:
    """Combine model probability with explicit URL warning signals."""
    severities = [signal[0] for signal in signals]
    titles = " ".join(signal[1] for signal in signals)

    # Explicit high-risk evidence, including a possible brand imitation,
    # must not be cancelled out by a low model prediction.
    if "high" in severities:
        probability = max(probability, 0.70)

    elif severities.count("medium") >= 2:
        probability = max(probability, 0.50)

    # A shortened link hides its destination but is not automatically a scam.
    if "Shortened link" in titles and "high" not in severities:
        probability = min(max(probability, 0.40), 0.60)

    # Do not force every URL without a rule signal into the safe category.
    # Let the trained model contribute its own probability.
    return max(0.0, min(float(probability), 1.0))


def hybrid_message_score(probability: float, signals) -> float:
    """Combine the message model with message and URL warning signals."""
    weights = {"high": 2.0, "medium": 1.0, "low": 0.25}
    points = sum(weights[signal[0]] for signal in signals)

    has_evidence = any(
        signal[0] in ("high", "medium") for signal in signals
    )

    if not has_evidence:
        return min(probability, 0.30)

    if points >= 4:
        return max(probability, 0.70)

    if points >= 2.5:
        return max(probability, 0.45)

    return probability


def pack_signals(signals):
    order = {"high": 0, "medium": 1, "low": 2}

    return [
        {"severity": severity, "title": title, "detail": detail}
        for severity, title, detail in sorted(
            signals, key=lambda signal: order[signal[0]]
        )
    ]


@app.get("/")
def home():
    return render_template("home.html", active="home")


@app.get("/check")
def check():
    return render_template("check.html", active="check")


@app.get("/result")
def result():
    # The browser fills in the result using the analysis response.
    return render_template("result.html", active="result")


@app.get("/api/health")
def health():
    import sklearn

    try:
        models()
        ok = True
    except RuntimeError:
        ok = False

    return jsonify(
        status="ok" if ok else "models_missing",
        sklearn=sklearn.__version__,
        models_built_with=_saved_sklearn_version(),
    )


@app.get("/api/metrics")
def metrics():
    path = os.path.join(MODEL_DIR, "metrics.json")

    if not os.path.exists(path):
        return jsonify({}), 404

    with open(path) as f:
        return jsonify(json.load(f))


@app.post("/api/analyze/message")
def analyze_message():
    data = request.get_json(silent=True) or {}
    text = (data.get("text") or "").strip()

    if not text:
        return jsonify(error="Paste a message to check."), 400

    if len(text) > MAX_MESSAGE:
        return jsonify(
            error=f"Message is too long. Limit is {MAX_MESSAGE} characters."
        ), 400

    message_probability = float(
        models()["message"].predict_proba([text])[0][1]
    )

    signals, highlights = message_signals(text)
    links = []

    for url in find_urls(text)[:5]:
        link_signals = url_signals(url)
        probability = hybrid_url_score(
            url_probability(url), link_signals
        )

        links.append({
            "url": url,
            "score": round(probability, 3),
        })

        for severity, title, detail in link_signals:
            signals.append((severity, f"Link: {title}", detail))

    if links:
        highest_link_score = max(link["score"] for link in links)

        score = max(
            0.60 * message_probability + 0.40 * highest_link_score,
            0.85 * highest_link_score,
        )
    else:
        score = message_probability

    score = hybrid_message_score(score, signals)

    return jsonify(
        kind="message",
        score=round(score, 3),
        message_score=round(message_probability, 3),
        verdict=verdict_for(score, "message"),
        signals=pack_signals(signals),
        highlights=[
            {"start": start, "end": end, "severity": severity}
            for start, end, severity in highlights
        ],
        links=links,
    )


@app.post("/api/analyze/url")
def analyze_url():
    data = request.get_json(silent=True) or {}
    raw_url = (data.get("url") or "").strip()

    if not raw_url:
        return jsonify(error="Enter a web address to check."), 400

    if len(raw_url) > MAX_URL or any(ch.isspace() for ch in raw_url):
        return jsonify(
            error="That doesn't look like a single web address."
        ), 400

    signals = url_signals(raw_url)
    probability = url_probability(raw_url)
    score = hybrid_url_score(probability, signals)

    return jsonify(
        kind="url",
        score=round(score, 3),
        url=normalize_url(raw_url),
        verdict=verdict_for(score, "url"),
        signals=pack_signals(signals),
    )


@app.errorhandler(RuntimeError)
def runtime_error(error):
    return jsonify(error=str(error)), 503


if __name__ == "__main__":
    # Disable Flask's automatic reloader unless explicitly requested.
    models()
    app.run(debug=os.environ.get("FLASK_DEBUG") == "1")