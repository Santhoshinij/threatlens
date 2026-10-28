"""Train the two ThreatLens classifiers and save them to models/.

    python train_model.py
    python train_model.py --messages my_sms.csv --urls my_urls.csv

Message model : TF-IDF (word + character n-grams) -> Logistic Regression
URL model     : 22 lexical features             -> Random Forest
"""
import argparse
import json
import os

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix, f1_score
from sklearn.model_selection import train_test_split
from sklearn.pipeline import FeatureUnion, Pipeline

from features import URL_FEATURE_NAMES, extract_url_features

HERE = os.path.dirname(os.path.abspath(__file__))
MODEL_DIR = os.path.join(HERE, "models")


def evaluate(name, y_true, y_pred):
    cm = confusion_matrix(y_true, y_pred)
    print(f"\n=== {name} ===")
    print(classification_report(y_true, y_pred, target_names=["safe", "scam"], digits=3))
    print("Confusion matrix [[TN FP] [FN TP]]:\n", cm)
    return {
        "accuracy": round(float(accuracy_score(y_true, y_pred)), 4),
        "f1": round(float(f1_score(y_true, y_pred)), 4),
        "confusion_matrix": cm.tolist(),
        "test_size": int(len(y_true)),
    }


def train_messages(path):
    df = pd.read_csv(path).dropna().drop_duplicates(subset="text")
    X_tr, X_te, y_tr, y_te = train_test_split(
        df["text"], df["label"], test_size=0.2, stratify=df["label"], random_state=7
    )
    pipe = Pipeline([
        ("tfidf", FeatureUnion([
            ("word", TfidfVectorizer(ngram_range=(1, 2), lowercase=True, sublinear_tf=True, min_df=2)),
            ("char", TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5), sublinear_tf=True, min_df=3)),
        ])),
        ("clf", LogisticRegression(max_iter=2000, C=4.0, class_weight="balanced")),
    ])
    pipe.fit(X_tr, y_tr)
    metrics = evaluate("Message classifier", y_te, pipe.predict(X_te))
    joblib.dump(pipe, os.path.join(MODEL_DIR, "message_model.joblib"))
    return metrics


def train_urls(path):
    df = pd.read_csv(path).dropna().drop_duplicates(subset="url")
    X = np.array([extract_url_features(u) for u in df["url"]], dtype=float)
    y = df["label"].values
    X_tr, X_te, y_tr, y_te = train_test_split(X, y, test_size=0.2, stratify=y, random_state=7)
    clf = RandomForestClassifier(n_estimators=250, max_depth=14, min_samples_leaf=2,
                                 class_weight="balanced", random_state=7, n_jobs=-1)
    clf.fit(X_tr, y_tr)
    metrics = evaluate("URL classifier", y_te, clf.predict(X_te))
    ranked = sorted(zip(URL_FEATURE_NAMES, clf.feature_importances_), key=lambda p: -p[1])
    metrics["top_features"] = [(n, round(float(v), 4)) for n, v in ranked[:8]]
    print("\nTop URL features:", metrics["top_features"])
    joblib.dump(clf, os.path.join(MODEL_DIR, "url_model.joblib"))
    return metrics


def train_all(messages_csv=None, urls_csv=None):
    """Train both models and write models/metrics.json (also records the scikit-learn version)."""
    import sklearn
    messages_csv = messages_csv or os.path.join(HERE, "data", "messages.csv")
    urls_csv = urls_csv or os.path.join(HERE, "data", "urls.csv")
    os.makedirs(MODEL_DIR, exist_ok=True)
    report = {"sklearn_version": sklearn.__version__,
              "messages": train_messages(messages_csv), "urls": train_urls(urls_csv)}
    with open(os.path.join(MODEL_DIR, "metrics.json"), "w") as f:
        json.dump(report, f, indent=2)
    return report


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--messages", default=os.path.join(HERE, "data", "messages.csv"))
    ap.add_argument("--urls", default=os.path.join(HERE, "data", "urls.csv"))
    args = ap.parse_args()

    train_all(args.messages, args.urls)
    print("\nSaved models and metrics.json to", MODEL_DIR)
