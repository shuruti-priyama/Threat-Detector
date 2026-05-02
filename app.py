import os
import re
import numpy as np
import pandas as pd

from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS

from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.cluster import KMeans

# ──────────────────────────────────────────────
# App Setup
# ──────────────────────────────────────────────
app = Flask(__name__)
CORS(app)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# ──────────────────────────────────────────────
# Helper - Find CSV Files
# ──────────────────────────────────────────────
def find_csv(filename):
    """Look for a CSV next to this script, or in Downloads as a fallback."""
    local_path = os.path.join(BASE_DIR, filename)
    if os.path.exists(local_path):
        return local_path
    downloads = os.path.join(os.path.expanduser("~"), "Downloads", filename)
    if os.path.exists(downloads):
        return downloads
    raise FileNotFoundError(
        f"Cannot find '{filename}'. Place it in the same folder as app.py."
    )

# ──────────────────────────────────────────────
# Part 1 - URL Classifier
# ──────────────────────────────────────────────
print("Loading URL dataset ...")
try:
    df_urls = pd.read_csv(find_csv("malicious_phish.csv")).head(400)

    vectorizer_url = TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5))
    X_url = vectorizer_url.fit_transform(df_urls["url"])

    le_url = LabelEncoder()
    y_url = le_url.fit_transform(df_urls["type"])

    X_train, X_test, y_train, y_test = train_test_split(
        X_url, y_url, test_size=0.2, random_state=42, stratify=y_url
    )

    clf_url = RandomForestClassifier(n_estimators=100, random_state=42)
    clf_url.fit(X_train, y_train)

    URL_MODEL_READY = True
    print("✅ URL classifier trained.")

except FileNotFoundError as e:
    print(f"⚠️  URL model skipped: {e}")
    URL_MODEL_READY = False

def map_to_binary(label):
    return "benign" if label.lower() == "benign" else "malicious"

# ──────────────────────────────────────────────
# Part 2 - Email Clustering & Threat Detection
# ──────────────────────────────────────────────
print("Loading email dataset ...")
try:
    df_emails = pd.read_csv(find_csv("email.csv"))
    email_texts = df_emails["Message"].fillna("")

    vectorizer_email = TfidfVectorizer(stop_words="english", max_features=1000)
    X_email = vectorizer_email.fit_transform(email_texts)

    kmeans = KMeans(n_clusters=2, random_state=42, n_init="auto")
    cluster_labels = kmeans.fit_predict(X_email)
    df_emails["cluster"] = cluster_labels

    # Find which cluster is malicious-like
    terms = np.array(vectorizer_email.get_feature_names_out())
    malicious_terms = {"win", "prize", "click", "free", "offer", "money", "password", "account"}
    cluster_keywords = {}

    for c in np.unique(cluster_labels):
        center = X_email[cluster_labels == c].mean(axis=0)
        idxs = np.argsort(np.asarray(center).ravel())[::-1][:10]
        cluster_keywords[c] = list(terms[idxs])

    mal_cluster = next(
        (c for c, words in cluster_keywords.items()
         if any(t in words for t in malicious_terms)),
        0
    )

    EMAIL_MODEL_READY = True
    print(f"✅ Email clustering ready (malicious cluster = {mal_cluster}).")

except FileNotFoundError as e:
    print(f"⚠️  Email model skipped: {e}")
    EMAIL_MODEL_READY = False
    mal_cluster = 0

# ──────────────────────────────────────────────
# Keyword-Based Threat Pattern
# ──────────────────────────────────────────────
THREAT_KEYWORDS = [
    "urgent", "alert", "suspicious", "verify", "action required",
    "click here", "login", "account", "password", "security",
    "winner", "prize", "free", "confirm", "limited time",
]
threat_pattern = re.compile(
    r"\b(" + "|".join(re.escape(k) for k in THREAT_KEYWORDS) + r")\b",
    re.IGNORECASE,
)

def keyword_threat_check(text):
    return "POTENTIALLY MALICIOUS" if threat_pattern.search(text) else "SAFE"

# ──────────────────────────────────────────────
# Routes
# ──────────────────────────────────────────────

@app.route("/")
def serve_frontend():
    return send_from_directory(BASE_DIR, "index.html")


@app.route("/health")
def health():
    return jsonify({
        "status": "running",
        "url_model": URL_MODEL_READY,
        "email_model": EMAIL_MODEL_READY,
    })


@app.route("/classify-url", methods=["POST"])
def classify_url():
    data = request.get_json(silent=True) or {}
    url = data.get("url", "").strip()

    if not url:
        return jsonify({"error": "No URL provided"}), 400

    if not URL_MODEL_READY:
        return jsonify({"error": "URL model not loaded. Place malicious_phish.csv next to app.py"}), 503

    vec = vectorizer_url.transform([url])
    pred = clf_url.predict(vec)[0]
    human_label = le_url.inverse_transform([pred])[0]
    binary = map_to_binary(human_label)

    return jsonify({"url": url, "classification": binary})


@app.route("/check-email", methods=["POST"])
def check_email():
    data = request.get_json(silent=True) or {}
    email_text = data.get("email_text", "").strip()

    if not email_text:
        return jsonify({"error": "No email text provided"}), 400

    threat_status = keyword_threat_check(email_text)

    if EMAIL_MODEL_READY:
        vec_e = vectorizer_email.transform([email_text])
        cluster_label = int(kmeans.predict(vec_e)[0])
        cluster_type = "malicious-like" if cluster_label == mal_cluster else "benign-like"
    else:
        cluster_label = -1
        cluster_type = "model not loaded"

    return jsonify({
        "email_text": email_text,
        "threat_status": threat_status,
        "cluster_label": cluster_label,
        "cluster_type": cluster_type,
    })


# ──────────────────────────────────────────────
# Entry Point
# ──────────────────────────────────────────────
if __name__ == "__main__":
    app.run(debug=True, port=5000)