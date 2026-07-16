from pathlib import Path
import joblib
import pandas as pd
BASE_DIR = Path(__file__).resolve().parent
MODEL_PATH = BASE_DIR / "models" / "risk_model.pkl"

def extract_url_features(url, redirect_count=0):
    return {
        "url_length": len(url), "n_dots": url.count("."), "n_hyphens": url.count("-"),
        "n_underline": url.count("_"), "n_slash": url.count("/"),
        "n_questionmark": url.count("?"), "n_equal": url.count("="),
        "n_at": url.count("@"), "n_and": url.count("&"),
        "n_exclamation": url.count("!"), "n_space": url.count(" "),
        "n_tilde": url.count("~"), "n_comma": url.count(","),
        "n_plus": url.count("+"), "n_asterisk": url.count("*"),
        "n_hashtag": url.count("#"), "n_dollar": url.count("$"),
        "n_percent": url.count("%"), "n_redirection": int(redirect_count > 0),
    }

def predict_ai_score(url, redirect_count=0):
    if not MODEL_PATH.exists():
        return None
    package = joblib.load(MODEL_PATH)
    model = package["model"]
    names = package["features"]
    values = extract_url_features(url, redirect_count)
    row = pd.DataFrame([[values[name] for name in names]], columns=names)
    return round(float(model.predict_proba(row)[0][1]) * 100)

def combine_rule_and_ai(rule_score, ai_score, rule_weight=0.90, ai_weight=0.10):
    if ai_score is None:
        return rule_score
    if round(rule_weight + ai_weight, 5) != 1:
        raise ValueError("Weights must equal 1")
    return round(max(0, min((rule_score * rule_weight) + (ai_score * ai_weight), 100)))
