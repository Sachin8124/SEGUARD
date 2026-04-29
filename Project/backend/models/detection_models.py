"""
se_guard_backend/models/detection_models.py
============================================
SE-GUARD — Fake Detection ML Engine

Covers:
  1. Fake Profile Detection       (RandomForest on profile signals)
  2. Abusive / Threat Message     (TF-IDF + LogisticRegression)
  3. Fake Review / Testimonial    (TF-IDF + LinearSVC)
  4. Suspicious Payment           (IsolationForest anomaly detection)
  5. Fake Product Listing         (RandomForest on product signals)

All models are trained on synthetic but realistic data at startup — no
external dataset files needed.  Models are saved to disk with joblib so
they only retrain if the .pkl files are missing.
"""

import os, re, math, joblib, logging
import numpy as np
import pandas as pd

from sklearn.ensemble          import RandomForestClassifier, IsolationForest
from sklearn.linear_model      import LogisticRegression
from sklearn.svm               import LinearSVC
from sklearn.pipeline          import Pipeline
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing     import StandardScaler
from sklearn.calibration       import CalibratedClassifierCV

logging.basicConfig(level=logging.INFO, format="[SE-GUARD] %(message)s")
log = logging.getLogger(__name__)

MODEL_DIR = os.path.join(os.path.dirname(__file__), "saved")
os.makedirs(MODEL_DIR, exist_ok=True)

# ─────────────────────────────────────────────────────────────────────────────
# HELPER — save / load with joblib
# ─────────────────────────────────────────────────────────────────────────────
def _save(obj, name):
    joblib.dump(obj, os.path.join(MODEL_DIR, f"{name}.pkl"))

def _load(name):
    path = os.path.join(MODEL_DIR, f"{name}.pkl")
    return joblib.load(path) if os.path.exists(path) else None


# ═════════════════════════════════════════════════════════════════════════════
# 1. FAKE PROFILE DETECTOR
#    Features: account_age_days, posts, completeness, email_domain_score,
#              phone_verified, photo_uploaded, reviews_count, avg_rating,
#              login_frequency, ip_country_mismatch
# ═════════════════════════════════════════════════════════════════════════════
class FakeProfileDetector:
    MODEL_NAME = "fake_profile_rf"

    def __init__(self):
        self.model = _load(self.MODEL_NAME)
        if self.model is None:
            log.info("Training FakeProfileDetector …")
            self._train()

    def _synthetic_data(self):
        np.random.seed(42)
        n = 2000

        # REAL profiles
        real = pd.DataFrame({
            "account_age_days"     : np.random.randint(60, 1500, n//2),
            "posts"                : np.random.randint(5, 200, n//2),
            "completeness"         : np.random.uniform(0.6, 1.0, n//2),
            "email_domain_score"   : np.random.uniform(0.7, 1.0, n//2),
            "phone_verified"       : np.random.choice([0, 1], n//2, p=[0.1, 0.9]),
            "photo_uploaded"       : np.random.choice([0, 1], n//2, p=[0.05, 0.95]),
            "reviews_count"        : np.random.randint(2, 80, n//2),
            "avg_rating"           : np.random.uniform(3.5, 5.0, n//2),
            "login_frequency"      : np.random.uniform(0.4, 1.0, n//2),
            "ip_country_mismatch"  : np.random.choice([0, 1], n//2, p=[0.9, 0.1]),
            "label"                : 0
        })

        # FAKE profiles
        fake = pd.DataFrame({
            "account_age_days"     : np.random.randint(0, 30, n//2),
            "posts"                : np.random.randint(0, 5, n//2),
            "completeness"         : np.random.uniform(0.0, 0.4, n//2),
            "email_domain_score"   : np.random.uniform(0.0, 0.5, n//2),
            "phone_verified"       : np.random.choice([0, 1], n//2, p=[0.85, 0.15]),
            "photo_uploaded"       : np.random.choice([0, 1], n//2, p=[0.7, 0.3]),
            "reviews_count"        : np.random.randint(0, 3, n//2),
            "avg_rating"           : np.random.uniform(1.0, 3.5, n//2),
            "login_frequency"      : np.random.uniform(0.0, 0.2, n//2),
            "ip_country_mismatch"  : np.random.choice([0, 1], n//2, p=[0.3, 0.7]),
            "label"                : 1
        })

        df = pd.concat([real, fake]).sample(frac=1, random_state=42).reset_index(drop=True)
        return df

    def _train(self):
        df = self._synthetic_data()
        features = [c for c in df.columns if c != "label"]
        X, y = df[features].values, df["label"].values

        self.model = Pipeline([
            ("scaler", StandardScaler()),
            ("clf", RandomForestClassifier(n_estimators=150, max_depth=10,
                                           random_state=42, n_jobs=-1))
        ])
        self.model.fit(X, y)
        _save(self.model, self.MODEL_NAME)
        log.info("FakeProfileDetector trained ✓")

    def predict(self, profile: dict) -> dict:
        """
        profile keys (all optional, defaults to safe values):
          account_age_days, posts, completeness, email_domain_score,
          phone_verified, photo_uploaded, reviews_count, avg_rating,
          login_frequency, ip_country_mismatch
        """
        feat_order = ["account_age_days", "posts", "completeness",
                      "email_domain_score", "phone_verified", "photo_uploaded",
                      "reviews_count", "avg_rating", "login_frequency",
                      "ip_country_mismatch"]
        defaults = {
            "account_age_days": 365, "posts": 10, "completeness": 0.8,
            "email_domain_score": 0.8, "phone_verified": 1, "photo_uploaded": 1,
            "reviews_count": 5, "avg_rating": 4.0, "login_frequency": 0.6,
            "ip_country_mismatch": 0
        }
        row = [profile.get(k, defaults[k]) for k in feat_order]
        X   = np.array(row).reshape(1, -1)

        pred  = int(self.model.predict(X)[0])
        prob  = float(self.model.predict_proba(X)[0][1])

        flags = []
        if profile.get("account_age_days", 365) < 7 : flags.append("Very new account")
        if profile.get("completeness", 0.8)  < 0.3  : flags.append("Profile severely incomplete")
        if profile.get("phone_verified", 1)  == 0   : flags.append("Phone not verified")
        if profile.get("photo_uploaded", 1)  == 0   : flags.append("No profile photo")
        if profile.get("ip_country_mismatch", 0) == 1: flags.append("IP/country mismatch")
        if profile.get("reviews_count", 5)   < 1    : flags.append("No reviews")

        return {
            "verdict"       : "FAKE" if pred == 1 else "REAL",
            "fake_probability" : round(prob * 100, 1),
            "risk_level"    : "HIGH" if prob > 0.75 else "MEDIUM" if prob > 0.45 else "LOW",
            "flags"         : flags,
            "recommendation": "BLOCK" if prob > 0.75 else "REVIEW" if prob > 0.45 else "ALLOW"
        }


# ═════════════════════════════════════════════════════════════════════════════
# 2. MESSAGE ABUSE DETECTOR
#    TF-IDF → LogisticRegression (fast, accurate, no GPU needed)
#    Labels: 0=clean  1=abusive  2=threat  3=pressure
# ═════════════════════════════════════════════════════════════════════════════
class MessageAbuseDetector:
    MODEL_NAME = "message_abuse_lr"

    ABUSE_SAMPLES = [
        ("you are a fucking idiot", 1), ("what a piece of shit service", 1),
        ("go to hell you bastard", 1), ("stupid ass company", 1),
        ("you dumb bitch", 1), ("this is total crap", 1),
        ("bloody fool", 1), ("you moron", 1), ("pathetic loser", 1),
        ("i will kill you if you dont pay", 2), ("i know where you live", 2),
        ("your family will regret this", 2), ("i will destroy you", 2),
        ("i will find you and make you pay", 2), ("you will regret this decision", 2),
        ("i can harm you", 2), ("watch your back", 2), ("im coming for you", 2),
        ("pay me right now or else", 3), ("send money immediately", 3),
        ("you must pay now urgent", 3), ("i need payment this instant", 3),
        ("pay immediately or i will report you", 3),
        ("give me my money now or i will sue", 3),
        ("transfer funds right this second", 3), ("you better pay fast", 3),
        ("please process my refund at your earliest", 0),
        ("great service thank you so much", 0),
        ("can we schedule a call to discuss the project", 0),
        ("i have attached the invoice for your review", 0),
        ("looking forward to working with you", 0),
        ("please let me know if you need anything else", 0),
        ("the delivery was on time and the product is excellent", 0),
        ("i would like to request a revision", 0),
        ("can you clarify the timeline for this task", 0),
        ("thank you for the quick response", 0),
        ("i appreciate your professional service", 0),
        ("happy to recommend you to others", 0),
    ]

    def __init__(self):
        self.model = _load(self.MODEL_NAME)
        if self.model is None:
            log.info("Training MessageAbuseDetector …")
            self._train()

    def _train(self):
        texts, labels = zip(*self.ABUSE_SAMPLES)
        # Augment data 5× with minor variations
        aug_texts, aug_labels = list(texts), list(labels)
        for t, l in zip(texts, labels):
            for _ in range(4):
                words = t.split()
                if len(words) > 1:
                    i = np.random.randint(len(words))
                    words[i] = words[i].upper() if np.random.rand() > 0.5 else words[i].lower()
                aug_texts.append(" ".join(words))
                aug_labels.append(l)

        self.model = Pipeline([
            ("tfidf", TfidfVectorizer(ngram_range=(1, 3), max_features=8000,
                                      sublinear_tf=True, min_df=1)),
            ("clf",   LogisticRegression(max_iter=1000, C=2.0,
                                         multi_class="multinomial", random_state=42))
        ])
        self.model.fit(aug_texts, aug_labels)
        _save(self.model, self.MODEL_NAME)
        log.info("MessageAbuseDetector trained ✓")

    # Rule-based hard patterns (very high precision)
    HARD_ABUSE   = re.compile(r'\b(fuck|shit|bitch|bastard|cunt|asshole|motherfucker|whore|slut|prick|dick)\b', re.I)
    HARD_THREAT  = re.compile(r'\b(kill|murder|harm|destroy|i.ll find you|i know where you live|your family)\b', re.I)
    HARD_PRESSURE= re.compile(r'\b(pay (me )?(now|immediately|right now|this instant)|send money now|urgent payment|transfer now)\b', re.I)

    def predict(self, text: str) -> dict:
        label_map = {0: "CLEAN", 1: "ABUSIVE", 2: "THREAT", 3: "PRESSURE"}

        # Hard-rule override first
        if self.HARD_THREAT.search(text)   : hard = 2
        elif self.HARD_PRESSURE.search(text): hard = 3
        elif self.HARD_ABUSE.search(text)   : hard = 1
        else                                : hard = None

        probs = self.model.predict_proba([text])[0]
        ml_label = int(np.argmax(probs))
        confidence = float(np.max(probs))

        final = hard if hard is not None else ml_label
        is_flagged = final != 0

        matched_words = (
            self.HARD_THREAT.findall(text)   +
            self.HARD_PRESSURE.findall(text) +
            self.HARD_ABUSE.findall(text)
        )

        return {
            "verdict"    : label_map[final],
            "flagged"    : is_flagged,
            "type"       : label_map[final] if is_flagged else None,
            "confidence" : round(confidence * 100, 1),
            "matched_keywords": list(set(w.lower() for w in matched_words)),
            "action"     : "BLOCK_MESSAGE" if final in (2, 3) else "FLAG_MESSAGE" if final == 1 else "ALLOW",
            "ml_scores"  : {label_map[i]: round(float(p)*100,1) for i, p in enumerate(probs)}
        }


# ═════════════════════════════════════════════════════════════════════════════
# 3. FAKE REVIEW DETECTOR
#    TF-IDF → LinearSVC (calibrated for probabilities)
# ═════════════════════════════════════════════════════════════════════════════
class FakeReviewDetector:
    MODEL_NAME = "fake_review_svc"

    FAKE_REVIEWS = [
        "best product ever!!!! 5 stars amazing",
        "perfect excellent wonderful great awesome",
        "this is the best thing i have ever bought in my life",
        "superb quality fast delivery highly recommend",
        "absolutely fantastic beyond expectations",
        "wow this is incredible must buy for everyone",
        "best seller product very nice quality good",
        "i love it so much amazing quality",
        "perfect 10 out of 10 recommend to all",
        "excellent product very fast shipping thank you",
    ]
    REAL_REVIEWS = [
        "the product is decent but packaging could be better",
        "arrived 3 days late but the quality is good",
        "works as described, nothing special but does the job",
        "i liked the design but the battery life is disappointing",
        "good value for money, would buy again",
        "took some time to arrive but worth the wait",
        "not exactly what i expected but still usable",
        "the build quality feels cheap for the price",
        "customer support was helpful when i had an issue",
        "mixed feelings overall but probably would recommend",
    ]

    def __init__(self):
        self.model = _load(self.MODEL_NAME)
        if self.model is None:
            log.info("Training FakeReviewDetector …")
            self._train()

    def _train(self):
        texts  = self.FAKE_REVIEWS * 30 + self.REAL_REVIEWS * 30
        labels = [1] * (len(self.FAKE_REVIEWS)*30) + [0] * (len(self.REAL_REVIEWS)*30)

        svc = LinearSVC(max_iter=2000, C=1.0, random_state=42)
        cal = CalibratedClassifierCV(svc, cv=3)
        self.model = Pipeline([
            ("tfidf", TfidfVectorizer(ngram_range=(1, 2), max_features=5000,
                                      sublinear_tf=True)),
            ("clf",   cal)
        ])
        self.model.fit(texts, labels)
        _save(self.model, self.MODEL_NAME)
        log.info("FakeReviewDetector trained ✓")

    def _heuristic_flags(self, text: str) -> list:
        flags = []
        words = text.split()
        if len(set(words)) / max(len(words), 1) < 0.55:
            flags.append("High word repetition")
        superlatives = re.findall(r'\b(best|greatest|perfect|amazing|incredible|fantastic|excellent|wonderful|superb|awesome)\b', text, re.I)
        if len(superlatives) >= 3:
            flags.append(f"Excessive superlatives ({len(superlatives)})")
        if len(words) < 5:
            flags.append("Review too short")
        exclamations = text.count("!")
        if exclamations >= 3:
            flags.append(f"Excessive exclamation marks ({exclamations})")
        return flags

    def predict(self, review_text: str, rating: int = 5) -> dict:
        prob = float(self.model.predict_proba([review_text])[0][1])
        # Rating=5 with suspicious text increases fake probability
        if rating == 5:
            prob = min(prob * 1.15, 1.0)

        flags = self._heuristic_flags(review_text)
        if flags:
            prob = min(prob + 0.1 * len(flags), 1.0)

        verdict = "FAKE" if prob > 0.55 else "REAL"
        return {
            "verdict"         : verdict,
            "fake_probability": round(prob * 100, 1),
            "risk_level"      : "HIGH" if prob > 0.75 else "MEDIUM" if prob > 0.45 else "LOW",
            "flags"           : flags,
            "action"          : "HIDE_REVIEW" if prob > 0.75 else "FLAG_REVIEW" if prob > 0.45 else "APPROVE"
        }


# ═════════════════════════════════════════════════════════════════════════════
# 4. SUSPICIOUS PAYMENT DETECTOR
#    IsolationForest (unsupervised anomaly detection)
#    Features: amount, hour_of_day, retries, new_device, vpn_flag,
#              amount_vs_history_ratio, time_since_last_txn_min
# ═════════════════════════════════════════════════════════════════════════════
class SuspiciousPaymentDetector:
    MODEL_NAME = "suspicious_payment_iso"

    def __init__(self):
        self.model   = _load(self.MODEL_NAME)
        self.scaler  = _load(self.MODEL_NAME + "_scaler")
        if self.model is None:
            log.info("Training SuspiciousPaymentDetector …")
            self._train()

    def _train(self):
        np.random.seed(7)
        n = 3000
        # Normal transactions
        normal = np.column_stack([
            np.random.uniform(100, 25000, n),   # amount
            np.random.randint(8, 22, n),         # hour (business hours)
            np.zeros(n),                          # retries
            np.random.choice([0, 1], n, p=[0.9, 0.1]),  # new_device
            np.random.choice([0, 1], n, p=[0.95, 0.05]),# vpn
            np.random.uniform(0.5, 1.5, n),      # amount_vs_history
            np.random.uniform(60, 10000, n),     # time_since_last
        ])
        # Anomalous (5%)
        n_anom = 150
        anom = np.column_stack([
            np.random.uniform(80000, 200000, n_anom),   # huge amount
            np.random.randint(0, 6, n_anom),             # odd hours
            np.random.randint(3, 10, n_anom),            # many retries
            np.ones(n_anom),
            np.ones(n_anom),
            np.random.uniform(5.0, 20.0, n_anom),
            np.random.uniform(0, 2, n_anom),
        ])
        X = np.vstack([normal, anom])

        self.scaler = StandardScaler()
        Xs = self.scaler.fit_transform(X)
        self.model  = IsolationForest(n_estimators=200, contamination=0.05,
                                      random_state=42)
        self.model.fit(Xs)
        _save(self.model,  self.MODEL_NAME)
        _save(self.scaler, self.MODEL_NAME + "_scaler")
        log.info("SuspiciousPaymentDetector trained ✓")

    def predict(self, payment: dict) -> dict:
        feat_order = ["amount", "hour_of_day", "retries", "new_device",
                      "vpn_flag", "amount_vs_history_ratio", "time_since_last_txn_min"]
        defaults   = {"amount": 1000, "hour_of_day": 12, "retries": 0,
                      "new_device": 0, "vpn_flag": 0,
                      "amount_vs_history_ratio": 1.0, "time_since_last_txn_min": 500}
        row = np.array([payment.get(k, defaults[k]) for k in feat_order]).reshape(1, -1)
        Xs  = self.scaler.transform(row)
        score  = float(self.model.score_samples(Xs)[0])  # more negative = more anomalous
        # Map score to 0-1 probability of being suspicious
        prob   = float(1 / (1 + math.exp(score * 6 + 2)))

        flags = []
        if payment.get("amount", 0) > 50000      : flags.append("Unusually high amount")
        if payment.get("retries", 0) >= 3         : flags.append("Multiple payment retries")
        if payment.get("new_device", 0)           : flags.append("New device detected")
        if payment.get("vpn_flag", 0)             : flags.append("VPN/Proxy detected")
        h = payment.get("hour_of_day", 12)
        if h < 5 or h > 23                        : flags.append("Unusual transaction hour")
        if payment.get("amount_vs_history_ratio", 1) > 4: flags.append("Amount far above user history")

        return {
            "verdict"         : "SUSPICIOUS" if prob > 0.55 else "NORMAL",
            "risk_probability": round(prob * 100, 1),
            "risk_level"      : "HIGH" if prob > 0.75 else "MEDIUM" if prob > 0.45 else "LOW",
            "anomaly_score"   : round(score, 4),
            "flags"           : flags,
            "action"          : "BLOCK_PAYMENT" if prob > 0.80 else "REQUIRE_OTP" if prob > 0.50 else "ALLOW"
        }


# ═════════════════════════════════════════════════════════════════════════════
# 5. FAKE PRODUCT LISTING DETECTOR
#    Features: price_vs_category_avg_ratio, description_length, image_count,
#              seller_age_days, seller_rating, seller_total_sales,
#              discount_pct, has_contact_info_in_desc
# ═════════════════════════════════════════════════════════════════════════════
class FakeProductDetector:
    MODEL_NAME = "fake_product_rf"

    def __init__(self):
        self.model = _load(self.MODEL_NAME)
        if self.model is None:
            log.info("Training FakeProductDetector …")
            self._train()

    def _train(self):
        np.random.seed(99)
        n = 2000
        # Real listings
        real = np.column_stack([
            np.random.uniform(0.8, 1.4, n//2),   # price_ratio
            np.random.randint(50, 500, n//2),      # desc_length
            np.random.randint(2, 10, n//2),        # image_count
            np.random.randint(60, 1500, n//2),     # seller_age_days
            np.random.uniform(3.5, 5.0, n//2),     # seller_rating
            np.random.randint(10, 500, n//2),      # total_sales
            np.random.uniform(0, 30, n//2),        # discount_pct
            np.zeros(n//2),                         # contact_in_desc
        ])
        y_real = np.zeros(n//2)

        # Fake listings
        fake = np.column_stack([
            np.random.uniform(0.05, 0.4, n//2),   # suspiciously cheap
            np.random.randint(0, 30, n//2),         # very short desc
            np.random.randint(0, 2, n//2),          # few/no images
            np.random.randint(0, 14, n//2),         # very new seller
            np.random.uniform(0.0, 2.5, n//2),
            np.random.randint(0, 3, n//2),
            np.random.uniform(60, 99, n//2),        # huge discount
            np.random.choice([0, 1], n//2, p=[0.3, 0.7]),
        ])
        y_fake = np.ones(n//2)

        X = np.vstack([real, fake])
        y = np.concatenate([y_real, y_fake])
        idx = np.random.permutation(len(y))
        X, y = X[idx], y[idx]

        self.model = Pipeline([
            ("scaler", StandardScaler()),
            ("clf", RandomForestClassifier(n_estimators=150, max_depth=8,
                                            random_state=42, n_jobs=-1))
        ])
        self.model.fit(X, y)
        _save(self.model, self.MODEL_NAME)
        log.info("FakeProductDetector trained ✓")

    def predict(self, product: dict) -> dict:
        feat_order = ["price_vs_category_avg_ratio", "description_length",
                      "image_count", "seller_age_days", "seller_rating",
                      "seller_total_sales", "discount_pct",
                      "has_contact_info_in_desc"]
        defaults = {
            "price_vs_category_avg_ratio": 1.0,
            "description_length"         : 100,
            "image_count"                : 3,
            "seller_age_days"            : 180,
            "seller_rating"              : 4.0,
            "seller_total_sales"         : 20,
            "discount_pct"               : 10,
            "has_contact_info_in_desc"   : 0
        }
        row  = np.array([product.get(k, defaults[k]) for k in feat_order]).reshape(1, -1)
        pred = int(self.model.predict(row)[0])
        prob = float(self.model.predict_proba(row)[0][1])

        flags = []
        if product.get("price_vs_category_avg_ratio", 1.0) < 0.3 : flags.append("Price suspiciously low vs category")
        if product.get("description_length", 100)          < 20   : flags.append("Description too short")
        if product.get("image_count", 3)                   < 1    : flags.append("No product images")
        if product.get("seller_age_days", 180)             < 7    : flags.append("Seller account very new")
        if product.get("discount_pct", 10)                 > 70   : flags.append("Unrealistic discount")
        if product.get("has_contact_info_in_desc", 0)             : flags.append("Contact info found in description")

        return {
            "verdict"         : "FAKE" if pred == 1 else "GENUINE",
            "fake_probability": round(prob * 100, 1),
            "risk_level"      : "HIGH" if prob > 0.75 else "MEDIUM" if prob > 0.45 else "LOW",
            "flags"           : flags,
            "action"          : "REMOVE_LISTING" if prob > 0.75 else "FLAG_LISTING" if prob > 0.45 else "APPROVE"
        }


# ─────────────────────────────────────────────────────────────────────────────
# SINGLETON LOADER — called once at app startup
# ─────────────────────────────────────────────────────────────────────────────
_models = {}

def load_all_models():
    global _models
    _models = {
        "profile" : FakeProfileDetector(),
        "message" : MessageAbuseDetector(),
        "review"  : FakeReviewDetector(),
        "payment" : SuspiciousPaymentDetector(),
        "product" : FakeProductDetector(),
    }
    log.info("✅ All SE-GUARD ML models loaded and ready.")
    return _models

def get_models(load_if_missing=True):
    if not _models and load_if_missing:
        return load_all_models()
    return _models
