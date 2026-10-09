from flask import Flask, request, render_template

from backend.database import (
    init_database,
    save_scan,
    get_history
)

import sys
from pathlib import Path

import pandas as pd
import joblib


# =========================================================
# PROJECT PATH
# =========================================================

BACKEND_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = BACKEND_DIR.parent

sys.path.append(str(PROJECT_ROOT))


# =========================================================
# IMPORT PHISHHUNT FUNCTIONS
# =========================================================

from backend.ml.predict import extract_features

from backend.cybersecurity.risk_engine import (
    analyze_security_rules
)


# =========================================================
# FLASK APP
# =========================================================

app = Flask(__name__)


# =========================================================
# INITIALIZE DATABASE
# =========================================================

init_database()


# =========================================================
# LOAD ML MODEL
# =========================================================

MODEL_PATH = (
    BACKEND_DIR
    / "ml"
    / "phishhunt_model.pkl"
)

print("Loading PhishHunt model...")

model = joblib.load(MODEL_PATH)

print("PhishHunt model loaded successfully!")


# =========================================================
# HOME ROUTE
# =========================================================

@app.route("/", methods=["GET"])
def home():

    return render_template("index.html")


# =========================================================
# HEALTH CHECK
# =========================================================

@app.route("/health", methods=["GET"])
def health():

    return {
        "status": "healthy",
        "model_loaded": True
    }


# =========================================================
# HISTORY API
# =========================================================

@app.route("/api/history", methods=["GET"])
def history():

    return {
        "success": True,
        "history": get_history()
    }


# =========================================================
# HISTORY PAGE
# =========================================================

@app.route("/history", methods=["GET"])
def history_page():

    return render_template("history.html")


# =========================================================
# DASHBOARD PAGE
# =========================================================

@app.route("/dashboard", methods=["GET"])
def dashboard_page():

    return render_template("dashboard.html")


# =========================================================
# URL ANALYSIS API
# =========================================================

@app.route("/api/analyze", methods=["POST"])
def analyze_url():

    # -----------------------------------------------------
    # GET JSON REQUEST
    # -----------------------------------------------------

    data = request.get_json(silent=True)

    if not data:

        return {
            "success": False,
            "error": "Request body must contain JSON"
        }, 400


    # -----------------------------------------------------
    # GET URL
    # -----------------------------------------------------

    url = data.get("url")

    if not url:

        return {
            "success": False,
            "error": "URL is required"
        }, 400


    # -----------------------------------------------------
    # MAKE SURE URL IS A STRING
    # -----------------------------------------------------

    url = str(url).strip()

    if not url:

        return {
            "success": False,
            "error": "URL cannot be empty"
        }, 400


    try:

        # =================================================
        # MACHINE LEARNING ANALYSIS
        # =================================================

        # Extract the same 31 URL-based features
        # used during model training.

        features = extract_features(url)

        X = pd.DataFrame([features])


        # -------------------------------------------------
        # CHECK ML FEATURE COMPATIBILITY
        # -------------------------------------------------

        if hasattr(model, "feature_names_in_"):

            expected_features = list(
                model.feature_names_in_
            )

            actual_features = list(
                X.columns
            )

            if expected_features != actual_features:

                return {
                    "success": False,
                    "error": "ML feature mismatch",
                    "expected_features": len(
                        expected_features
                    ),
                    "actual_features": len(
                        actual_features
                    )
                }, 500


        # -------------------------------------------------
        # ML PREDICTION
        # -------------------------------------------------

        prediction = model.predict(X)[0]

        probabilities = model.predict_proba(X)[0]

        confidence = float(
            max(probabilities) * 100
        )


        # -------------------------------------------------
        # PHISHHUNT LABEL MAPPING
        # -------------------------------------------------

        # 0 = LEGITIMATE
        # 1 = PHISHING

        if prediction == 1:

            ml_result = "PHISHING"

        else:

            ml_result = "LEGITIMATE"


        # =================================================
        # CYBERSECURITY RULE ENGINE
        # =================================================

        security_result = analyze_security_rules(url)


        security_decision = (
            security_result["decision"]
        )

        risk_score = (
            security_result["risk_score"]
        )

        security_indicators = (
            security_result["indicators"]
        )


        # =================================================
        # FINAL DECISION ENGINE
        # =================================================

        # Priority:
        #
        # 1. HIGH RISK  -> PHISHING
        # 2. LEGITIMATE trusted result -> LEGITIMATE
        # 3. SUSPICIOUS -> use ML + risk score
        # 4. LOW RISK -> do not allow uncertain ML
        #                   prediction to override a
        #                   very low security risk.
        #
        # This prevents cases such as:
        #
        # Google
        # ML Prediction: PHISHING
        # Risk Score: 10
        # Security Decision: LOW RISK
        #
        # from being displayed as PHISHING.


        # -------------------------------------------------
        # LEGITIMATE
        # -------------------------------------------------

        if security_decision == "LEGITIMATE":

            final_result = "LEGITIMATE"


        # -------------------------------------------------
        # HIGH RISK
        # -------------------------------------------------

        elif security_decision == "HIGH RISK":

            final_result = "PHISHING"


        # -------------------------------------------------
        # SUSPICIOUS
        # -------------------------------------------------

        elif security_decision == "SUSPICIOUS":

            # If ML predicts phishing OR risk is 40+
            # classify as phishing.

            if prediction == 1 or risk_score >= 40:

                final_result = "PHISHING"

            else:

                final_result = "SUSPICIOUS"


        # -------------------------------------------------
        # LOW RISK
        # -------------------------------------------------

        elif security_decision == "LOW RISK":

            # Very low risk should not be classified as
            # phishing only because the ML model is
            # uncertain.

            if risk_score < 20:

                final_result = "LEGITIMATE"

            else:

                final_result = ml_result


        # -------------------------------------------------
        # UNKNOWN SECURITY DECISION
        # -------------------------------------------------

        else:

            final_result = ml_result


        # =================================================
        # SAVE SCAN TO DATABASE
        # =================================================

        save_scan(

            url=url,

            final_result=final_result,

            ml_prediction=ml_result,

            ml_confidence=round(
                confidence,
                2
            ),

            risk_score=risk_score,

            security_decision=security_decision,

            security_indicators=security_indicators

        )


        # =================================================
        # API RESPONSE
        # =================================================

        return {

            "success": True,

            "url": url,

            "final_result": final_result,

            "ml_prediction": ml_result,

            "ml_confidence": round(
                confidence,
                2
            ),

            "risk_score": risk_score,

            "security_decision": security_decision,

            "security_indicators": security_indicators

        }


    # =====================================================
    # ERROR HANDLING
    # =====================================================

    except Exception as e:

        print(
            "Analysis error:",
            str(e)
        )

        return {

            "success": False,

            "error": str(e)

        }, 500


# =========================================================
# START SERVER
# =========================================================

if __name__ == "__main__":

    print()

    print("======================================")

    print("       PHISHHUNT API SERVER")

    print("======================================")

    print()

    print("Server starting...")

    print(
        "Open: http://127.0.0.1:5000"
    )

    print(
        "API:   http://127.0.0.1:5000/api/analyze"
    )

    print()

    print("Press CTRL+C to stop the server.")

    print()


    app.run(

        host="127.0.0.1",

        port=5000,

        debug=True

    )