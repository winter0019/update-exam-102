import os
import re
import json
import uuid
import hashlib
import traceback
from datetime import datetime, timedelta
from functools import wraps

from flask import Flask, render_template, request, jsonify, session, redirect, url_for
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.utils import secure_filename

import google.generativeai as genai
from google.generativeai.types import HarmCategory, HarmBlockThreshold

import logging
import requests

# =========================
# APP CONFIG
# =========================
app = Flask(__name__)
CORS(app)

app.secret_key = os.environ.get("FLASK_SECRET_KEY", "supersecret")
limiter = Limiter(get_remote_address, app=app, default_limits=["200 per day", "50 per hour"])

# Logging setup
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(name)s:%(lineno)d - %(message)s",
)
logger = logging.getLogger("app")


# =========================
# HELPERS
# =========================
def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if "user" not in session:
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return wrapper


def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()


# =========================
# GOOGLE GENAI CONFIG
# =========================
genai.configure(api_key=os.environ.get("GEMINI_API_KEY"))

gemini_model = genai.GenerativeModel(
    "gemini-1.5-flash",
    generation_config={"temperature": 0.2, "top_p": 0.9, "top_k": 40, "max_output_tokens": 512},
    safety_settings={
        HarmCategory.HARM_CATEGORY_HARASSMENT: HarmBlockThreshold.BLOCK_MEDIUM_AND_ABOVE,
        HarmCategory.HARM_CATEGORY_HATE_SPEECH: HarmBlockThreshold.BLOCK_MEDIUM_AND_ABOVE,
        HarmCategory.HARM_CATEGORY_SEXUALLY_EXPLICIT: HarmBlockThreshold.BLOCK_MEDIUM_AND_ABOVE,
        HarmCategory.HARM_CATEGORY_DANGEROUS_CONTENT: HarmBlockThreshold.BLOCK_MEDIUM_AND_ABOVE,
    },
)


# =========================
# ROUTES
# =========================
@app.route("/")
def home():
    if "user" in session:
        return redirect(url_for("quiz"))
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        try:
            data = request.get_json(force=True)
            username = data.get("username")
            password = data.get("password")

            if not username or not password:
                return jsonify({"status": "error", "message": "Missing credentials"}), 400

            # For demo: single hardcoded user
            if username == "admin" and hash_password(password) == hash_password("password"):
                session["user"] = username
                return jsonify({"status": "success"}), 200

            return jsonify({"status": "error", "message": "Invalid login"}), 401
        except Exception as e:
            logger.error(f"Login error: {e}")
            return jsonify({"status": "error", "message": "Login failed"}), 500

    return render_template("login.html")


@app.route("/quiz")
@login_required
def quiz():
    return render_template("quiz.html")


# =========================
# QUIZ GENERATION ROUTE
# =========================
@app.route("/generate_quiz", methods=["POST"])
@login_required
def generate_quiz():
    try:
        data = request.get_json(force=True)
        topic = data.get("topic", "current affairs")

        # Fetch context (news text from GNews or fallback)
        context = fetch_gnews_text(topic)

        # Generate quiz via Gemini
        questions = call_gemini_for_quiz(context)

        logger.info(f"Generated {len(questions)} questions for topic '{topic}'")

        return jsonify({"status": "success", "questions": questions}), 200

    except Exception as e:
        logger.error(f"Error in /generate_quiz: {e}\n{traceback.format_exc()}")
        return jsonify({"status": "error", "message": str(e)}), 400


# =========================
# NEWS FETCHING (GNews)
# =========================
def fetch_gnews_text(query: str) -> str:
    api_key = os.environ.get("GNEWS_API_KEY")
    if not api_key:
        logger.warning("GNEWS_API_KEY is not set; returning simulated news instead.")
        return f"Simulated news content for {query}. This is fallback text."

    try:
        url = f"https://gnews.io/api/v4/search?q={query}&lang=en&max=5&token={api_key}"
        resp = requests.get(url, timeout=10)
        data = resp.json()

        if "articles" not in data:
            return f"No relevant news found for {query}."

        articles = [a.get("title", "") + " " + a.get("description", "") for a in data["articles"]]
        return " ".join(articles[:5])

    except Exception as e:
        logger.error(f"GNews fetch failed: {e}")
        return f"News fetch error for {query}"


# =========================
# GEMINI QUIZ GENERATION
# =========================
def call_gemini_for_quiz(context: str):
    """
    Generate quiz questions from text context using Gemini with stricter JSON enforcement.
    """
    prompt = f"""
You are a quiz generator. Based ONLY on the following context, generate 3 multiple-choice questions.

Context:
\"\"\"{context}\"\"\"

Rules:
- Strict JSON output ONLY.
- Each question object must include:
  "question": string,
  "options": [string, string, string, string],
  "answer": string (must match one of the options).

Output format:
[
  {{
    "question": "...",
    "options": ["...", "...", "...", "..."],
    "answer": "..."
  }}
]
"""

    try:
        response = gemini_model.generate_content(prompt)
        text = response.text.strip()

        # Try parsing directly
        try:
            return json.loads(text)
        except Exception:
            pass

        # Extract JSON block
        match = re.search(r"\[.*\]", text, re.DOTALL)
        if match:
            return json.loads(match.group(0))

        logger.warning("Falling back: failed to parse JSON properly.")
        return [{"question": "Parsing failed", "options": ["A", "B", "C", "D"], "answer": "A"}]

    except Exception as e:
        logger.error(f"Gemini quiz generation failed: {e}")
        return [{"question": "Error generating quiz", "options": ["A", "B", "C", "D"], "answer": "A"}]


# =========================
# AFTER REQUEST HOOK
# =========================
@app.after_request
def after_request_hook(response):
    logger.info("%s - %s %s %s", request.remote_addr, request.method, request.path, response.status_code)
    return response


# =========================
# MAIN ENTRY
# =========================
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=True)
