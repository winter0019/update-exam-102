# app.py
# Updated full application with GNews & stricter JSON prompt fixes.
# Keep in mind to set environment variables:
#   - GEMINI_API_KEY
#   - (optional) FIREBASE_SERVICE_ACCOUNT (JSON string)
#   - (optional) GNEWS_API_KEY

import os
import re
import json
import uuid
import hashlib
import traceback
import textwrap
from datetime import datetime, timedelta
from functools import wraps

from flask import Flask, render_template, request, jsonify, session, redirect, url_for
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.utils import secure_filename

import google.generativeai as genai
from google.generativeai.types import HarmCategory, HarmBlockThreshold

from loguru import logger
from dotenv import load_dotenv

import requests
import tempfile
import docx
import PyPDF2
import pytesseract
from PIL import Image

import firebase_admin
from firebase_admin import credentials, firestore, auth
from google.cloud.firestore_v1.base_query import FieldFilter

# --- Load Environment ---
load_dotenv()

# --- Configure Google Gemini ---
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
if not GEMINI_API_KEY:
    raise RuntimeError("GEMINI_API_KEY is not set")
genai.configure(api_key=GEMINI_API_KEY)

# --- Flask App Setup ---
app = Flask(__name__, template_folder="templates", static_folder="static")
CORS(app)
app.secret_key = os.getenv("SECRET_KEY", "super-secret-key")

# --- Rate Limiter (note: in-memory storage warning is expected if no backend set) ---
limiter = Limiter(get_remote_address, app=app, default_limits=["100 per day", "20 per hour"])

# --- Logger ---
logger.remove()
logger.add("logs/app_{time}.log", rotation="1 day", level="INFO")
logger.add(lambda msg: print(msg, flush=True), level="INFO")

# --- Firebase Setup (optional) ---
db = None
try:
    firebase_json = os.getenv("FIREBASE_SERVICE_ACCOUNT")
    if firebase_json:
        cred_dict = json.loads(firebase_json) if isinstance(firebase_json, str) else firebase_json
        cred = credentials.Certificate(cred_dict)
        firebase_admin.initialize_app(cred)
        db = firestore.client()
        logger.info("Firebase initialized successfully")
    else:
        logger.info("FIREBASE_SERVICE_ACCOUNT not set; using in-memory room storage only.")
except Exception as e:
    logger.warning(f"Firebase not initialized: {e}")

# --- Constants ---
ALLOWED_EXTENSIONS = {"pdf", "docx", "png", "jpg", "jpeg"}
ALLOWED_USERS = {
    "deborahibiyinka@gmail.com", "feuri73@gmail.com", "zainabsalawu1989@gmail.com",
    "alograce69@gmail.com", "abdullahimuhd790@gmail.com", "davidirene2@gmail.com",
    "maryaugie2@gmail.com", "ashami73@gmail.com", "comzelhua@gmail.com",
    "niyiolaniyi@gmail.com", "itszibnisah@gmail.com", "olayemisiola06@gmail.com",
    "shemasalik@gmail.com", "akawupeter2@gmail.com", "pantuyd@gmail.com",
    "omnibuszara@gmail.com", "mssphartyma@gmail.com", "assyy.au@gmail.com",
    "shenyshehu@gmail.com", "isadeeq17@gmail.com", "dangalan20@gmail.com",
    "muhammadsadanu@gmail.com", "rukitafida@gmail.com", "winter0019@protonmail.com",
    "winter19@gmail.com", "adedoyinfehintola@gmail.com", "aderemijudy@gmail.com",
    "meetmohdibrahim@gmail.com", "ishayasamuel23@gmail.com", "msani516@gmail.com",
    "olufunkehenryobadofin@gmail.com", "saintmajid@gmail.com", "yhuleira@gmail.com",
    "ahmedhauwadukku@gmail.com", "ladiamdiila42@gmail.com", "ummalikko@gmail.com",
    "dearmairamri@gmail.com",
}
ALLOWED_USERS = {email.lower() for email in ALLOWED_USERS}
ADMIN_USER = "dangalan20@gmail.com"
APP_ID = "nysc-exam-prep-app"  # Placeholder App ID

# In-memory storage for active sessions (for online user count)
active_sessions = {}
# Simple in-memory cache
cache = {}

# --- Helpers ---
def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

def extract_text_from_file(file_path):
    """
    Extract text from pdf, docx, or image using PyPDF2, python-docx, pytesseract.
    Returns an empty string on failure (and logs the error).
    """
    text = ""
    ext = os.path.splitext(file_path)[1].lower().lstrip(".")
    try:
        if ext == "pdf":
            with open(file_path, "rb") as f:
                reader = PyPDF2.PdfReader(f)
                for page in reader.pages:
                    text += page.extract_text() or ""
        elif ext == "docx":
            document = docx.Document(file_path)
            text = "\n".join(p.text for p in document.paragraphs)
        elif ext in {"png", "jpg", "jpeg"}:
            img = Image.open(file_path)
            text = pytesseract.image_to_string(img)
        else:
            raise ValueError(f"Unsupported file type: {ext}")
    except Exception as e:
        logger.error(f"File extraction failed for {file_path}: {e}", exc_info=True)
    return (text or "").strip()

def preprocess_text_for_quiz(text):
    """
    Some lightweight cleanup for uploaded documents so prompts are less noisy.
    Removes lines like "Chapter 1", 6-digit keys, and top/bottom 'Answer' noise.
    """
    lines = text.splitlines()
    processed_lines = []
    for line in lines:
        stripped_line = line.strip()
        if not stripped_line:
            continue
        if re.match(r'^(Chapter|Section)\s+\S+', stripped_line, re.I):
            continue
        if re.match(r'^\s*\d{6}\s+\S+', stripped_line):
            continue
        processed_lines.append(line)
    processed_text = "\n".join(processed_lines)
    processed_text = re.sub(r'Questions?\s*\d*\s*[\.\-]?', '', processed_text, flags=re.I)
    processed_text = re.sub(r'\s*Answer[s]?\s*[\.\-]?', '', processed_text, flags=re.I)
    return processed_text.strip()

def generate_cache_key(base, ttl_minutes, prefix=""):
    h = hashlib.md5(base.encode()).hexdigest()
    return f"{prefix}_{h}_{ttl_minutes}"

def cache_set(key, value, ttl_minutes=5):
    cache[key] = {"value": value, "expires": datetime.utcnow() + timedelta(minutes=ttl_minutes)}

def cache_get(key):
    v = cache.get(key)
    if not v:
        return None
    if datetime.utcnow() < v["expires"]:
        return v["value"]
    # expired
    try:
        del cache[key]
    except KeyError:
        pass
    return None

def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if "user_email" not in session:
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return wrapper

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get('user_email') != ADMIN_USER:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# --- Middleware ---
@app.before_request
def before_request_hook():
    # track last active for in-memory sessions
    if 'user_email' in session:
        active_sessions[session['user_email']] = datetime.utcnow()

@app.after_request
def after_request_hook(response):
    logger.info(f"{request.remote_addr} {request.method} {request.path} {response.status_code}")
    return response

# --- Robust Gemini quiz parsing & helpers ---
def _extract_first_json_block(text: str):
    """
    Attempt to extract the first JSON object from a possibly noisy LLM response.
    Look for ```json ... ``` fenced blocks, then code fences, then the first {...} block.
    """
    if not text:
        return None
    # Look for code-fenced JSON (```json { ... } ```)
    m = re.search(r"```json\s*(\{.*?\})\s*```", text, flags=re.S)
    if m:
        return m.group(1)
    # Also allow generic code fences with JSON inside
    m = re.search(r"```(?:\w+)?\s*(\{(?:.|\n)*?\})\s*```", text, flags=re.S)
    if m:
        return m.group(1)
    # Otherwise look for first { ... } that is likely JSON (balanced approach)
    # This is intentionally conservative to avoid grabbing other braces.
    start = text.find("{")
    if start == -1:
        return None
    # Try to find matching closing brace by scanning
    depth = 0
    for i in range(start, len(text)):
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
            if depth == 0:
                candidate = text[start:i+1]
                return candidate
    return None

def quiz_to_uniform_schema(quiz_obj):
    """
    Normalize different quiz structures returned by the LLM into:
    {"questions": [{"question": "...", "options": [...4 options...], "answer": "..."}, ...]}
    """
    out = {"questions": []}
    items = []
    if isinstance(quiz_obj, dict):
        # Prefer a top-level 'questions' key; fallback to 'quiz' or root list
        if "questions" in quiz_obj and isinstance(quiz_obj["questions"], list):
            items = quiz_obj["questions"]
        elif "quiz" in quiz_obj and isinstance(quiz_obj["quiz"], list):
            items = quiz_obj["quiz"]
        else:
            # If quiz_obj itself looks like a list-like mapping, try to coerce
            # Not typical — but keep defensive
            items = []
    elif isinstance(quiz_obj, list):
        items = quiz_obj
    else:
        return out

    for q in items:
        if not isinstance(q, dict):
            continue
        question = str(q.get("question") or q.get("q") or "").strip()
        options = q.get("options") or q.get("choices") or []
        answer = str(q.get("answer") or q.get("correct") or q.get("correct_answer") or "").strip()

        # Options may be provided as dict like {"A": "x", "B": "y", ...}
        if isinstance(options, dict):
            # keep alphabetical order if possible
            ordered = []
            for k in sorted(options.keys()):
                ordered.append(options[k])
            options = ordered

        if isinstance(options, list):
            options = [str(o).strip() for o in options if o is not None and str(o).strip() != ""]
        else:
            options = []

        # Normalize to exactly 4 options
        while len(options) < 4:
            options.append("N/A")
        options = options[:4]

        # Ensure answer matches one of the options; otherwise clear it (so front-end doesn't rely on invalid answer)
        if answer and answer not in options:
            # allow answers given as letter "A"/"B" etc.
            letter_mapping = {"A": 0, "B": 1, "C": 2, "D": 3}
            if answer.upper() in letter_mapping:
                idx = letter_mapping[answer.upper()]
                if 0 <= idx < len(options):
                    answer = options[idx]
                else:
                    answer = ""
            else:
                # maybe the answer is just a substring; try fuzzy match (simple)
                found = None
                for opt in options:
                    if answer.lower() in opt.lower() or opt.lower() in answer.lower():
                        found = opt
                        break
                answer = found or ""

        if question:
            out["questions"].append({
                "question": question,
                "options": options,
                "answer": answer
            })
    return out

def call_gemini_for_quiz(context_text: str, subject: str, grade: str):
    """
    Ask Gemini to generate realistic Nigerian Civil Service/NYSC promotional exam-style MCQs.

    This function instructs the model to return STRICT JSON ONLY. The example JSON in the prompt uses
    doubled braces where necessary so the f-string remains valid.
    """
    # Keep context reasonably sized to avoid token explosion
    safe_context = (context_text or "")[:4000]

    # Use a dedented prompt for clarity. We'll double braces in the embedded example JSON so
    # the f-string can contain literal braces.
    prompt = textwrap.dedent(f"""
    You are an expert in Nigerian Public Service Rules and NYSC regulations. Generate HIGH QUALITY multiple-
    choice exam questions derived strictly from the provided source material. Your output MUST be valid JSON and
    follow the exact schema requested below. Do NOT provide any additional explanation, text, or commentary.
    If you cannot produce valid JSON, return an empty JSON object: {{ "questions": [] }}.

    Source material (use only this to create questions):
    {safe_context}

    Output requirements (MUST follow exactly):
    - Return a single JSON object with one key: "questions".
    - "questions" must be a JSON array of 5 to 10 objects.
    - Each question object must contain exactly the keys: "question", "options", "answer".
      * "question": string (the question text).
      * "options": array of exactly 4 strings (A, B, C, D). Order matters.
      * "answer": string that EXACTLY matches one of the four options.
    - Questions should test practical knowledge (duties, rights, administrative procedures).
    - Do NOT ask about numbering, page layout, or structural metadata in the source.
    - MUST produce strict JSON only. No Markdown, no surrounding backticks, no explanation.

    Example of the exact JSON structure you MUST return (use literal braces and the same keys):
    {{
      "questions": [
        {{
          "question": "An officer on SGL 08 has a disciplinary issue. According to the Public Service Rules, what committee is responsible for handling promotion, appointment, and discipline of this officer?",
          "options": [
            "Junior Staff Committee (JSC) Local",
            "Junior Staff Committee (JSC) Headquarters",
            "Senior Staff Committee (SSC)",
            "A special committee with a chairman on SGL 15 and above"
          ],
          "answer": "Senior Staff Committee (SSC)"
        }},
        {{
          "question": "A serving corps member is reported by an employer for an infraction. As a Local Government Inspector, what is the first step you would take to address the issue?",
          "options": [
            "Immediately withdraw the corps member from the PPA.",
            "Issue a query to the corps member to get a documented response.",
            "Visit the corps member's place of primary assignment and interview all parties.",
            "Invite the corps member to the office to hear their side of the story."
          ],
          "answer": "Invite the corps member to the office to hear their side of the story."
        }}
      ]
    }}
    """)

    # Instantiate model and generate
    model = genai.GenerativeModel("gemini-1.5-flash")
    try:
        response = model.generate_content(
            prompt,
            safety_settings={
                HarmCategory.HARM_CATEGORY_HARASSMENT: HarmBlockThreshold.BLOCK_NONE,
                HarmCategory.HARM_CATEGORY_HATE_SPEECH: HarmBlockThreshold.BLOCK_NONE,
                HarmCategory.HARM_CATEGORY_SEXUALLY_EXPLICIT: HarmBlockThreshold.BLOCK_NONE,
                HarmCategory.HARM_CATEGORY_DANGEROUS_CONTENT: HarmBlockThreshold.BLOCK_NONE,
            }
        )
    except Exception as e:
        logger.error(f"Gemini model call failed: {e}", exc_info=True)
        return {"questions": []}

    raw = (response.text or "").strip()
    logger.debug(f"Raw Gemini output (first 1000 chars): {raw[:1000]}")

    # Try strict json parse first
    try:
        parsed = json.loads(raw)
        return quiz_to_uniform_schema(parsed)
    except Exception as e:
        logger.warning(f"Failed to parse strict JSON. Attempting fallback. Error: {e}")

    # Attempt to extract a JSON block
    jb = _extract_first_json_block(raw)
    if jb:
        try:
            parsed = json.loads(jb)
            logger.info("Successfully parsed extracted JSON block.")
            return quiz_to_uniform_schema(parsed)
        except Exception as e:
            logger.warning(f"Parsed JSON block but json.loads failed: {e}. Attempting to clean up common issues.")
            # attempt to fix common issues: trailing commas, smart quotes, etc.
            cleaned = jb.replace("\t", " ").replace("\r", "")
            cleaned = re.sub(r",\s*}", "}", cleaned)
            cleaned = re.sub(r",\s*\]", "]", cleaned)
            cleaned = cleaned.replace("“", "\"").replace("”", "\"").replace("‘", "'").replace("’", "'")
            try:
                parsed = json.loads(cleaned)
                return quiz_to_uniform_schema(parsed)
            except Exception as e2:
                logger.warning(f"Cleaned JSON still failed: {e2}")

    # Final fallback: regex parse (best-effort)
    logger.warning("Falling back to regex parsing for questions.")
    questions = []
    # split on blank lines as heuristic
    blocks = re.split(r"\n\s*\n", raw)
    for b in blocks:
        lines = [ln.strip("- \t") for ln in b.splitlines() if ln.strip()]
        if not lines:
            continue
        # first non-empty line is question
        qtext = lines[0]
        opts = []
        # search next lines for A/B/C/D style options
        for ln in lines[1:]:
            m = re.match(r"^[A-D][\).:\-]?\s*(.+)$", ln, flags=re.I)
            if m:
                opts.append(m.group(1).strip())
            else:
                # maybe options are on single-line comma-separated
                # or the block contains numbered options; try to split by common delimiters
                parts = re.split(r"\s{2,}|\s*;\s*|\s*\|\s*", ln)
                for p in parts:
                    if p and len(opts) < 4:
                        opts.append(p.strip())
            if len(opts) >= 4:
                break

        while len(opts) < 4:
            opts.append("N/A")

        questions.append({"question": qtext, "options": opts[:4], "answer": ""})
        if len(questions) >= 10:
            break

    if questions:
        logger.info(f"Parsed {len(questions)} questions via regex fallback.")
        return {"questions": questions[:10]}

    logger.error(f"Quiz generation failed after all parsing attempts. Raw output head:\n{raw[:2000]}")
    return {"questions": []}

# --- GNews fetch helper; uses real API if credentials & package available, otherwise simulated ---
def fetch_gnews_text(query, max_results=5, language='en', country='NG'):
    """
    Try to use the GNews package if GNEWS_API_KEY is set and package available.
    Otherwise return a simulated set of recent headlines/descriptions.
    """
    gnews_key = os.getenv("GNEWS_API_KEY")
    if not gnews_key:
        logger.warning("GNEWS_API_KEY is not set; returning simulated news instead.")
        # Simulated data for current affairs context
        simulated_data = {
            "articles": [
                {"title": "Nigeria's economy shows signs of growth, says World Bank report.", "description": "The latest report highlights a 3.5% GDP increase in the last quarter.", "published date": "2025-09-12T10:00:00Z"},
                {"title": "Recent security measures in Northern Nigeria praised by global analysts.", "description": "New initiatives are aimed at curbing banditry and improving civilian safety.", "published date": "2025-09-11T15:30:00Z"},
                {"title": "National Assembly passes new bill on infrastructure development.", "description": "The new legislation focuses on public-private partnerships to build key roads and bridges.", "published date": "2025-09-10T08:45:00Z"},
                {"title": "Super Eagles' new coach looks ahead to the next AFCON qualifiers.", "description": "The team is preparing for crucial matches to secure a spot in the next African Cup of Nations.", "published date": "2025-09-09T18:00:00Z"},
                {"title": "Global oil prices continue to fluctuate, impacting Nigeria's budget.", "description": "Experts are debating the long-term effects of recent changes in the international oil market on the national economy.", "published date": "2025-09-08T09:15:00Z"}
            ]
        }
        context_text = ""
        for article in simulated_data["articles"][:max_results]:
            context_text += f"Title: {article['title']}\n"
            context_text += f"Description: {article['description']}\n"
            context_text += f"Published Date: {article['published date']}\n\n"
        return context_text

    # If key is present, try to import and use GNews package (best-effort)
    try:
        # A few different GNews libraries exist; try common ones
        try:
            from gnews import GNews
            client = GNews(language=language, country=country, max_results=max_results)
            news_articles = client.get_news(query)
            if not news_articles:
                logger.warning("GNews returned no articles; falling back to simulated.")
                return fetch_gnews_text(query, max_results=max_results, language=language, country=country)
            context_text = ""
            for art in news_articles[:max_results]:
                # the GNews library returns dicts with keys like 'title', 'description', 'published', etc.
                context_text += f"Title: {art.get('title','')}\n"
                context_text += f"Description: {art.get('description','')}\n"
                context_text += f"Published Date: {art.get('published','')}\n\n"
            return context_text
        except Exception:
            # try gnewsclient (older)
            try:
                from gnewsclient import gnewsclient
                client = gnewsclient.NewsClient(language=language, location=country, max_results=max_results)
                news_articles = client.get_news(query)
                context_text = ""
                for art in news_articles[:max_results]:
                    context_text += f"Title: {art.get('title','')}\n"
                    context_text += f"Description: {art.get('description','')}\n\n"
                return context_text
            except Exception as e2:
                logger.warning(f"GNews libs not available or failed ({e2}); falling back to simulated.")
                return fetch_gnews_text(query, max_results=max_results, language=language, country=country)
    except Exception as outer_e:
        logger.error(f"GNews fetch failed unexpectedly: {outer_e}", exc_info=True)
        return fetch_gnews_text(query, max_results=max_results, language=language, country=country)

# --- Routes ---
@app.route("/")
def home():
    return redirect(url_for("login"))

@app.route("/health")
def health():
    return jsonify({"ok": True, "time": datetime.utcnow().isoformat() + "Z"})

@app.route("/login", methods=["GET", "POST"])
def login():
    """
    Accepts form POSTs or JSON. Required field: email.
    If email is in ALLOWED_USERS, set session and redirect user appropriately.
    """
    if request.method == "POST":
        # Accept JSON or form
        if request.is_json:
            data = request.get_json(silent=True) or {}
            email = (data.get("email") or "").strip().lower()
            password = data.get("password", "")
        else:
            email = (request.form.get("email") or "").strip().lower()
            password = request.form.get("password", "")

        if not email:
            # Return a clear 400 when missing email (helps client debug)
            return jsonify({"ok": False, "error": "Email is required"}), 400

        if email not in ALLOWED_USERS:
            return jsonify({"ok": False, "error": "Unauthorized email"}), 401

        # set session
        session["user_email"] = email
        role = "admin" if email == ADMIN_USER else "user"

        if role == "admin":
            return jsonify({"ok": True, "redirect": url_for("admin_dashboard")})
        else:
            return jsonify({"ok": True, "redirect": url_for("quiz")})

    # GET -> show login page
    return render_template("login.html")

@app.route("/logout", methods=["POST"])
def logout():
    user_email = session.get("user_email")
    if user_email and db:
        try:
            user_doc_ref = db.collection("artifacts").document(APP_ID).collection("public").document("data").collection("presence_users").document(user_email.replace('.', '_'))
            user_doc_ref.delete()
        except Exception as e:
            logger.warning(f"Failed to delete presence doc for {user_email}: {e}")

    session.clear()
    return jsonify({"ok": True})

@app.route("/dashboard")
@login_required
def dashboard():
    user = session["user_email"]
    if user == ADMIN_USER:
        return redirect(url_for("admin_dashboard"))
    return render_template("dashboard.html", email=user)

@app.route("/admin_dashboard")
@admin_required
def admin_dashboard():
    return render_template("admin_dashboard.html")

@app.route("/quiz")
@login_required
def quiz():
    """Renders the quiz page for the user."""
    return render_template("quiz.html")

# --- Free Trial Quiz API ---
@app.route("/api/quiz/free_trial", methods=["POST"])
@login_required
def generate_free_quiz():
    try:
        data = request.get_json(force=True, silent=True) or {}
        grade = data.get("gl") or data.get("grade") or "GL10"
        subject = data.get("subject") or "General Knowledge"

        context_text = ""
        if subject.lower() in ["global politics", "current affairs"]:
            context_text = fetch_gnews_text("current affairs Nigeria politics")
        elif subject.lower() == "international bodies and acronyms":
            context_text = """
            What does FIFA stand for? Fédération Internationale de Football Association.
            What does FAO stand for? Food and Agriculture Organization.
            What does ECOWAS stand for? Economic Community of West African States.
            What does NAFDAC stand for? National Agency for Food and Drug Administration and Control.
            What does NSCDC stand for? Nigeria Security and Civil Defence Corps.
            What does WHO stand for? World Health Organization.
            What does UNICEF stand for? United Nations Children's Fund.
            What does AU stand for? African Union.
            What does NATO stand for? North Atlantic Treaty Organization.
            What does OPEC stand for? Organization of the Petroleum Exporting Countries.
            """
        else:
            context_text = f"Trial quiz for {subject} at grade {grade}"

        cache_key = generate_cache_key(f"{context_text}_{grade}_{subject}", 10, "freequiz")
        cached = cache_get(cache_key)
        if cached:
            return jsonify(cached)

        quiz = call_gemini_for_quiz(context_text, subject, grade)
        cache_set(cache_key, quiz, ttl_minutes=10)
        return jsonify(quiz)

    except Exception as e:
        logger.error(f"Free quiz error: {e}", exc_info=True)
        return jsonify({"error": "Quiz generation failed"}), 500

# --- Document Upload Quiz API ---
@app.route("/api/quiz/upload", methods=["POST"])
@login_required
def generate_quiz():
    try:
        if "document" not in request.files:
            return jsonify({"error": "No file uploaded"}), 400

        file = request.files["document"]
        if file.filename == "":
            return jsonify({"error": "No selected file"}), 400

        if not allowed_file(file.filename):
            return jsonify({"error": "Invalid file type"}), 400

        grade = request.form.get("grade", "GL10")
        subject = request.form.get("subject", "General Knowledge")
        filename = secure_filename(file.filename)

        suffix = os.path.splitext(filename)[1] or ".pdf"
        tmp_path = None

        try:
            with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
                file.save(tmp.name)
                tmp_path = tmp.name

            raw_text = extract_text_from_file(tmp_path)
            context_text = preprocess_text_for_quiz(raw_text)

            if not context_text:
                return jsonify({"error": "Could not extract text from uploaded file"}), 400

            cache_key = generate_cache_key(f"{context_text}_{grade}_{subject}", 60, "genquiz")
            cached = cache_get(cache_key)
            if cached:
                return jsonify(cached)

            quiz = call_gemini_for_quiz(context_text, subject, grade)

            if not quiz or not quiz.get("questions"):
                return jsonify({"error": "No questions generated from the document"}), 500

            cache_set(cache_key, quiz, ttl_minutes=60)
            return jsonify(quiz)

        except Exception as e:
            logger.error("Quiz generation failed: %s", str(e), exc_info=True)
            return jsonify({"error": "Quiz generation failed due to a server error."}), 500
        finally:
            if tmp_path and os.path.exists(tmp_path):
                try:
                    os.unlink(tmp_path)
                except Exception as cleanup_err:
                    logger.warning(f"Could not delete temp file: {cleanup_err}")

    except Exception as e:
        logger.error("Quiz generation failed: %s", str(e), exc_info=True)
        return jsonify({"error": "Quiz generation failed"}), 500

@app.route("/api/delete_topic/<topic_id>", methods=["DELETE"])
@admin_required
def delete_topic(topic_id):
    if not db:
        return jsonify({"error": "Database not configured"}), 500

    try:
        # Delete all messages within the topic first
        messages_ref = db.collection("artifacts").document(APP_ID).collection("public").document("data").collection("discussion_topics").document(topic_id).collection("messages")
        for message in messages_ref.stream():
            message.reference.delete()

        # Then delete the topic itself
        db.collection("artifacts").document(APP_ID).collection("public").document("data").collection("discussion_topics").document(topic_id).delete()
        return jsonify({"success": True, "message": "Topic deleted successfully."})
    except Exception as e:
        logger.error(f"Failed to delete discussion topic: {e}", exc_info=True)
        return jsonify({"error": "Failed to delete discussion topic"}), 500

@app.route("/api/ping", methods=["POST"])
@login_required
@limiter.limit("60 per minute")
def ping():
    try:
        user_email = session.get("user_email")
        if user_email and db:
            user_doc_ref = db.collection("artifacts").document(APP_ID).collection("public").document("data").collection("presence_users").document(user_email.replace('.', '_'))
            user_doc_ref.set({
                "user_email": user_email,
                "last_active": firestore.SERVER_TIMESTAMP,
                "role": "admin" if user_email == ADMIN_USER else "user",
            }, merge=True)
            logger.debug(f"Ping received from {user_email}, presence updated.")
        return jsonify({"status": "ok"})
    except Exception as e:
        logger.error(f"Failed to update user presence: {e}", exc_info=True)
        return jsonify({"status": "error"}), 500

# --- Online Users API (single definition) ---
@app.route("/api/online_users", methods=["GET"])
@login_required
@limiter.limit("60 per minute")
def get_online_users():
    """
    Returns users with 'last_active' within cutoff (Firestore-based).
    If Firestore is not configured, returns in-memory active_sessions.
    """
    if not db:
        # fallback to in-memory active_sessions
        cutoff = datetime.utcnow() - timedelta(seconds=60)
        users = []
        for email, last in active_sessions.items():
            if last >= cutoff:
                users.append({"user_email": email, "last_active": last.isoformat()})
        return jsonify({"count": len(users), "users": users})

    try:
        presence_ref = db.collection("artifacts").document(APP_ID).collection("public").document("data").collection("presence_users")
        cutoff = datetime.utcnow() - timedelta(seconds=60)
        # Firestore library expectation: use FieldFilter or where()
        users_stream = presence_ref.where(filter=FieldFilter("last_active", ">=", cutoff)).stream()
        online_users = [{"id": doc.id, **doc.to_dict()} for doc in users_stream]
        return jsonify({"count": len(online_users), "users": online_users})
    except Exception as e:
        logger.error(f"Failed to fetch online users: {e}", exc_info=True)
        return jsonify({"error": "Failed to fetch online users"}), 500

# --- Discussions endpoints ---
@app.route("/api/discussions", methods=["GET", "POST"])
@login_required
@limiter.limit("60 per minute")
def discussions():
    if not db:
        return jsonify({"error": "Database not configured"}), 500

    if request.method == "POST":
        data = request.get_json(silent=True) or {}
        question = data.get("question")
        if not question:
            return jsonify({"error": "Question is required"}), 400

        try:
            topics_ref = db.collection("artifacts").document(APP_ID).collection("public").document("data").collection("discussion_topics")
            new_topic_doc = topics_ref.add({
                "question": question,
                "author": session["user_email"],
                "created_at": firestore.SERVER_TIMESTAMP
            })
            topic_id = new_topic_doc[1].id
            return jsonify({"id": topic_id, "question": question})
        except Exception as e:
            logger.error(f"Failed to create discussion: {e}", exc_info=True)
            return jsonify({"error": "Failed to create discussion"}), 500
    else:
        try:
            topics_ref = db.collection("artifacts").document(APP_ID).collection("public").document("data").collection("discussion_topics")
            topics_stream = topics_ref.order_by("created_at", direction=firestore.Query.DESCENDING).stream()
            topics = [{"id": doc.id, **doc.to_dict()} for doc in topics_stream]
            return jsonify(topics)
        except Exception as e:
            logger.error(f"Failed to fetch discussions: {e}", exc_info=True)
            return jsonify({"error": "Failed to fetch discussions"}), 500

@app.route("/api/discussions/<topic_id>/messages", methods=["GET", "POST"])
@login_required
@limiter.limit("60 per minute")
def discussion_messages(topic_id):
    if not db:
        return jsonify({"error": "Database not configured"}), 500

    if request.method == "POST":
        data = request.get_json(silent=True) or {}
        message_text = data.get("message")
        if not message_text:
            return jsonify({"error": "Message text is required"}), 400

        try:
            messages_ref = db.collection("artifacts").document(APP_ID).collection("public").document("data").collection("discussion_topics").document(topic_id).collection("messages")
            new_message_ref = messages_ref.add({
                "text": message_text,
                "author": session["user_email"],
                "created_at": firestore.SERVER_TIMESTAMP,
                "is_admin": session.get("user_email") == ADMIN_USER
            })
            return jsonify({"id": new_message_ref[1].id, "message": message_text})
        except Exception as e:
            logger.error(f"Failed to post message: {e}", exc_info=True)
            return jsonify({"error": "Failed to post message"}), 500
    else:
        try:
            messages_ref = db.collection("artifacts").document(APP_ID).collection("public").document("data").collection("discussion_topics").document(topic_id).collection("messages")
            messages_stream = messages_ref.order_by("created_at").stream()
            message_list = [{"id": msg.id, **msg.to_dict()} for msg in messages_stream]
            return jsonify(message_list)
        except Exception as e:
            logger.error(f"Failed to get messages: {e}", exc_info=True)
            return jsonify({"error": "Failed to get messages"}), 500

@app.route("/api/discussions/<topic_id>/summary", methods=["POST"])
@login_required
@limiter.limit("10 per day")
def discussion_summary(topic_id):
    if not db:
        return jsonify({"error": "Database not configured"}), 500

    try:
        cache_key = f"summary:{topic_id}"
        cached_summary = cache_get(cache_key)
        if cached_summary:
            topic_doc = db.collection("artifacts").document(APP_ID).collection("public").document("data").collection("discussion_topics").document(topic_id).get()
            return jsonify({"topic_title": topic_doc.to_dict().get("question"), "summary": cached_summary})

        topic_doc = db.collection("artifacts").document(APP_ID).collection("public").document("data").collection("discussion_topics").document(topic_id).get()
        if not topic_doc.exists:
            return jsonify({"error": "Topic not found"}), 404

        messages_ref = db.collection("artifacts").document(APP_ID).collection("public").document("data").collection("discussion_topics").document(topic_id).collection("messages")
        messages_stream = messages_ref.order_by("created_at").stream()
        message_list = [f"{msg.to_dict()['author']}: {msg.to_dict()['text']}" for msg in messages_stream]

        joined_messages = "\n".join(message_list)

        prompt = f"""
        Summarize the following discussion among NYSC staff and corps members.
        Provide a clear, professional, and accurate summary and answer raised questions where possible.

        Discussion:
        {joined_messages}
        """
        model = genai.GenerativeModel("gemini-1.5-flash")
        response = model.generate_content(prompt)
        summary = (response.text or "").strip()

        cache_set(cache_key, summary, ttl_minutes=60)
        logger.info(f"Summary for topic {topic_id} generated and cached.")

        return jsonify({"topic_title": topic_doc.to_dict().get("question"), "summary": summary})
    except Exception as e:
        logger.error(f"Gemini summary failed: {e}", exc_info=True)
        return jsonify({"error": "Failed to generate summary"}), 500

# --- App entrypoint ---
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "5000")))
