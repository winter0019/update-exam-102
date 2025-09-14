# app.py
import os
import re
import json
import uuid
import hashlib
import traceback
from datetime import datetime, timedelta
from functools import wraps
from typing import Optional

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

# --- Rate Limiter ---
limiter = Limiter(get_remote_address, app=app, default_limits=["100 per day", "20 per hour"])

# --- Logger ---
logger.remove()
logger.add("logs/app_{time}.log", rotation="1 day", level="INFO")
logger.add(lambda msg: print(msg, flush=True), level="INFO")  # also log to stdout

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
# Dictionary to store cached quiz data
cache = {}

# --- Helpers ---
def allowed_file(filename: str) -> bool:
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

def extract_text_from_file(file_path: str) -> str:
    text = ""
    ext = os.path.splitext(file_path)[1].lower().lstrip(".")
    try:
        if ext == "pdf":
            with open(file_path, "rb") as f:
                reader = PyPDF2.PdfReader(f)
                for page in reader.pages:
                    text_page = page.extract_text()
                    if text_page:
                        text += text_page + "\n"
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

def preprocess_text_for_quiz(text: str) -> str:
    lines = text.split('\n')
    processed_lines = []
    for line in lines:
        stripped_line = line.strip()
        # Skip chapter/section headings that are likely irrelevant
        if re.match(r'^(Chapter|Section)\s+\S+$', stripped_line, re.I):
            continue
        # Skip lines that look like IDs or exam numbers
        if re.match(r'^\s*\d{6}\s+\S+', stripped_line):
            continue
        processed_lines.append(line)
    processed_text = '\n'.join(processed_lines)
    processed_text = re.sub(r'Questions?\s*\d*\s*[\.\-:]*', '', processed_text, flags=re.I)
    processed_text = re.sub(r'\s*Answer\s*[\.\-:]*', '', processed_text, flags=re.I)
    processed_text = re.sub(r'\s{2,}', ' ', processed_text)
    return processed_text.strip()

def generate_cache_key(base: str, ttl_minutes: int, prefix: str = "") -> str:
    h = hashlib.md5(base.encode()).hexdigest()
    return f"{prefix}_{h}_{ttl_minutes}"

def cache_set(key: str, value, ttl_minutes: int = 5):
    cache[key] = {"value": value, "expires": datetime.now() + timedelta(minutes=ttl_minutes)}

def cache_get(key: str):
    if key in cache:
        if datetime.now() < cache[key]["expires"]:
            return cache[key]["value"]
        del cache[key]
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
    if 'user_email' in session:
        active_sessions[session['user_email']] = datetime.utcnow()

@app.after_request
def after_request_hook(response):
    try:
        logger.info(f"{request.remote_addr} {request.method} {request.path} {response.status_code}")
    except Exception:
        # Logging should not break responses
        pass
    return response

# --- Robust Gemini quiz parsing utilities ---
def _extract_first_json_block(text: str) -> Optional[str]:
    if not text:
        return None
    # First, look for triple-backticked JSON blocks
    m = re.search(r"```json\s*(\{.*?\})\s*```", text, flags=re.S)
    if m:
        return m.group(1)
    # Then, try to find the first balanced-looking JSON object (naive)
    m = re.search(r"(\{(?:[^{}]|(?R))*\})", text, flags=re.S) if hasattr(re, 'R') else re.search(r"(\{(?:.|\n)*\})", text)
    if m:
        return m.group(1)
    # Simple fallback: first { ... } pair
    m = re.search(r"(\{(?:.|\n)*?\})", text)
    if m:
        return m.group(1)
    return None

def quiz_to_uniform_schema(quiz_obj: dict):
    out = {"questions": []}
    items = quiz_obj.get("questions") or quiz_obj.get("quiz") or []
    if not isinstance(items, list):
        # If items is a dict keyed by indices, transform
        if isinstance(items, dict):
            items = list(items.values())
        else:
            items = []

    for q in items:
        if not isinstance(q, dict):
            continue
        question = str(q.get("question") or q.get("q") or "").strip()
        options = q.get("options") or q.get("choices") or []
        answer = str(q.get("answer") or q.get("correct") or q.get("correct_answer") or "").strip()

        if isinstance(options, dict):
            # sometimes options are a dict like {"A": "...", "B": "..."}
            keys = sorted(options.keys())
            options = [options[k].strip() for k in keys if options.get(k)]

        if isinstance(options, list):
            options = [str(o).strip() for o in options if o is not None and str(o).strip() != ""]
        else:
            options = []

        # Normalize to exactly 4 entries
        while len(options) < 4:
            options.append("N/A")
        options = options[:4]

        # Ensure answer matches one of the options; otherwise blank it
        if answer and answer not in options:
            # Accept letter-form answers like "A" or "B"
            if re.fullmatch(r'^[A-Da-d]$', answer):
                idx = ord(answer.upper()) - ord('A')
                if 0 <= idx < len(options):
                    answer = options[idx]
                else:
                    answer = ""
            else:
                answer = ""

        if question:
            out["questions"].append({
                "question": question,
                "options": options,
                "answer": answer
            })
    return out

# --- GNews integration (real if key present, simulated otherwise) ---
GNEWS_API_KEY = os.getenv("GNEWS_API_KEY")

def fetch_gnews_text(query: str, max_results: int = 5, language: str = 'en', country: str = 'ng') -> str:
    """
    Fetch short titles/descriptions from GNews.io (if configured) otherwise return
    a simulated set. Returns concatenated string suitable for passing to Gemini as context.
    """
    if not GNEWS_API_KEY:
        logger.warning("GNEWS_API_KEY is not set; returning simulated news instead.")
        # Simulated data (kept small intentionally)
        simulated_data = [
            {"title": "Nigeria's economy shows signs of growth, says World Bank report.", "description": "The latest report highlights a 3.5% GDP increase in the last quarter.", "publishedAt": "2025-09-12T10:00:00Z"},
            {"title": "National Assembly passes new bill on infrastructure development.", "description": "The new legislation focuses on public-private partnerships.", "publishedAt": "2025-09-10T08:45:00Z"},
            {"title": "Security initiatives aimed at curbing banditry in Northern Nigeria.", "description": "Local governments welcome the new measures.", "publishedAt": "2025-09-11T15:30:00Z"}
        ]
        context_text = ""
        for a in simulated_data[:max_results]:
            context_text += f"Title: {a['title']}\nDescription: {a['description']}\nPublished At: {a['publishedAt']}\n\n"
        return context_text

    try:
        # Use the GNews API at https://gnews.io/ -- note: limits apply.
        url = "https://gnews.io/api/v4/search"
        params = {
            "q": query,
            "token": GNEWS_API_KEY,
            "lang": language,
            "country": country,
            "max": max_results
        }
        resp = requests.get(url, params=params, timeout=8)
        resp.raise_for_status()
        data = resp.json()
        articles = data.get("articles", [])[:max_results]
        if not articles:
            return "No recent articles found for this topic."

        context_text = ""
        for article in articles:
            context_text += f"Title: {article.get('title')}\n"
            context_text += f"Description: {article.get('description')}\n"
            context_text += f"Published Date: {article.get('publishedAt') or article.get('published date')}\n\n"
        return context_text
    except Exception as e:
        logger.error(f"GNews fetch failed: {e}", exc_info=True)
        # fallback to simulated data
        return fetch_gnews_text(query, max_results, language, country)

# --- Gemini (Gemini-1.5-flash) quiz generation with strict JSON prompt & retries ---
def _strict_json_prompt(context_text: str, subject: str, grade: str, num_questions: int = 6) -> str:
    """
    Construct a prompt that *requires* a strict JSON output and includes an explicit
    JSON schema with examples. Keep context_text trimmed to avoid hitting model input length.
    """
    ctx = context_text.strip()
    if len(ctx) > 3800:
        ctx = ctx[:3800] + "\n\n[TRUNCATED]"
    prompt = f"""
You are an expert exam writer for Nigerian public service and NYSC exams.
Using ONLY the provided source material, generate exactly {num_questions} high-quality multiple-choice questions.

Source material (use only information from this block):
{ctx}

REQUIREMENTS:
- Output MUST be valid JSON only. No commentary, no explanation, nothing before or after the JSON.
- Use this schema exactly:

{{
  "questions": [
    {{
      "question": "<string>",
      "options": ["<string>", "<string>", "<string>", "<string>"],
      "answer": "<string>"   // must be exactly one of the options above
    }}
  ]
}}

- Provide exactly {num_questions} objects in the "questions" array.
- Each "options" array must contain exactly 4 items (A - D) in logical order.
- The "answer" field must match exactly one of those 4 options (do not provide letters).
- Keep each question concise (max 2 sentences).
- Do not invent facts not supported by the source. If the source doesn't contain enough facts, make safe plausible questions tied to the source.
- If you cannot create {num_questions} from the source alone, create as many as you can (minimum 3). Still output a valid JSON structure.

Return the JSON only.
"""
    return prompt

def call_gemini_for_quiz(context_text: str, subject: str, grade: str, num_questions: int = 6):
    """
    Ask Gemini to generate realistic NYSC/public service MCQs. Implements:
      - strict JSON prompt
      - multiple parsing attempts and clear logging
      - fallback regex parsing only as last resort
    """
    prompt = _strict_json_prompt(context_text, subject, grade, num_questions=num_questions)

    model = genai.GenerativeModel("gemini-1.5-flash")

    try:
        response = model.generate_content(
            prompt,
            safety_settings={
                HarmCategory.HARM_CATEGORY_HARASSMENT: HarmBlockThreshold.BLOCK_NONE,
                HarmCategory.HARM_CATEGORY_HATE_SPEECH: HarmBlockThreshold.BLOCK_NONE,
                HarmCategory.HARM_CATEGORY_SEXUALLY_EXPLICIT: HarmBlockThreshold.BLOCK_NONE,
                HarmCategory.HARM_CATEGORY_DANGEROUS_CONTENT: HarmBlockThreshold.BLOCK_NONE,
            },
            # optional: temperature or other generation params can go here
        )
    except Exception as e:
        logger.error(f"Gemini API call failed: {e}", exc_info=True)
        return {"questions": []}

    raw = (response.text or "").strip()
    logger.debug(f"Raw Gemini response:\n{raw[:4000]}")

    # First attempt: parse full response as JSON
    try:
        parsed = json.loads(raw)
        uniform = quiz_to_uniform_schema(parsed)
        if uniform and uniform.get("questions"):
            logger.info("Parsed strict JSON from Gemini response successfully.")
            return uniform
    except json.JSONDecodeError as e:
        logger.warning(f"Failed to parse strict JSON. Attempting fallback methods. Error: {e}")

    # Second attempt: extract JSON block and parse
    jb = _extract_first_json_block(raw)
    if jb:
        try:
            parsed = json.loads(jb)
            uniform = quiz_to_uniform_schema(parsed)
            if uniform and uniform.get("questions"):
                logger.info("Successfully extracted and parsed a JSON block from Gemini response.")
                return uniform
        except json.JSONDecodeError as e:
            logger.warning(f"Failed to parse extracted JSON block. Error: {e}")

    # Third attempt: try to normalize a common pattern like "questions": [...]
    try:
        m = re.search(r'"questions"\s*:\s*(\[[\s\S]*\])', raw)
        if m:
            candidate = m.group(1)
            parsed = json.loads(candidate)
            if isinstance(parsed, list):
                uniform = quiz_to_uniform_schema({"questions": parsed})
                if uniform and uniform.get("questions"):
                    logger.info("Parsed 'questions' array extracted by regex.")
                    return uniform
    except Exception as e:
        logger.debug(f"Regex extraction of 'questions' array failed: {e}")

    # Last resort: heuristic regex parsing into basic question/options
    logger.warning("All JSON parsing failed. Falling back to heuristic regex parsing of plain text.")
    questions = []
    # split by double newlines or lines starting with Q or 1.
    blocks = re.split(r'\n\s*\n', raw)
    for b in blocks:
        lines = [ln.strip("-* \t\r") for ln in b.split("\n") if ln.strip()]
        if not lines:
            continue
        # First non-empty line likely the question
        qline = lines[0]
        # Collect up to 4 option lines starting with A/B/C/D or (a)/1.
        opts = []
        for ln in lines[1:]:
            if re.match(r'^[A-Da-d][\)\.\-:]\s*', ln) or re.match(r'^\([A-Da-d]\)', ln):
                # strip leading letter
                opt = re.sub(r'^[A-Da-d][\)\.\-:]\s*', '', ln)
                opt = re.sub(r'^\([A-Da-d]\)\s*', '', opt)
                opts.append(opt.strip())
            else:
                # fallback: if the line contains " or " maybe options were inline
                parts = re.split(r'\s*\|\s*', ln)
                if len(parts) >= 4 and not opts:
                    opts = [p.strip() for p in parts[:4]]
        # If options still insufficient, try to find lettered tokens within the block
        if len(opts) < 4:
            lettered = re.findall(r'[A-Da-d][\)\.\-:]\s*([^\n]+)', b)
            for it in lettered:
                if len(opts) >= 4:
                    break
                opts.append(it.strip())
        while len(opts) < 4:
            opts.append("N/A")
        if qline and opts:
            questions.append({"question": qline, "options": opts[:4], "answer": ""})
        if len(questions) >= num_questions:
            break

    if questions:
        logger.info(f"Parsed {len(questions)} question(s) via heuristic parsing.")
        return {"questions": questions[:num_questions]}

    # If everything fails
    logger.error("Quiz generation failed after all parsing attempts. Returning empty quiz.", exc_info=True)
    return {"questions": []}

# --- Routes ---
@app.route("/")
def home():
    return redirect(url_for("login"))

@app.route("/health")
def health():
    return jsonify({"ok": True, "time": datetime.utcnow().isoformat() + "Z"})

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        if request.is_json:
            data = request.get_json(silent=True) or {}
            email = data.get("email", "").lower()
            password = data.get("password", "")
        else:
            email = request.form.get("email", "").lower()
            password = request.form.get("password", "")

        if email not in ALLOWED_USERS:
            return jsonify({"ok": False, "error": "Unauthorized email"}), 401

        session["user_email"] = email
        role = "admin" if email == ADMIN_USER else "user"
        
        if role == "admin":
            return jsonify({"ok": True, "redirect": url_for("admin_dashboard")})
        else:
            return jsonify({"ok": True, "redirect": url_for("quiz")})

    return render_template("login.html")

@app.route("/logout", methods=["POST"])
def logout():
    user_email = session.get("user_email")
    if user_email and db:
        try:
            user_doc_ref = db.collection("artifacts").document(APP_ID).collection("public").document("data").collection("presence_users").document(user_email.replace('.', '_'))
            user_doc_ref.delete()
        except Exception as e:
            logger.warning(f"Failed to remove presence document for {user_email}: {e}", exc_info=True)
    
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
            logger.info("Serving free quiz from cache.")
            return jsonify(cached)

        quiz = call_gemini_for_quiz(context_text, subject, grade, num_questions=6)
        cache_set(cache_key, quiz, ttl_minutes=10)
        return jsonify(quiz)

    except Exception as e:
        logger.error(f"Free quiz error: {e}", exc_info=True)
        return jsonify({"error": "Quiz generation failed"}), 500

# --- Document Upload Quiz API (primary) ---
@app.route("/api/quiz/upload", methods=["POST"])
@login_required
def generate_quiz_upload():
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
                logger.info("Serving generated quiz from cache.")
                return jsonify(cached)

            quiz = call_gemini_for_quiz(context_text, subject, grade, num_questions=8)
            
            if not quiz or not quiz.get("questions"):
                return jsonify({"error": "No questions generated from the document"}), 500

            cache_set(cache_key, quiz, ttl_minutes=60)
            return jsonify(quiz)

        except Exception as e:
            logger.error("Quiz generation failed (upload route): %s", str(e), exc_info=True)
            return jsonify({"error": "Quiz generation failed due to a server error."}), 500
        finally:
            if tmp_path and os.path.exists(tmp_path):
                try:
                    os.unlink(tmp_path)
                except Exception as cleanup_err:
                    logger.warning(f"Could not delete temp file: {cleanup_err}")

    except Exception as e:
        logger.error("Quiz generation failed (upload outer): %s", str(e), exc_info=True)
        return jsonify({"error": "Quiz generation failed"}), 500

# --- Backwards compatible route some UIs post to (/generate_quiz) ---
@app.route("/generate_quiz", methods=["POST"])
@login_required
def generate_quiz_alias():
    # Mirror fields expected by older frontend (multipart form)
    return generate_quiz_upload()

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

# --- Online Users API (single, non-duplicated) ---
@app.route("/api/online_users", methods=["GET"])
@login_required
@limiter.limit("60 per minute")
def get_online_users():
    if not db:
        return jsonify({"error": "Database not configured"}), 500
    
    try:
        presence_ref = db.collection("artifacts").document(APP_ID).collection("public").document("data").collection("presence_users")
        cutoff = datetime.utcnow() - timedelta(seconds=60)
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
        data = request.get_json() or {}
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

    else:  # GET request
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
        data = request.get_json() or {}
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
    else:  # GET request
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
        # Get topic doc (we need it whether cached or not)
        topic_doc_ref = db.collection("artifacts").document(APP_ID).collection("public").document("data").collection("discussion_topics").document(topic_id)
        topic_doc = topic_doc_ref.get()
        if not topic_doc.exists:
            return jsonify({"error": "Topic not found"}), 404

        cache_key = f"summary:{topic_id}"
        cached_summary = cache_get(cache_key)
        if cached_summary:
            logger.info(f"Summary for topic {topic_id} served from cache.")
            return jsonify({"topic_title": topic_doc.to_dict().get("question"), "summary": cached_summary})

        messages_ref = topic_doc_ref.collection("messages")
        messages_stream = messages_ref.order_by("created_at").stream()
        message_list = [f"{msg.to_dict().get('author')}: {msg.to_dict().get('text')}" for msg in messages_stream]
        
        joined_messages = "\n".join(message_list)
        
        prompt = f"""
Summarize the following discussion among NYSC staff and corps members.
Provide a clear, professional, and accurate summary with an authentic answer
if users raised questions.

Discussion:
{joined_messages}
"""
        model = genai.GenerativeModel("gemini-1.5-flash")
        response = model.generate_content(prompt)
        summary = (response.text or "").strip()

        # Save summary to cache
        cache_set(cache_key, summary, ttl_minutes=60)  # Cache for 60 minutes
        logger.info(f"Summary for topic {topic_id} generated and cached.")

        return jsonify({"topic_title": topic_doc.to_dict().get("question"), "summary": summary})
    except Exception as e:
        logger.error(f"Gemini summary failed: {e}", exc_info=True)
        return jsonify({"error": "Failed to generate summary"}), 500

# --- Admin-only: delete all presence (example utility) ---
@app.route("/api/admin/clear_presence", methods=["POST"])
@admin_required
def admin_clear_presence():
    if not db:
        return jsonify({"error": "Database not configured"}), 500
    try:
        presence_ref = db.collection("artifacts").document(APP_ID).collection("public").document("data").collection("presence_users")
        for doc in presence_ref.stream():
            doc.reference.delete()
        return jsonify({"ok": True})
    except Exception as e:
        logger.error(f"Failed to clear presence: {e}", exc_info=True)
        return jsonify({"error": "Failed to clear presence"}), 500

# --- Run ---
if __name__ == "__main__":
    # Helpful debug/launch logging
    logger.info("Starting app with GEMINI_API_KEY set: %s", bool(GEMINI_API_KEY))
    logger.info("Starting app with GNEWS_API_KEY set: %s", bool(GNEWS_API_KEY))
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "5000")), debug=False)
