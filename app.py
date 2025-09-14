# app.py
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

# --- GNews API Key (set in env) ---
GNEWS_API_KEY = os.getenv("GNEWS_API_KEY")  # set this in your environment to your GNews key

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
def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

def extract_text_from_file(file_path):
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
        logger.error(f"File extraction failed: {e}")
    return (text or "").strip()

def preprocess_text_for_quiz(text):
    lines = text.split('\n')
    processed_lines = []
    for line in lines:
        stripped_line = line.strip()
        if re.match(r'^(Chapter|Section)\s+\S+$', stripped_line, re.I):
            continue
        if re.match(r'^\s*\d{6}\s+\S+', stripped_line):
            continue
        processed_lines.append(line)
    processed_text = '\n'.join(processed_lines)
    processed_text = re.sub(r'Questions?\s*\d*\s*[\.\-]', '', processed_text, flags=re.I)
    processed_text = re.sub(r'\s*Answer\s*[\.\-]', '', processed_text, flags=re.I)
    return processed_text.strip()

def generate_cache_key(base, ttl_minutes, prefix=""):
    h = hashlib.md5(base.encode()).hexdigest()
    return f"{prefix}_{h}_{ttl_minutes}"

def cache_set(key, value, ttl_minutes=5):
    cache[key] = {"value": value, "expires": datetime.now() + timedelta(minutes=ttl_minutes)}

def cache_get(key):
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
    logger.info(f"{request.remote_addr} {request.method} {request.path} {response.status_code}")
    return response

# --- Robust Gemini quiz parsing ---
def _extract_first_json_block(text: str):
    if not text:
        return None
    # First, look for code-fenced JSON
    m = re.search(r"```json\s*(\{.*?\})\s*```", text, flags=re.S)
    if m:
        return m.group(1)
    # Then, try to find a standalone JSON object
    m = re.search(r"(\{(?:.|\n)*\})", text)
    if m:
        return m.group(1)
    return None

def quiz_to_uniform_schema(quiz_obj):
    out = {"questions": []}
    items = quiz_obj.get("questions") or quiz_obj.get("quiz") or []

    for q in items:
        question = str(q.get("question") or q.get("q") or "").strip()
        options = q.get("options") or q.get("choices") or []
        answer = str(q.get("answer") or q.get("correct") or q.get("correct_answer") or "").strip()

        if isinstance(options, dict):
            keys = ["A", "B", "C", "D"]
            options = [options.get(k, "").strip() for k in keys if options.get(k)]

        if isinstance(options, list):
            options = [str(o).strip() for o in options if o]
        else:
            options = []

        while len(options) < 4:
            options.append("N/A")
        options = options[:4]

        if answer not in options:
            answer = ""

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
    """
    prompt = f"""
    You are an expert in Nigerian Public Service Rules and NYSC regulations, tasked with generating a high-quality promotional exam. Your questions must be based ONLY on the provided context.

    Source material:
    {context_text[:4000]}  # limit to first 4000 chars for context

    Guidelines for Exam Questions:
    - Create 5-10 multiple-choice questions.
    - Each question must have exactly 4 options (A, B, C, D).
    - Questions should test a candidate's practical knowledge of duties, rights, and administrative procedures.
    - Questions should be derived from the three main categories in the source document: NYSC Operations, Public Service Rules, and Current Affairs.
    - DO NOT ask questions about the document's structure, such as question numbers, section names, or list counts.
    - Each item must include: "question", "options", "answer".
    - The "answer" must exactly match one of the options.
    - Return output in strict JSON format ONLY, with no extra commentary.
    """

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
        logger.error(f"Gemini call failed: {e}", exc_info=True)
        return {"questions": []}

    raw = (response.text or "").strip()

    try:
        # Try parsing as strict JSON
        return quiz_to_uniform_schema(json.loads(raw))
    except json.JSONDecodeError as e:
        logger.warning(f"Failed to parse strict JSON. Attempting fallback methods. Error: {e}")
        
    # If that fails, try to extract a JSON block
    jb = _extract_first_json_block(raw)
    if jb:
        try:
            logger.info("Successfully extracted a JSON block. Parsing...")
            return quiz_to_uniform_schema(json.loads(jb))
        except json.JSONDecodeError as e:
            logger.warning(f"Failed to parse extracted JSON block. Error: {e}")
    
    # As a final fallback, try regex parsing
    logger.warning("All JSON parsing failed. Falling back to regex.")
    questions = []
    blocks = re.split(r"\n\s*\n", raw)
    for b in blocks:
        lines = [ln.strip("- ").strip() for ln in b.split("\n") if ln.strip()]
        if len(lines) >= 5:
            q = lines[0]
            opts = []
            for ln in lines[1:5]:
                m = re.match(r"^[A-D][\).:\-]\s*(.+)$", ln, flags=re.I)
                opts.append(m.group(1) if m else ln)
            while len(opts) < 4:
                opts.append("N/A")
            questions.append({"question": q, "options": opts[:4], "answer": ""})
    
    if questions:
        logger.info(f"Successfully parsed {len(questions)} questions via regex.")
        return {"questions": questions[:5]}

    # If all parsing fails, log and return empty quiz
    logger.error(f"Quiz generation failed after all parsing attempts. Raw output:\n{raw}", exc_info=True)
    return {"questions": []}

def fetch_gnews_text(query, max_results=5, language='en', country='ng'):
    """
    Fetch news from GNews (gnews.io). Requires GNEWS_API_KEY set in environment.
    Falls back to a simulated result if key not set or the request fails.
    """
    if not GNEWS_API_KEY:
        logger.warning("GNEWS_API_KEY is not set; returning simulated news instead.")
        # Simulated fallback (short)
        simulated = [
            {"title": "Nigeria's economy shows signs of growth", "description": "GDP rises according to recent report.", "publishedAt": "2025-09-12T10:00:00Z"},
            {"title": "Security measures praised in Northern Nigeria", "description": "New initiatives to curb banditry.", "publishedAt": "2025-09-11T15:30:00Z"},
        ]
        ctx = ""
        for a in simulated[:max_results]:
            ctx += f"Title: {a['title']}\nDescription: {a['description']}\nPublished Date: {a['publishedAt']}\n\n"
        return ctx

    endpoint = "https://gnews.io/api/v4/search"
    params = {
        "q": query,
        "token": GNEWS_API_KEY,
        "lang": language,
        "max": max_results,
        "country": country
    }
    try:
        resp = requests.get(endpoint, params=params, timeout=8)
        resp.raise_for_status()
        data = resp.json()

        # GNews returns 'articles' list; normalize into context text
        articles = data.get("articles") or []
        if not articles:
            logger.info("GNews returned no articles; returning simulated text.")
            return fetch_gnews_text(query, max_results, language, country)  # fallback to simulated

        ctx = ""
        for art in articles[:max_results]:
            title = art.get("title", "")
            desc = art.get("description", "") or art.get("content", "")
            pub = art.get("publishedAt", art.get("published date", ""))
            ctx += f"Title: {title}\n"
            ctx += f"Description: {desc}\n"
            ctx += f"Published Date: {pub}\n\n"
        return ctx
    except Exception as e:
        logger.error(f"GNews fetch failed: {e}", exc_info=True)
        # fallback to simulated
        return fetch_gnews_text(query, max_results, language, country)

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
        user_doc_ref = db.collection("artifacts").document(APP_ID).collection("public").document("data").collection("presence_users").document(user_email.replace('.', '_'))
        try:
            user_doc_ref.delete()
        except Exception:
            logger.exception("Failed to remove presence doc during logout.")
    
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

# --- This is the endpoint your front-end was hitting (POST /generate_quiz) ---
# It returns a quiz based on current affairs using GNews when subject is "current affairs".
@app.route("/generate_quiz", methods=["POST"])
@login_required
def generate_quiz_page():
    try:
        # Support both JSON and form submissions
        if request.is_json:
            data = request.get_json(silent=True) or {}
            subject = data.get("subject", "Current Affairs")
            grade = data.get("grade", "GL10")
        else:
            subject = request.form.get("subject", "Current Affairs")
            grade = request.form.get("grade", "GL10")

        # If subject implies news/current affairs -> fetch from GNews
        if subject and subject.lower() in ["current affairs", "global politics", "news", "current events"]:
            context_text = fetch_gnews_text("Nigeria current affairs", max_results=6)
        else:
            # fallback simple context
            context_text = f"Trial quiz for {subject} at grade {grade}"

        cache_key = generate_cache_key(f"{context_text}_{grade}_{subject}", 10, "pagequiz")
        cached = cache_get(cache_key)
        if cached:
            return jsonify(cached)

        quiz = call_gemini_for_quiz(context_text, subject, grade)
        cache_set(cache_key, quiz, ttl_minutes=10)
        return jsonify(quiz)

    except Exception as e:
        logger.error(f"generate_quiz_page failed: {e}", exc_info=True)
        return jsonify({"error": "Failed to generate quiz"}), 500

# --- Free Trial Quiz API ---
@app.route("/api/quiz/free_trial", methods=["POST"])
@login_required
def api_generate_free_quiz():
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
def api_generate_quiz_upload():
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

# --- Online Users API (single definition; fixed duplicate issue) ---
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

@app.route("/api/discussions", methods=["GET", "POST"])
@login_required
@limiter.limit("60 per minute")
def discussions():
    if not db:
        return jsonify({"error": "Database not configured"}), 500
        
    if request.method == "POST":
        data = request.get_json()
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

    else: # GET request
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
        data = request.get_json()
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
    else: # GET request
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
        # Check for summary in cache
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
        Provide a clear, professional, and accurate summary with an authentic answer
        if users raised questions.

        Discussion:
        {joined_messages}
        """
        model = genai.GenerativeModel("gemini-1.5-flash")
        response = model.generate_content(prompt)
        summary = (response.text or "").strip()

        # Save summary to cache
        cache_set(cache_key, summary, ttl_minutes=60) # Cache for 60 minutes
        logger.info(f"Summary for topic {topic_id} generated and cached.")

        return jsonify({"topic_title": topic_doc.to_dict().get("question"), "summary": summary})
    except Exception as e:
        logger.error(f"Gemini summary failed: {e}", exc_info=True)
        return jsonify({"error": "Failed to generate summary"}), 500

# --- Run ---
if __name__ == "__main__":
    # Recommended: configure host/port via env vars in production
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "5000")))
