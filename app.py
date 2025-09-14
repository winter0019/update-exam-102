#!/usr/bin/env python3
"""
app.py - NYSC / Public Service Quiz Generator (updated)

This is the full application file incorporating:
 - GNews integration (uses python-gnews if available; falls back to simulated news)
 - Stricter JSON-only prompt for Gemini (ask model to only return JSON, with delimiters)
 - Defensive parsing of model output (code fences, JSON block extraction, regex fallback)
 - Single definition of the /api/online_users endpoint (removed duplicates)
 - Added a convenience route /generate_quiz used by the frontend (falls back to GNews when no topic)
 - Improved logging and error messages

Notes:
 - Make sure environment variables are set:
    GEMINI_API_KEY - required
    SECRET_KEY - optional (defaults to 'super-secret-key')
    FIREBASE_SERVICE_ACCOUNT - optional (JSON string)
    GNEWS_API_KEY - optional (if set and python-gnews is available, will be used)
 - This file is intentionally self-contained and verbose for clarity.
"""

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

# Google Gemini client
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

# Try to import GNews library. If not available, we'll fallback.
try:
    from gnews import GNews  # python package 'gnews'
    GNEWS_AVAILABLE = True
except Exception:
    GNEWS_AVAILABLE = False

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
        # Firebase service account string may be a JSON string or a path; try to parse as JSON first
        try:
            cred_dict = json.loads(firebase_json) if isinstance(firebase_json, str) else firebase_json
            cred = credentials.Certificate(cred_dict)
        except Exception:
            # maybe it's a path
            cred = credentials.Certificate(firebase_json)
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
                    # Some PDFs might return None for extract_text()
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
    """
    Perform basic cleanup of extracted text to remove headers/footers,
    question numbering artifacts, and other noise that could confuse the LLM.
    """
    lines = text.split('\n')
    processed_lines = []
    for line in lines:
        stripped_line = line.strip()
        # Remove lines that look like chapter/section headings
        if re.match(r'^(Chapter|Section)\s+\S+', stripped_line, re.I):
            continue
        # Remove lines that start with 6-digit codes like exam ids etc
        if re.match(r'^\s*\d{6}\s+\S+', stripped_line):
            continue
        processed_lines.append(line)
    processed_text = '\n'.join(processed_lines)
    processed_text = re.sub(r'Questions?\s*\d*\s*[\.\-]', '', processed_text, flags=re.I)
    processed_text = re.sub(r'\s*Answer\s*[\.\-]', '', processed_text, flags=re.I)
    # Collapse multiple blank lines
    processed_text = re.sub(r'\n{3,}', '\n\n', processed_text)
    return processed_text.strip()

def generate_cache_key(base, ttl_minutes, prefix=""):
    # Use md5 of base to keep key length reasonable
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
    """
    Attempt to find the first JSON object inside the text.
    It looks for code-fenced JSON blocks first, then raw {...} blocks.
    """
    if not text:
        return None
    # First, look for code-fenced JSON
    m = re.search(r"```json\s*(\{(?:.|\n)*?\})\s*```", text, flags=re.I | re.S)
    if m:
        return m.group(1)
    # Look for any JSON object (non-greedy)
    m = re.search(r"(\{(?:.|\n)*?\})", text, flags=re.S)
    if m:
        return m.group(1)
    return None

def quiz_to_uniform_schema(quiz_obj):
    """
    Normalize a variety of possible quiz structures into:
    {
      "questions": [
         {"question": str, "options": [A,B,C,D], "answer": correct_option_or_empty}
      ]
    }
    """
    out = {"questions": []}
    items = quiz_obj.get("questions") or quiz_obj.get("quiz") or quiz_obj.get("items") or []

    for q in items:
        # q might be str or dict
        if isinstance(q, str):
            # best effort: skip raw strings
            continue
        if not isinstance(q, dict):
            continue

        question = str(q.get("question") or q.get("q") or q.get("prompt") or "").strip()
        options = q.get("options") or q.get("choices") or q.get("answers") or []
        answer = str(q.get("answer") or q.get("correct") or q.get("correct_answer") or "").strip()

        # options might be dict mapping A-D
        if isinstance(options, dict):
            # Ensure order A, B, C, D when present
            keys = ["A", "B", "C", "D"]
            options = [options.get(k, "").strip() for k in keys if options.get(k)]
        # options might be a string separated by newlines
        if isinstance(options, str):
            opts = [ln.strip() for ln in re.split(r'[\n\r]+', options) if ln.strip()]
            options = opts

        if isinstance(options, list):
            options = [str(o).strip() for o in options if o is not None and str(o).strip()]
        else:
            options = []

        # Normalize length to exactly 4
        while len(options) < 4:
            options.append("N/A")
        options = options[:4]

        # If answer is a letter like "A", map to option
        if re.match(r'^[A-D]$', answer, flags=re.I):
            idx = ord(answer.upper()) - ord('A')
            if 0 <= idx < len(options):
                answer = options[idx]
            else:
                answer = ""
        # If answer is one of the option texts leave it; otherwise blank
        if answer and answer not in options:
            # attempt fuzzy match: strip punctuation and compare lower
            def simple_norm(s): return re.sub(r'[^\w\s]', '', s or "").strip().lower()
            norm_opts = {simple_norm(opt): opt for opt in options}
            ans_norm = simple_norm(answer)
            if ans_norm in norm_opts:
                answer = norm_opts[ans_norm]
            else:
                answer = ""

        if question:
            out["questions"].append({
                "question": question,
                "options": options,
                "answer": answer
            })
    return out

def call_gemini_for_quiz(context_text: str, subject: str, grade: str, min_questions:int=5, max_questions:int=10):
    """
    Call Google Gemini to generate multiple-choice questions based ONLY on supplied context.
    This function builds a strict JSON-only prompt and tries to robustly parse the response.
    """
    # Truncate context to safe length for prompt but keep important bits.
    MAX_CONTEXT_CHARS = 5000
    ctx = (context_text or "").strip()
    if len(ctx) > MAX_CONTEXT_CHARS:
        # Take start + end to preserve some concluding lines
        ctx = ctx[:4000] + "\n\n...TRUNCATED...\n\n" + ctx[-900:]

    # Provide an explicit JSON schema and very strict instructions.
    prompt = f"""
You are an expert exam writer for Nigerian Public Service and NYSC examinations.

CONTEXT:
\"\"\"BEGIN CONTEXT
{ctx}
END CONTEXT\"\"\"

TASK:
Using ONLY the information in the CONTEXT above, produce a set of multiple-choice questions suitable for a professional promotional exam.

REQUIREMENTS (READ CAREFULLY):
1) Return EXACTLY one JSON object and NOTHING ELSE.
2) The JSON must match this schema:

{{
  "questions": [
    {{
      "question": "<plain text>",
      "options": ["<option A text>", "<option B text>", "<option C text>", "<option D text>"],
      "answer": "<exactly one of the option texts>"
    }},
    ...
  ]
}}

3) Produce between {min_questions} and {max_questions} questions (inclusive).
4) Each question MUST have exactly 4 options.
5) The "answer" field MUST exactly match one of the four option strings.
6) Do NOT include explanations, commentary, source citations, or metadata.
7) Do NOT invent facts outside the CONTEXT. If CONTEXT lacks sufficient information, create plausible but clearly derived questions from the context.
8) If you cannot produce the required number of questions strictly from the context, still return a valid JSON with as many as you can, but do not return an empty JSON or non-JSON.

OUTPUT FORMAT:
- Output must be ONLY the JSON object. To help, you may wrap the JSON in triple backticks with the word "json" on the fence, but there must be no other text.

EXAMPLE (for format only):
```json
{{
  "questions": [
    {{
      "question": "Example question?",
      "options": [
        "Option A",
        "Option B",
        "Option C",
        "Option D"
      ],
      "answer": "Option B"
    }}
  ]
}}
