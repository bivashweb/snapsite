import os
import hmac
import logging
import re
import sqlite3
import shutil
import zipfile
from functools import wraps
from html import escape
from datetime import datetime, timedelta
from io import BytesIO
from pathlib import Path
from time import time
from urllib.parse import quote
from uuid import uuid4

import requests
from dotenv import load_dotenv
from flask import (
    Flask,
    abort,
    flash,
    redirect,
    render_template,
    jsonify,
    request,
    send_file,
    send_from_directory,
    session,
    url_for,
)
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.utils import secure_filename

BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env")

UPLOAD_FOLDER = BASE_DIR / "static" / "uploads"
GENERATED_SITES_DIR = BASE_DIR / "generated_sites"
PAYMENTS_FOLDER = BASE_DIR / "payments"
LOGS_DIR = BASE_DIR / "logs"
GENERATION_LOG_PATH = LOGS_DIR / "generation.log"
DB_PATH = BASE_DIR / "database.db"
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "webp", "svg"}
MAX_LENGTHS = {
    "business_name": 80,
    "business_type": 80,
    "description": 600,
    "services": 400,
    "phone": 20,
    "whatsapp": 20,
    "address": 160,
    "city": 80,
    "google_maps_link": 500,
    "template_style": 24,
}
REFERRAL_CODE_MAX_LENGTH = 24
CREATOR_NAME_MAX_LENGTH = 80
REFERRAL_COMMISSION_AMOUNT = 20
GENERATE_SITE_RATE_LIMIT = 10
GENERATE_SITE_RATE_WINDOW = 60
ADMIN_LOGIN_RATE_LIMIT = 5
ADMIN_LOGIN_RATE_WINDOW = 300
generation_attempts_by_ip = {}
admin_login_attempts_by_ip = {}


def env_flag(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


APP_ENV = os.getenv("APP_ENV", "development").strip().lower()
IS_PRODUCTION = APP_ENV == "production"
SECRET_KEY = os.getenv("SECRET_KEY", "").strip()

app = Flask(__name__)
app.config["SECRET_KEY"] = SECRET_KEY or "dev-secret-change-this"
app.config["UPLOAD_FOLDER"] = str(UPLOAD_FOLDER)
app.config["PAYMENTS_FOLDER"] = str(PAYMENTS_FOLDER)
app.config["MAX_CONTENT_LENGTH"] = 3 * 1024 * 1024
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = env_flag("SESSION_COOKIE_SECURE", IS_PRODUCTION)
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(hours=12)
app.config["PREFERRED_URL_SCHEME"] = "https" if IS_PRODUCTION else "http"
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)


def ensure_runtime_dirs():
    UPLOAD_FOLDER.mkdir(parents=True, exist_ok=True)
    GENERATED_SITES_DIR.mkdir(parents=True, exist_ok=True)
    PAYMENTS_FOLDER.mkdir(parents=True, exist_ok=True)
    LOGS_DIR.mkdir(parents=True, exist_ok=True)


def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


ensure_runtime_dirs()
logger = logging.getLogger("snapsite")
if not logger.handlers:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")


def rotate_generation_log():
    if GENERATION_LOG_PATH.exists() and GENERATION_LOG_PATH.stat().st_size > 5 * 1024 * 1024:
        archived_path = GENERATION_LOG_PATH.with_name("generation.log.1")
        if archived_path.exists():
            archived_path.unlink()
        GENERATION_LOG_PATH.replace(archived_path)


def has_valid_secret_key() -> bool:
    return bool(SECRET_KEY) and SECRET_KEY != "dev-secret-change-this" and len(SECRET_KEY) >= 32


def has_valid_admin_password() -> bool:
    admin_password = os.getenv("ADMIN_PASSWORD", "").strip()
    return len(admin_password) >= 12


def get_startup_issues() -> list[str]:
    issues = []
    if not has_valid_secret_key():
        issues.append("SECRET_KEY is missing, defaulted, or too short.")
    if not os.getenv("GEMINI_API_KEY", "").strip():
        issues.append("GEMINI_API_KEY is not configured.")
    if not has_valid_admin_password():
        issues.append("ADMIN_PASSWORD is missing or too weak.")
    return issues


def log_startup_warnings():
    for issue in get_startup_issues():
        logger.warning("%s Production launch is incomplete.", issue)


@app.after_request
def apply_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "SAMEORIGIN"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    return response


rotate_generation_log()
log_startup_warnings()


def init_db():
    conn = get_db_connection()
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS creators (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            referral_code TEXT NOT NULL UNIQUE,
            total_referrals INTEGER NOT NULL DEFAULT 0,
            total_earnings INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS sites (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            payment_id INTEGER,
            business_name TEXT NOT NULL,
            business_type TEXT NOT NULL,
            description TEXT NOT NULL,
            services TEXT NOT NULL,
            phone TEXT NOT NULL,
            whatsapp TEXT NOT NULL,
            address TEXT NOT NULL,
            city TEXT NOT NULL,
            color_theme TEXT NOT NULL,
            template_name TEXT NOT NULL,
            logo_path TEXT,
            slug TEXT,
            preview_url TEXT,
            netlify_site_name TEXT,
            site_slug TEXT NOT NULL UNIQUE,
            site_url TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS payments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            txn_id TEXT NOT NULL,
            screenshot TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'pending',
            site_generated INTEGER NOT NULL DEFAULT 0,
            referral_code TEXT,
            referral_commission INTEGER NOT NULL DEFAULT 0,
            referral_status TEXT NOT NULL DEFAULT '',
            date TEXT NOT NULL
        )
        """
    )
    # Lightweight migration for old databases that do not have status column.
    creator_columns = [row["name"] for row in conn.execute("PRAGMA table_info(creators)").fetchall()]
    payment_columns = [row["name"] for row in conn.execute("PRAGMA table_info(payments)").fetchall()]
    site_columns = [row["name"] for row in conn.execute("PRAGMA table_info(sites)").fetchall()]
    if "total_referrals" not in creator_columns:
        conn.execute("ALTER TABLE creators ADD COLUMN total_referrals INTEGER NOT NULL DEFAULT 0")
    if "total_earnings" not in creator_columns:
        conn.execute("ALTER TABLE creators ADD COLUMN total_earnings INTEGER NOT NULL DEFAULT 0")
    if "status" not in payment_columns:
        conn.execute("ALTER TABLE payments ADD COLUMN status TEXT NOT NULL DEFAULT 'pending'")
    if "site_generated" not in payment_columns:
        conn.execute("ALTER TABLE payments ADD COLUMN site_generated INTEGER NOT NULL DEFAULT 0")
    if "referral_code" not in payment_columns:
        conn.execute("ALTER TABLE payments ADD COLUMN referral_code TEXT")
    if "referral_commission" not in payment_columns:
        conn.execute("ALTER TABLE payments ADD COLUMN referral_commission INTEGER NOT NULL DEFAULT 0")
    if "referral_status" not in payment_columns:
        conn.execute("ALTER TABLE payments ADD COLUMN referral_status TEXT NOT NULL DEFAULT ''")
    if "payment_id" not in site_columns:
        conn.execute("ALTER TABLE sites ADD COLUMN payment_id INTEGER")
    if "slug" not in site_columns:
        conn.execute("ALTER TABLE sites ADD COLUMN slug TEXT")
    if "preview_url" not in site_columns:
        conn.execute("ALTER TABLE sites ADD COLUMN preview_url TEXT")
    if "netlify_site_name" not in site_columns:
        conn.execute("ALTER TABLE sites ADD COLUMN netlify_site_name TEXT")
    conn.execute("UPDATE payments SET status = 'pending' WHERE status IS NULL OR status = ''")
    conn.execute("UPDATE payments SET site_generated = 0 WHERE site_generated IS NULL")
    conn.execute("UPDATE payments SET referral_commission = 0 WHERE referral_commission IS NULL")
    conn.execute("UPDATE payments SET referral_status = '' WHERE referral_status IS NULL")
    conn.execute(
        """
        UPDATE payments
        SET referral_status = CASE
            WHEN referral_code IS NOT NULL AND referral_code != '' AND referral_commission > 0 AND referral_status = '' THEN 'pending'
            WHEN referral_status = '' THEN ''
            ELSE referral_status
        END
        """
    )
    conn.execute("UPDATE creators SET total_referrals = 0 WHERE total_referrals IS NULL")
    conn.execute("UPDATE creators SET total_earnings = 0 WHERE total_earnings IS NULL")
    conn.execute("UPDATE sites SET slug = site_slug WHERE slug IS NULL OR slug = ''")
    conn.execute("UPDATE sites SET preview_url = site_url WHERE preview_url IS NULL OR preview_url = ''")
    conn.commit()
    conn.close()


init_db()


def allowed_file(filename: str) -> bool:
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def slugify(value: str) -> str:
    value = value.strip().lower()
    value = re.sub(r"[^a-z0-9\s-]", "", value)
    value = re.sub(r"\s+", "-", value)
    value = re.sub(r"-+", "-", value)
    return value[:60].strip("-") or "business-site"


def sanitize_field(name: str, value: str) -> str:
    value = (value or "").strip()
    limit = MAX_LENGTHS[name]
    if len(value) > limit:
        raise ValueError(f"{name.replace('_', ' ').title()} exceeds {limit} characters.")
    return value


def sanitize_creator_name(value: str) -> str:
    value = (value or "").strip()
    if len(value) > CREATOR_NAME_MAX_LENGTH:
        raise ValueError(f"Creator Name exceeds {CREATOR_NAME_MAX_LENGTH} characters.")
    return value


def normalize_referral_code(value: str) -> str:
    value = (value or "").strip().upper()
    value = re.sub(r"[^A-Z0-9]", "", value)
    return value[:REFERRAL_CODE_MAX_LENGTH]


def build_referral_redirect(code: str):
    normalized_code = normalize_referral_code(code)
    if normalized_code:
        return redirect(url_for("payment", ref=normalized_code))
    return redirect(url_for("payment"))


def creator_exists(conn, referral_code: str, exclude_id: int | None = None) -> bool:
    query = "SELECT 1 FROM creators WHERE referral_code = ?"
    params = [referral_code]
    if exclude_id is not None:
        query += " AND id != ?"
        params.append(exclude_id)
    return conn.execute(query, tuple(params)).fetchone() is not None


def generate_referral_code_candidate(name: str, attempt: int) -> str:
    base = normalize_referral_code(name)
    base = re.sub(r"[0-9]+$", "", base)
    if not base:
        base = "SITE"
    base = base[:10]
    suffix = f"{(int(uuid4().hex[:6], 16) + attempt) % 90 + 10}"
    if len(base) + len(suffix) > REFERRAL_CODE_MAX_LENGTH:
        base = base[: REFERRAL_CODE_MAX_LENGTH - len(suffix)]
    return f"{base}{suffix}"


def resolve_creator_for_referral(conn, raw_referral_code: str):
    referral_code = normalize_referral_code(raw_referral_code)
    if not referral_code:
        return None, ""
    creator = conn.execute(
        "SELECT id, name, referral_code, total_referrals, total_earnings, created_at FROM creators WHERE referral_code = ?",
        (referral_code,),
    ).fetchone()
    return creator, referral_code


def build_creator_referral_link(referral_code: str) -> str:
    return url_for("payment", ref=referral_code, _external=True)


def apply_referral_approval(conn, payment_row):
    referral_code = normalize_referral_code(payment_row["referral_code"])
    if not referral_code:
        return None
    if payment_row["referral_status"] != "pending":
        return None
    creator = conn.execute(
        "SELECT id, name, referral_code FROM creators WHERE referral_code = ?",
        (referral_code,),
    ).fetchone()
    if not creator:
        conn.execute(
            "UPDATE payments SET referral_status = '' WHERE id = ?",
            (payment_row["id"],),
        )
        return None
    conn.execute(
        """
        UPDATE creators
        SET total_referrals = total_referrals + 1,
            total_earnings = total_earnings + ?
        WHERE id = ?
        """,
        (payment_row["referral_commission"], creator["id"]),
    )
    conn.execute(
        "UPDATE payments SET referral_status = 'approved' WHERE id = ?",
        (payment_row["id"],),
    )
    return creator


def render_admin_dashboard(selected_creator_id: int | None = None):
    conn = get_db_connection()
    total_sites = conn.execute("SELECT COUNT(*) AS total FROM sites").fetchone()["total"]
    total_payments = conn.execute("SELECT COUNT(*) AS total FROM payments").fetchone()["total"]
    approved_payments = conn.execute(
        "SELECT COUNT(*) AS total FROM payments WHERE status = 'approved'"
    ).fetchone()["total"]
    deployed_sites = conn.execute(
        "SELECT COUNT(*) AS total FROM sites WHERE site_url IS NOT NULL AND site_url != '' AND site_url != preview_url"
    ).fetchone()["total"]
    total_creators = conn.execute("SELECT COUNT(*) AS total FROM creators").fetchone()["total"]
    total_referral_earnings = conn.execute(
        "SELECT COALESCE(SUM(total_earnings), 0) AS total FROM creators"
    ).fetchone()["total"]
    sites = conn.execute(
        "SELECT payment_id, slug, preview_url, site_url, netlify_site_name, created_at FROM sites ORDER BY id DESC"
    ).fetchall()
    payments = conn.execute(
        """
        SELECT p.id, p.txn_id, p.screenshot, p.status, p.date, p.referral_code, p.referral_commission, p.referral_status,
               c.name AS creator_name
        FROM payments p
        LEFT JOIN creators c ON c.referral_code = p.referral_code
        ORDER BY p.id DESC
        """
    ).fetchall()
    creators = conn.execute(
        """
        SELECT id, name, referral_code, total_referrals, total_earnings, created_at
        FROM creators
        ORDER BY id DESC
        """
    ).fetchall()
    selected_creator = None
    creator_payments = []
    if selected_creator_id is not None:
        selected_creator = conn.execute(
            """
            SELECT id, name, referral_code, total_referrals, total_earnings, created_at
            FROM creators
            WHERE id = ?
            """,
            (selected_creator_id,),
        ).fetchone()
        if selected_creator:
            creator_payments = conn.execute(
                """
                SELECT id, txn_id, status, date, referral_commission, referral_status, site_generated
                FROM payments
                WHERE referral_code = ?
                ORDER BY id DESC
                """,
                (selected_creator["referral_code"],),
            ).fetchall()
    conn.close()
    creator_links = {
        creator["id"]: build_creator_referral_link(creator["referral_code"])
        for creator in creators
    }
    return render_template(
        "admin.html",
        total_sites=total_sites,
        total_payments=total_payments,
        approved_payments=approved_payments,
        deployed_sites=deployed_sites,
        total_creators=total_creators,
        total_referral_earnings=total_referral_earnings,
        sites=sites,
        payments=payments,
        creators=creators,
        creator_links=creator_links,
        selected_creator=selected_creator,
        creator_payments=creator_payments,
    )


def get_client_ip() -> str:
    forwarded = request.headers.get("X-Forwarded-For", "")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.remote_addr or "unknown"


def is_rate_limited(bucket: dict[str, list[float]], limit: int, window: int) -> bool:
    now = time()
    ip = get_client_ip()
    attempts = bucket.get(ip, [])
    attempts = [stamp for stamp in attempts if now - stamp < window]
    if len(attempts) >= limit:
        bucket[ip] = attempts
        return False
    attempts.append(now)
    bucket[ip] = attempts
    return True


def rate_limit_generation_attempts() -> bool:
    return is_rate_limited(
        generation_attempts_by_ip,
        GENERATE_SITE_RATE_LIMIT,
        GENERATE_SITE_RATE_WINDOW,
    )


def rate_limit_admin_login_attempts() -> bool:
    return is_rate_limited(
        admin_login_attempts_by_ip,
        ADMIN_LOGIN_RATE_LIMIT,
        ADMIN_LOGIN_RATE_WINDOW,
    )


def clear_admin_login_attempts():
    admin_login_attempts_by_ip.pop(get_client_ip(), None)


def admin_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("admin_logged_in"):
            return redirect(url_for("admin_login"))
        return view(*args, **kwargs)

    return wrapped


def validate_or_redirect_approved_payment():
    payment = get_active_payment()
    if not payment:
        flash("Complete payment of INR 59 to unlock site generation.", "warning")
        return None, redirect(url_for("payment"))
    if payment["status"] == "pending":
        flash("Payment verification is still in progress. This usually clears shortly after admin review.", "warning")
        return None, redirect(url_for("waiting"))
    if payment["status"] == "rejected":
        flash("Your payment was rejected. Please submit payment again.", "danger")
        session.pop("active_payment_id", None)
        return None, redirect(url_for("payment"))
    if payment["site_generated"]:
        flash("Website already generated for this payment.", "warning")
        return None, redirect(url_for("landing"))
    return payment, None


def build_unique_site_slug(base_name: str) -> str:
    base_slug = slugify(base_name)
    candidate = base_slug
    counter = 2
    while (GENERATED_SITES_DIR / candidate).exists():
        candidate = f"{base_slug}-{counter}"
        counter += 1
    return candidate


def extract_html_document(response_text: str) -> str:
    cleaned = response_text.strip()
    if not cleaned:
        raise ValueError("Gemini returned empty content.")
    code_block = re.search(r"```(?:html)?\s*(.*?)```", cleaned, re.DOTALL | re.IGNORECASE)
    if code_block:
        cleaned = code_block.group(1).strip()
    lower_cleaned = cleaned.lower()
    if "<html" not in lower_cleaned or "<body" not in lower_cleaned:
        raise ValueError("Gemini did not return a valid full HTML document.")
    return cleaned


def get_template_style_rules(template_style: str) -> str:
    style_rules = {
        "modern": "- Use a gradient hero background, bold typography, and card-style services.",
        "minimal": "- Use a light background, thin typography, and a simple layout.",
        "business": "- Use a professional blue/gray palette, strong CTA buttons, and a structured layout.",
    }
    return style_rules.get(template_style.lower(), style_rules["modern"])


def build_gemini_prompt(data: dict) -> str:
    description = data["description"] or "Not provided. Write a concise business description."
    services = data["services"] or "Not provided. Invent 3 to 5 suitable services."
    logo_instruction = (
        f'If you include a logo image, use the relative path "{data["logo_reference"]}".'
        if data["logo_reference"]
        else "Do not require any external logo asset."
    )
    google_maps_link = (data.get("google_maps_link") or "").strip()
    map_instruction = (
        f'Use this Google Maps link for the map iframe: {google_maps_link}'
        if google_maps_link
        else f'Build the Google Maps embed using this location: {data["address"]}, {data["city"]}'
    )
    template_style_rules = get_template_style_rules(data["template_style"])

    system_instruction = """
You are a professional web designer generating small business landing pages.

Your task is to produce a clean, modern, conversion-focused business website.

Rules:
- Output ONLY valid HTML.
- Output a full HTML document with embedded CSS.
- Do not include markdown formatting.
- Do not include explanations or comments.
- The design must be clean, balanced, and mobile-first.
- The layout must be visually professional.
""".strip()

    return f"""
{system_instruction}

Create a modern responsive business website for the following business.

Business Name: {data["business_name"]}
Business Type: {data["business_type"]}
Description: {description}
Services: {services}
Phone: {data["phone"]}
WhatsApp: {data["whatsapp"]}
Address: {data["address"]}
City: {data["city"]}
Template Style: {data["template_style"]}

Layout rules:
- The HTML must include these sections in this order: header -> hero -> services -> about -> contact -> map -> footer.
- Use a header with logo and navigation.
- Use <section id="hero"> for the hero section.
- Use <section id="services"> for the services section.
- Use <section id="about"> for the about section.
- Use <section id="contact"> for the contact section.
- Use <section id="map"> for the map section.
- Include a footer.
- Include a floating WhatsApp button fixed at the bottom-right.

Hero rules:
- The hero section must include the business name.
- The hero section must include a short tagline.
- The hero section must include a call button.
- The hero section must include a WhatsApp button.

Contact rules:
- The contact section must contain a phone link using tel:.
- The contact section must contain a WhatsApp link.
- The contact section must contain the address.
- The map section must contain a Google Maps embed iframe.
- {map_instruction}

Design rules:
- Use a maximum width container between 1100px and 1200px.
- Use a consistent spacing system for margins and paddings.
- Use readable typography and a clear hierarchy.
- Buttons should have rounded corners and hover effects.
- The layout must be fully responsive for mobile devices.

Template style rules:
{template_style_rules}

Output rules:
- Return ONLY a single complete HTML file with embedded CSS.
- Return ONLY a full HTML document.
- Do not include markdown formatting.
- Do not include explanations or comments.
- Use semantic HTML and modern CSS.
- Avoid external CSS or JS dependencies.
- Keep the entire HTML under 1200 lines.
- Avoid unnecessary comments or redundant markup.
- {logo_instruction}
""".strip()


def validate_generated_html(html: str) -> str:
    cleaned = extract_html_document(html)
    required_fragments = [
        "<header",
        '<section id="hero"',
        '<section id="services"',
        '<section id="about"',
        '<section id="contact"',
        "<footer",
    ]
    lower_cleaned = cleaned.lower()
    missing = [fragment for fragment in required_fragments if fragment.lower() not in lower_cleaned]
    if missing:
        raise ValueError(f"Gemini output missing required sections: {', '.join(missing)}")
    return cleaned


def add_base_href(html: str, site_name: str) -> str:
    base_tag = f'<base href="/site/{site_name}/">'
    if "<head" in html.lower():
        return re.sub(r"(<head[^>]*>)", r"\1\n  " + base_tag, html, count=1, flags=re.IGNORECASE)
    return base_tag + "\n" + html


def write_netlify_config(site_dir: Path):
    (site_dir / "netlify.toml").write_text('[build]\npublish = "."\n', encoding="utf-8")


def log_generation(payment_id: int, slug: str, generator_used: str):
    rotate_generation_log()
    timestamp = datetime.utcnow().isoformat(timespec="seconds")
    with GENERATION_LOG_PATH.open("a", encoding="utf-8") as log_file:
        log_file.write(f"{timestamp} | payment_id={payment_id} | slug={slug} | generator={generator_used}\n")


def build_netlify_site_name(base_slug: str, attempt: int) -> str:
    if attempt == 0:
        return base_slug
    if attempt == 1:
        return f"{base_slug}-{int(time()) % 1000:03d}"
    return f"{base_slug}-{uuid4().hex[:4]}"


def create_netlify_site(api_token: str, desired_name: str) -> dict:
    response = requests.post(
        "https://api.netlify.com/api/v1/sites",
        headers={
            "Authorization": f"Bearer {api_token}",
            "Content-Type": "application/json",
        },
        json={"name": desired_name},
        timeout=60,
    )
    if response.status_code == 422:
        raise ValueError("Netlify site name already exists.")
    response.raise_for_status()
    return response.json()


def upload_netlify_deploy(api_token: str, site_id: str, zip_payload: bytes) -> dict:
    response = requests.post(
        f"https://api.netlify.com/api/v1/sites/{site_id}/deploys",
        headers={
            "Authorization": f"Bearer {api_token}",
            "Content-Type": "application/zip",
        },
        data=zip_payload,
        timeout=90,
    )
    response.raise_for_status()
    return response.json()


def deploy_to_netlify(site_dir: Path, base_slug: str) -> dict:
    api_token = os.getenv("NETLIFY_API_TOKEN", "").strip()
    if not api_token:
        return {"url": "", "site_name": ""}

    zip_buffer = BytesIO()
    with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as zip_file:
        for path in site_dir.rglob("*"):
            if path.is_file():
                zip_file.write(path, path.relative_to(site_dir))
    zip_buffer.seek(0)
    zip_payload = zip_buffer.getvalue()

    last_error = None
    for attempt in range(3):
        desired_name = build_netlify_site_name(base_slug, attempt)
        try:
            site_payload = create_netlify_site(api_token, desired_name)
            deploy_payload = upload_netlify_deploy(api_token, site_payload["id"], zip_payload)
            return {
                "url": deploy_payload.get("ssl_url") or deploy_payload.get("url") or site_payload.get("ssl_url") or site_payload.get("url") or "",
                "site_name": site_payload.get("name") or desired_name,
            }
        except ValueError as exc:
            last_error = exc
            continue

    if last_error:
        raise requests.RequestException(str(last_error))
    raise requests.RequestException("Netlify deployment failed.")


def build_share_url(site_url: str) -> str:
    if not site_url:
        return ""
    if site_url.startswith("http://") or site_url.startswith("https://"):
        return site_url
    return request.url_root.rstrip("/") + site_url


def build_qr_code_url(site_url: str) -> str:
    share_url = build_share_url(site_url)
    if not share_url:
        return ""
    return f"https://api.qrserver.com/v1/create-qr-code/?size=220x220&data={quote(share_url, safe='')}"


def build_whatsapp_share_url(site_url: str) -> str:
    share_url = build_share_url(site_url)
    if not share_url:
        return ""
    return f"https://wa.me/?text={quote(f'Check out this website: {share_url}', safe='')}"


def build_maps_embed_src(data: dict) -> str:
    google_maps_link = (data.get("google_maps_link") or "").strip()
    if google_maps_link:
        if "output=embed" in google_maps_link or "/maps/embed" in google_maps_link:
            return escape(google_maps_link)
        separator = "&" if "?" in google_maps_link else "?"
        return escape(f"{google_maps_link}{separator}output=embed")

    maps_query = escape(f"{data['address']}, {data['city']}").replace(" ", "+")
    return f"https://maps.google.com/maps?q={maps_query}&output=embed"


def generate_basic_site(data: dict) -> str:
    services = [
        escape(item.strip())
        for item in data["services"].split(",")
        if item.strip()
    ] or ["Consultation", "Premium Service", "Customer Support"]
    services_html = "".join(f"<li>{service}</li>" for service in services)
    description = escape(data["description"] or f"{data['business_name']} delivers trusted {data['business_type']} services in {data['city']}.")
    maps_embed_src = build_maps_embed_src(data)
    whatsapp = re.sub(r"[^0-9]", "", data["whatsapp"]) or escape(data["whatsapp"])
    logo_markup = ""
    if data.get("logo_reference"):
        logo_markup = f'<img src="{escape(data["logo_reference"])}" alt="{escape(data["business_name"])} logo" class="brand-logo">'

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>{escape(data["business_name"])} | SnapSite</title>
  <style>
    :root {{
      --bg: #f6f3ee;
      --panel: #fffdf9;
      --ink: #1f2933;
      --accent: #b45309;
      --accent-dark: #7c2d12;
      --muted: #6b7280;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      font-family: Georgia, "Times New Roman", serif;
      background:
        radial-gradient(circle at top left, rgba(245, 158, 11, 0.14), transparent 34%),
        linear-gradient(180deg, #fffaf2, var(--bg));
      color: var(--ink);
    }}
    .wrap {{ width: min(1100px, 92%); margin: 0 auto; }}
    .hero {{
      padding: 4.5rem 0 3rem;
      display: grid;
      gap: 2rem;
      grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
      align-items: center;
    }}
    .eyebrow {{ letter-spacing: 0.18em; text-transform: uppercase; color: var(--accent-dark); font-size: 0.78rem; }}
    h1, h2 {{ margin: 0 0 0.75rem; line-height: 1.05; }}
    h1 {{ font-size: clamp(2.4rem, 6vw, 4.8rem); }}
    p {{ color: var(--muted); font-size: 1rem; line-height: 1.7; }}
    .hero-card, .panel {{
      background: rgba(255, 253, 249, 0.92);
      border: 1px solid rgba(180, 83, 9, 0.14);
      border-radius: 24px;
      box-shadow: 0 20px 45px rgba(31, 41, 51, 0.08);
    }}
    .hero-card {{ padding: 1.4rem; }}
    .panel {{ padding: 1.4rem; margin-bottom: 1rem; }}
    .brand-logo {{
      max-width: 180px;
      max-height: 80px;
      display: block;
      margin-bottom: 1rem;
      object-fit: contain;
    }}
    .cta-row {{ display: flex; gap: 0.9rem; flex-wrap: wrap; margin-top: 1.25rem; }}
    .btn {{
      display: inline-block;
      padding: 0.85rem 1.15rem;
      border-radius: 999px;
      text-decoration: none;
      font-weight: 700;
    }}
    .btn.primary {{ background: var(--accent); color: #fff; }}
    .btn.secondary {{ background: #fff; color: var(--ink); border: 1px solid rgba(31, 41, 51, 0.12); }}
    .grid {{
      display: grid;
      gap: 1rem;
      grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
      margin: 1rem 0 2rem;
    }}
    ul {{ margin: 0; padding-left: 1.2rem; color: var(--muted); }}
    iframe {{ width: 100%; min-height: 280px; border: 0; border-radius: 18px; }}
    footer {{ padding: 2rem 0 3rem; color: var(--muted); text-align: center; }}
    @media (max-width: 640px) {{
      .hero {{ padding-top: 3rem; }}
    }}
  </style>
</head>
<body>
  <div class="wrap">
    <section class="hero">
      <div>
        <div class="eyebrow">{escape(data["business_type"])}</div>
        <h1>{escape(data["business_name"])}</h1>
        <p>{description}</p>
        <div class="cta-row">
          <a class="btn primary" href="https://wa.me/{whatsapp}" target="_blank" rel="noopener">Chat on WhatsApp</a>
          <a class="btn secondary" href="tel:{escape(data["phone"])}">Call {escape(data["phone"])}</a>
        </div>
      </div>
      <div class="hero-card">
        {logo_markup}
        <h2>Trusted in {escape(data["city"])}</h2>
        <p>{description}</p>
      </div>
    </section>

    <section class="grid">
      <article class="panel">
        <h2>About</h2>
        <p>{description}</p>
      </article>
      <article class="panel">
        <h2>Services</h2>
        <ul>{services_html}</ul>
      </article>
    </section>

    <section class="panel">
      <h2>Contact</h2>
      <p>Phone: {escape(data["phone"])}</p>
      <p>WhatsApp: {escape(data["whatsapp"])}</p>
      <p>Address: {escape(data["address"])}, {escape(data["city"])}</p>
    </section>

    <section class="panel">
      <h2>Location</h2>
      <iframe src="{maps_embed_src}" loading="lazy"></iframe>
    </section>

    <footer>Generated by SnapSite</footer>
  </div>
</body>
</html>
"""


def generate_website_code(data: dict) -> str:
    api_key = os.getenv("GEMINI_API_KEY", "").strip()
    if not api_key:
        raise RuntimeError("GEMINI_API_KEY is not set.")
    prompt = build_gemini_prompt(data)
    last_error = None

    for attempt in range(2):
        response = requests.post(
            "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent",
            params={"key": api_key},
            json={
                "contents": [{"parts": [{"text": prompt}]}],
                "generationConfig": {
                    "temperature": 0.4,
                    "topP": 0.9,
                    "maxOutputTokens": 4096,
                },
            },
            timeout=60,
        )
        response.raise_for_status()
        payload = response.json()
        candidates = payload.get("candidates") or []
        if not candidates:
            raise RuntimeError("Gemini returned no candidates.")

        parts = candidates[0].get("content", {}).get("parts", [])
        text = "".join(part.get("text", "") for part in parts).strip()
        if not text:
            raise RuntimeError("Gemini returned empty content.")

        try:
            return validate_generated_html(text)
        except ValueError as exc:
            last_error = exc
            if attempt == 0:
                continue
            raise

    if last_error:
        raise last_error
    raise RuntimeError("Gemini generation failed.")


def build_site_record(data: dict, site_slug: str) -> dict:
    return {
        "payment_id": data["payment_id"],
        "business_name": data["business_name"],
        "business_type": data["business_type"],
        "description": data["description"] or "",
        "services": data["services"] or "",
        "phone": data["phone"],
        "whatsapp": data["whatsapp"],
        "address": data["address"],
        "city": data["city"],
        "color_theme": "#0F766E",
        "template_name": data["template_style"],
        "logo_path": data["logo_path"],
        "slug": site_slug,
        "preview_url": f"/site/{site_slug}",
        "netlify_site_name": data.get("netlify_site_name", ""),
        "site_slug": site_slug,
        "site_url": data["site_url"],
    }


def update_payment_generation_status(payment_id: int, generated: int):
    conn = get_db_connection()
    conn.execute("UPDATE payments SET site_generated = ? WHERE id = ?", (generated, payment_id))
    conn.commit()
    conn.close()


def save_site_to_db(payload: dict):
    conn = get_db_connection()
    conn.execute(
        """
        INSERT INTO sites (
            payment_id, business_name, business_type, description, services, phone, whatsapp,
            address, city, color_theme, template_name, logo_path, slug, preview_url, netlify_site_name, site_slug, site_url, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            payload["payment_id"],
            payload["business_name"],
            payload["business_type"],
            payload["description"],
            payload["services"],
            payload["phone"],
            payload["whatsapp"],
            payload["address"],
            payload["city"],
            payload["color_theme"],
            payload["template_name"],
            payload["logo_path"],
            payload["slug"],
            payload["preview_url"],
            payload["netlify_site_name"],
            payload["site_slug"],
            payload["site_url"],
            datetime.utcnow().isoformat(timespec="seconds"),
        ),
    )
    conn.commit()
    conn.close()


@app.route("/")
def landing():
    return render_template("landing.html")


@app.get("/health")
def health():
    issues = get_startup_issues()
    status_code = 200 if not issues else 503
    return (
        jsonify(
            {
                "status": "ok" if not issues else "degraded",
                "service": "snapsite",
                "environment": APP_ENV,
                "issues": issues,
            }
        ),
        status_code,
    )


@app.route("/privacy")
def privacy():
    return render_template("privacy.html")


@app.route("/terms")
def terms():
    return render_template("terms.html")


@app.route("/payment")
def payment():
    referral_code = normalize_referral_code(request.args.get("ref", ""))
    return render_template("payment.html", referral_code=referral_code)


@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    if session.get("admin_logged_in"):
        return redirect(url_for("admin"))

    if request.method == "POST":
        if not rate_limit_admin_login_attempts():
            flash("Too many login attempts. Try again in a few minutes.", "danger")
            return render_template("admin_login.html"), 429

        submitted_password = request.form.get("password", "")
        admin_password = os.getenv("ADMIN_PASSWORD", "").strip()
        if admin_password and hmac.compare_digest(submitted_password, admin_password):
            session.permanent = True
            session["admin_logged_in"] = True
            clear_admin_login_attempts()
            return redirect(url_for("admin"))
        flash("Invalid admin password.", "danger")

    return render_template("admin_login.html")


@app.route("/admin/logout")
def admin_logout():
    session.pop("admin_logged_in", None)
    flash("Logged out from admin panel.", "success")
    return redirect(url_for("admin_login"))


@app.route("/verify_payment", methods=["POST"])
def verify_payment():
    txn_id = request.form.get("txn_id", "").strip()
    referral_code_input = request.form.get("referral_code", "")
    screenshot_file = request.files.get("payment_screenshot")

    if not txn_id:
        flash("Please enter UPI transaction ID.", "danger")
        return build_referral_redirect(referral_code_input)

    if not screenshot_file or not screenshot_file.filename:
        flash("Please upload a payment screenshot.", "danger")
        return build_referral_redirect(referral_code_input)

    if not allowed_file(screenshot_file.filename):
        flash("Invalid screenshot format. Use png/jpg/jpeg/webp/svg.", "danger")
        return build_referral_redirect(referral_code_input)

    filename = secure_filename(screenshot_file.filename)
    final_name = f"{datetime.utcnow().strftime('%Y%m%d%H%M%S')}_{filename}"
    save_path = PAYMENTS_FOLDER / final_name
    save_path.parent.mkdir(parents=True, exist_ok=True)
    screenshot_file.save(save_path)

    conn = get_db_connection()
    creator, normalized_referral_code = resolve_creator_for_referral(conn, referral_code_input)
    applied_referral_code = creator["referral_code"] if creator else ""
    applied_referral_commission = REFERRAL_COMMISSION_AMOUNT if creator else 0
    applied_referral_status = "pending" if creator else ""
    conn.execute(
        """
        INSERT INTO payments (
            txn_id, screenshot, status, site_generated, referral_code, referral_commission, referral_status, date
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            txn_id,
            final_name,
            "pending",
            0,
            applied_referral_code,
            applied_referral_commission,
            applied_referral_status,
            datetime.utcnow().isoformat(timespec="seconds"),
        ),
    )
    payment_id = conn.execute("SELECT last_insert_rowid() AS id").fetchone()["id"]
    conn.commit()
    conn.close()

    if normalized_referral_code and not creator:
        flash("Referral code not found. Payment was submitted without affiliate credit.", "warning")
    session["active_payment_id"] = payment_id
    return redirect(url_for("waiting"))


@app.route("/payments/<path:filename>")
def serve_payment_screenshot(filename):
    return send_from_directory(PAYMENTS_FOLDER, filename)


def get_active_payment():
    payment_id = session.get("active_payment_id")
    if not payment_id:
        return None

    conn = get_db_connection()
    payment = conn.execute(
        """
        SELECT id, txn_id, screenshot, status, site_generated, referral_code, referral_commission, referral_status, date
        FROM payments
        WHERE id = ?
        """,
        (payment_id,),
    ).fetchone()
    conn.close()
    return payment


@app.route("/waiting")
def waiting():
    payment = get_active_payment()
    if not payment:
        flash("Submit payment first to continue.", "warning")
        return redirect(url_for("payment"))

    if payment["status"] == "approved":
        flash("Payment approved. You can now create your website.", "success")
        return redirect(url_for("create_site"))

    if payment["status"] == "rejected":
        flash("Your payment was rejected. Please submit payment again.", "danger")
        session.pop("active_payment_id", None)
        return redirect(url_for("payment"))

    flash("Payment verification is taking a little longer than usual. Please refresh again in a moment.", "warning")
    return render_template("waiting.html")


@app.route("/create", methods=["GET"])
def create_site():
    _, redirect_response = validate_or_redirect_approved_payment()
    if redirect_response:
        return redirect_response
    return render_template("create_site.html")


@app.route("/generate_site", methods=["POST"])
def generate_site():
    payment, redirect_response = validate_or_redirect_approved_payment()
    if redirect_response:
        return redirect_response
    if not rate_limit_generation_attempts():
        return render_template("429.html"), 429

    try:
        form_data = {
            "business_name": sanitize_field("business_name", request.form.get("business_name", "")),
            "business_type": sanitize_field("business_type", request.form.get("business_type", "")),
            "description": sanitize_field("description", request.form.get("description", "")),
            "services": sanitize_field("services", request.form.get("services", "")),
            "phone": sanitize_field("phone", request.form.get("phone", "")),
            "whatsapp": sanitize_field("whatsapp", request.form.get("whatsapp", "")),
            "address": sanitize_field("address", request.form.get("address", "")),
            "city": sanitize_field("city", request.form.get("city", "")),
            "google_maps_link": sanitize_field("google_maps_link", request.form.get("google_maps_link", "")),
            "template_style": sanitize_field("template_style", request.form.get("template_style", "")),
        }
    except ValueError as exc:
        flash(str(exc), "danger")
        return redirect(url_for("create_site"))

    required_fields = [
        "business_name",
        "business_type",
        "phone",
        "whatsapp",
        "address",
        "city",
        "template_style",
    ]
    if any(not form_data[field] for field in required_fields):
        flash("Please fill all required fields.", "danger")
        return redirect(url_for("create_site"))

    logo_upload = request.files.get("logo_upload")
    temp_logo_name = ""
    if logo_upload and logo_upload.filename:
        if not allowed_file(logo_upload.filename):
            flash("Invalid logo format. Use png/jpg/jpeg/webp/svg.", "danger")
            return redirect(url_for("create_site"))
        extension = Path(secure_filename(logo_upload.filename)).suffix.lower() or ".png"
        temp_logo_name = f"pending_{payment['id']}_{datetime.utcnow().strftime('%Y%m%d%H%M%S')}{extension}"
        logo_upload.save(UPLOAD_FOLDER / temp_logo_name)

    session["pending_generation"] = {**form_data, "temp_logo_name": temp_logo_name}
    return redirect(url_for("generating"))


@app.route("/generating", methods=["GET"])
def generating():
    _, redirect_response = validate_or_redirect_approved_payment()
    if redirect_response:
        return redirect_response

    if not session.get("pending_generation"):
        flash("Submit the website form first.", "warning")
        return redirect(url_for("create_site"))
    return render_template("generating.html")


@app.route("/process_generation", methods=["POST"])
def process_generation():
    payment, redirect_response = validate_or_redirect_approved_payment()
    if redirect_response:
        return redirect_response

    form_data = session.get("pending_generation")
    if not form_data:
        flash("Submit the website form first.", "warning")
        return redirect(url_for("create_site"))

    site_slug = build_unique_site_slug(form_data["business_name"])
    site_dir = GENERATED_SITES_DIR / site_slug
    site_dir.mkdir(parents=True, exist_ok=False)

    logo_reference = ""
    temp_logo_name = form_data.get("temp_logo_name", "")
    if temp_logo_name:
        extension = Path(temp_logo_name).suffix.lower() or ".png"
        logo_reference = f"logo{extension}"

    try:
        generation_mode = "gemini"
        try:
            html = generate_website_code({**form_data, "logo_reference": logo_reference})
        except (ValueError, RuntimeError, requests.RequestException):
            generation_mode = "basic"
            html = generate_basic_site({**form_data, "logo_reference": logo_reference})

        logo_path = ""
        if temp_logo_name:
            source_logo = UPLOAD_FOLDER / temp_logo_name
            if source_logo.exists():
                logo_path = f"logo{source_logo.suffix.lower() or '.png'}"
                shutil.move(str(source_logo), str(site_dir / logo_path))
        html = add_base_href(html, site_slug)
        (site_dir / "index.html").write_text(html, encoding="utf-8")
        write_netlify_config(site_dir)
        deployed_url = ""
        netlify_site_name = ""
        deployment_error = False
        try:
            deploy_result = deploy_to_netlify(site_dir, slugify(form_data["business_name"]))
            deployed_url = deploy_result.get("url", "")
            netlify_site_name = deploy_result.get("site_name", "")
        except requests.RequestException:
            deployed_url = ""
            netlify_site_name = ""
            deployment_error = True

        site_record = build_site_record(
            {
                **form_data,
                "payment_id": payment["id"],
                "logo_path": f"/site/{site_slug}/{logo_path}" if logo_path else "",
                "netlify_site_name": netlify_site_name,
                "site_url": deployed_url or f"/site/{site_slug}",
            },
            site_slug,
        )
        save_site_to_db(site_record)
        update_payment_generation_status(payment["id"], 1)
        log_generation(payment["id"], site_slug, generation_mode)
        session.pop("pending_generation", None)
        session.pop("active_payment_id", None)
        return render_template(
            "success.html",
            site_name=site_slug,
            site_url=deployed_url or f"/site/{site_slug}",
            preview_url=f"/site/{site_slug}",
            deployed_url=deployed_url,
            share_url=build_share_url(deployed_url or f"/site/{site_slug}"),
            qr_code_url=build_qr_code_url(deployed_url or f"/site/{site_slug}"),
            whatsapp_share_url=build_whatsapp_share_url(deployed_url or f"/site/{site_slug}"),
            deployment_error=deployment_error,
            site_folder=str(site_dir),
            generation_mode=generation_mode,
        )
    except Exception as exc:
        session.pop("pending_generation", None)
        temp_logo_name = form_data.get("temp_logo_name", "")
        if temp_logo_name:
            temp_logo_path = UPLOAD_FOLDER / temp_logo_name
            if temp_logo_path.exists():
                temp_logo_path.unlink()
        if site_dir.exists():
            shutil.rmtree(site_dir)
        flash("We could not generate your website right now because the AI service did not return a usable page. Please try again in a few minutes.", "danger")
        return redirect(url_for("create_site"))


@app.route("/site/<name>")
@app.route("/site/<name>/")
def serve_generated_site(name):
    safe_name = slugify(name)
    site_dir = GENERATED_SITES_DIR / safe_name
    if not site_dir.exists():
        abort(404)
    return send_from_directory(site_dir, "index.html")


@app.route("/site/<name>/<path:filename>")
def serve_generated_site_asset(name, filename):
    safe_name = slugify(name)
    site_dir = GENERATED_SITES_DIR / safe_name
    if not site_dir.exists():
        abort(404)
    return send_from_directory(site_dir, filename)


@app.route("/export_site/<name>")
def export_site(name):
    safe_name = slugify(name)
    site_dir = GENERATED_SITES_DIR / safe_name
    if not site_dir.exists():
        abort(404)

    zip_buffer = BytesIO()
    with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as zip_file:
        for path in site_dir.rglob("*"):
            if path.is_file():
                zip_file.write(path, path.relative_to(site_dir))
    zip_buffer.seek(0)

    return send_file(
        zip_buffer,
        mimetype="application/zip",
        as_attachment=True,
        download_name="snapsite-generated-website.zip",
    )


@app.route("/delete_site/<slug>", methods=["POST"])
@admin_required
def delete_site(slug):
    safe_slug = slugify(slug)
    site_dir = GENERATED_SITES_DIR / safe_slug
    if site_dir.exists():
        shutil.rmtree(site_dir)

    conn = get_db_connection()
    conn.execute("DELETE FROM sites WHERE slug = ? OR site_slug = ?", (safe_slug, safe_slug))
    conn.commit()
    conn.close()

    flash(f"Site '{safe_slug}' deleted.", "success")
    return redirect(url_for("admin"))


@app.route("/admin")
@admin_required
def admin():
    return render_admin_dashboard()


@app.route("/admin/creators", methods=["POST"])
@admin_required
def create_creator():
    try:
        creator_name = sanitize_creator_name(request.form.get("creator_name", ""))
    except ValueError as exc:
        flash(str(exc), "danger")
        return redirect(url_for("admin"))
    referral_code_input = normalize_referral_code(request.form.get("referral_code", ""))
    if not creator_name:
        flash("Creator name is required.", "danger")
        return redirect(url_for("admin"))

    conn = get_db_connection()
    if referral_code_input:
        if creator_exists(conn, referral_code_input):
            conn.close()
            flash("Referral code already exists. Use a unique code.", "danger")
            return redirect(url_for("admin"))
        referral_code = referral_code_input
    else:
        referral_code = ""
        for attempt in range(12):
            candidate = generate_referral_code_candidate(creator_name, attempt)
            if not creator_exists(conn, candidate):
                referral_code = candidate
                break
        if not referral_code:
            conn.close()
            flash("Could not generate a unique referral code. Try again.", "danger")
            return redirect(url_for("admin"))

    conn.execute(
        """
        INSERT INTO creators (name, referral_code, total_referrals, total_earnings, created_at)
        VALUES (?, ?, 0, 0, ?)
        """,
        (creator_name, referral_code, datetime.utcnow().isoformat(timespec="seconds")),
    )
    conn.commit()
    conn.close()
    flash(f"Creator '{creator_name}' created with code {referral_code}.", "success")
    return redirect(url_for("admin"))


@app.route("/admin/creators/<int:creator_id>/payments")
@admin_required
def creator_payments(creator_id):
    return render_admin_dashboard(selected_creator_id=creator_id)


@app.route("/approve_payment/<int:payment_id>", methods=["POST"])
@admin_required
def approve_payment(payment_id):
    conn = get_db_connection()
    payment = conn.execute(
        """
        SELECT id, status, referral_code, referral_commission, referral_status
        FROM payments
        WHERE id = ?
        """,
        (payment_id,),
    ).fetchone()
    if not payment:
        conn.close()
        flash(f"Payment #{payment_id} not found.", "danger")
        return redirect(url_for("admin"))

    creator = None
    if payment["status"] != "approved":
        conn.execute("UPDATE payments SET status = 'approved' WHERE id = ?", (payment_id,))
        creator = apply_referral_approval(conn, payment)
        conn.commit()
        conn.close()
        if creator:
            flash(
                f"Payment #{payment_id} approved. Referral credited to {creator['name']} ({creator['referral_code']}).",
                "success",
            )
            return redirect(url_for("admin"))
    else:
        creator = apply_referral_approval(conn, payment)
        conn.commit()
        conn.close()
        if creator:
            flash(
                f"Payment #{payment_id} was already approved. Pending referral credit was applied to {creator['name']}.",
                "success",
            )
            return redirect(url_for("admin"))
        flash(f"Payment #{payment_id} was already approved.", "warning")
        return redirect(url_for("admin"))
    flash(f"Payment #{payment_id} approved.", "success")
    return redirect(url_for("admin"))


@app.route("/reject_payment/<int:payment_id>", methods=["POST"])
@admin_required
def reject_payment(payment_id):
    conn = get_db_connection()
    conn.execute("UPDATE payments SET status = 'rejected' WHERE id = ?", (payment_id,))
    conn.commit()
    conn.close()
    flash(f"Payment #{payment_id} rejected.", "warning")
    return redirect(url_for("admin"))


@app.errorhandler(404)
def page_not_found(error):
    return render_template("404.html"), 404


@app.errorhandler(500)
def internal_server_error(error):
    return render_template("500.html"), 500


if __name__ == "__main__":
    ensure_runtime_dirs()
    rotate_generation_log()
    log_startup_warnings()
    init_db()
    app.run(
        host=os.getenv("HOST", "127.0.0.1"),
        port=int(os.getenv("PORT", "5000")),
        debug=False,
    )
