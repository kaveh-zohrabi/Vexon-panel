import asyncio
import hashlib
import hmac
import json
import os
import secrets
import struct
import time
import base64
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo
from urllib.parse import quote
from collections import deque, defaultdict
from pathlib import Path

import aiofiles
import httpx
import logging
import uvicorn

try:
    import orjson
    _use_orjson = True
except ImportError:
    orjson = None
    _use_orjson = False

try:
    import pyotp
except ImportError:
    pyotp = None

from fastapi import FastAPI, Request, HTTPException, WebSocket, WebSocketDisconnect, Depends, Query
from fastapi.responses import Response, HTMLResponse, JSONResponse, RedirectResponse
from fastapi.middleware.cors import CORSMiddleware

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("Vexon")

IRAN_TZ = ZoneInfo("Asia/Tehran")

app = FastAPI(title="Vexon-panel", docs_url=None, redoc_url=None)

# ══════════════════════════════════════════════════════════════════════════════
# Persistence
# ══════════════════════════════════════════════════════════════════════════════
DATA_DIR = Path(os.environ.get("DATA_DIR", "/data"))
DATA_FILE = DATA_DIR / "vexon_state.json"
SECRET_FILE = DATA_DIR / "vexon_secret.key"
ADMIN_PW_FILE = DATA_DIR / "vexon_admin_pw.txt"
SAVE_LOCK = asyncio.Lock()

def _load_or_create_secret() -> str:
    """SECRET_KEY را روی دیسک ذخیره و ثابت نگه می‌دارد."""
    env_secret = os.environ.get("SECRET_KEY")
    if env_secret:
        return env_secret
    try:
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        if SECRET_FILE.exists():
            existing = SECRET_FILE.read_text(encoding="utf-8").strip()
            if existing:
                return existing
        new_secret = secrets.token_urlsafe(32)
        SECRET_FILE.write_text(new_secret, encoding="utf-8")
        return new_secret
    except Exception as e:
        logger.warning(f"Could not persist SECRET_KEY: {e}")
        return secrets.token_urlsafe(32)

CONFIG = {
    "port": int(os.environ.get("PORT", 8000)),
    "secret": _load_or_create_secret(),
    "host": os.environ.get("RAILWAY_PUBLIC_DOMAIN", "localhost"),
}

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ══════════════════════════════════════════════════════════════════════════════
# Password Hashing — PBKDF2-HMAC-SHA256 با پشتیبانی از migration خودکار
# ══════════════════════════════════════════════════════════════════════════════
PBKDF2_ITERATIONS = 600_000

def _hash_pbkdf2(pw: str, salt: bytes | None = None) -> str:
    """هش رمز با PBKDF2-HMAC-SHA256. خروجی: pbkdf2:<iter>:<salt_b64>:<hash_b64>"""
    if salt is None:
        salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", pw.encode("utf-8"), salt, PBKDF2_ITERATIONS)
    salt_b64 = base64.b64encode(salt).decode()
    dk_b64 = base64.b64encode(dk).decode()
    return f"pbkdf2:{PBKDF2_ITERATIONS}:{salt_b64}:{dk_b64}"

def _verify_pbkdf2(pw: str, stored: str) -> bool:
    """بررسی رمز در برابر هش PBKDF2."""
    try:
        _, iter_str, salt_b64, dk_b64 = stored.split(":", 3)
        salt = base64.b64decode(salt_b64)
        dk = base64.b64decode(dk_b64)
        iterations = int(iter_str)
        dk_new = hashlib.pbkdf2_hmac("sha256", pw.encode("utf-8"), salt, iterations)
        return hmac.compare_digest(dk_new, dk)
    except Exception:
        return False

def _is_pbkdf2_hash(h: str) -> bool:
    return h.startswith("pbkdf2:")

def hash_password(pw: str) -> str:
    """هش رمز جدید با PBKDF2."""
    return _hash_pbkdf2(pw)

def verify_password(pw: str, stored_hash: str) -> bool:
    """بررسی رمز: اگر هش قدیمی SHA256 باشد، خودکار migration می‌کنه."""
    if _is_pbkdf2_hash(stored_hash):
        return _verify_pbkdf2(pw, stored_hash)
    # هش قدیمی SHA256 — فقط تطابق می‌ده، migration در change-password انجام می‌شه
    old_hash = hashlib.sha256(f"{pw}{CONFIG['secret']}".encode()).hexdigest()
    return hmac.compare_digest(old_hash, stored_hash)

def _migrate_hash_if_needed(pw: str, stored_hash: str) -> str:
    """اگر هش قدیمی SHA256 باشد، هش جدید PBKDF2 برمی‌گرداند."""
    if _is_pbkdf2_hash(stored_hash):
        return stored_hash
    return _hash_pbkdf2(pw)

# ══════════════════════════════════════════════════════════════════════════════
# State save/load
# ══════════════════════════════════════════════════════════════════════════════
async def _serialize_state() -> dict:
    return {
        "links": dict(LINKS),
        "subs": dict(SUBS),
        "users": dict(USERS),
        "password_changed": AUTH.get("password_changed", False),
        "saved_at": datetime.now().isoformat(),
    }

async def load_state():
    global LINKS, AUTH, USERS
    try:
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        if DATA_FILE.exists():
            async with aiofiles.open(DATA_FILE, "r", encoding="utf-8") as f:
                raw = await f.read()
            if _use_orjson:
                data = orjson.loads(raw)
            else:
                data = json.loads(raw)
            LINKS.update(data.get("links", {}))
            SUBS.update(data.get("subs", {}))
            # مهاجرت ساختار users از نسخه‌های قبلی
            loaded_users = data.get("users", {})
            if loaded_users:
                USERS.update(loaded_users)
            else:
                # نسخه‌ی قدیمی: فقط یک password_hash داشتیم — کاربر ادمین پیش‌فرض بساز
                old_hash = data.get("password_hash")
                if old_hash:
                    USERS["admin"] = {
                        "password_hash": old_hash,
                        "role": "admin",
                        "totp_secret": None,
                        "totp_enabled": False,
                        "created_at": data.get("saved_at", datetime.now().isoformat()),
                    }
            if "password_changed" in data:
                AUTH["password_changed"] = data["password_changed"]
            # حذف لینک‌های legacy
            legacy_default_uids = [uid for uid, l in LINKS.items() if l.get("is_default")]
            for uid in legacy_default_uids:
                LINKS.pop(uid, None)
            if legacy_default_uids:
                asyncio.create_task(save_state())
            logger.info(f"State loaded: {len(LINKS)} links, {len(SUBS)} subs, {len(USERS)} users")
    except Exception as e:
        logger.warning(f"Could not load state: {e}")

async def save_state():
    async with SAVE_LOCK:
        try:
            DATA_DIR.mkdir(parents=True, exist_ok=True)
            data = await _serialize_state()
            tmp = DATA_FILE.with_suffix(".tmp")
            if _use_orjson:
                payload = orjson.dumps(data).decode("utf-8")
            else:
                payload = json.dumps(data, ensure_ascii=False, indent=2)
            async with aiofiles.open(tmp, "w", encoding="utf-8") as f:
                await f.write(payload)
            tmp.replace(DATA_FILE)
        except Exception as e:
            logger.warning(f"Could not save state: {e}")

# ══════════════════════════════════════════════════════════════════════════════
# In-memory state
# ══════════════════════════════════════════════════════════════════════════════
connections: dict = {}
stats = {
    "total_bytes": 0,
    "total_requests": 0,
    "total_errors": 0,
    "start_time": time.time(),
}
error_logs: deque = deque(maxlen=50)
activity_logs: deque = deque(maxlen=200)
hourly_traffic: dict = defaultdict(int)
http_client: httpx.AsyncClient | None = None
LINKS: dict = {}
LINKS_LOCK = asyncio.Lock()
SUBS: dict = {}
SUBS_LOCK = asyncio.Lock()

PROTOCOLS = ("vless-ws", "xhttp")
DEFAULT_PROTOCOL = "vless-ws"

FINGERPRINTS = ("chrome", "firefox", "safari", "ios", "android", "edge", "360", "qq", "random", "randomized")
DEFAULT_FINGERPRINT = "chrome"

DEFAULT_ALPN_BY_PROTOCOL = {
    "vless-ws": "http/1.1",
    "xhttp": "h2,http/1.1",
}
DEFAULT_PORT = 443
MIN_PORT, MAX_PORT = 1, 65535

DEFAULT_SPEED_LIMIT = 0

def log_activity(kind: str, message: str, level: str = "info"):
    activity_logs.append({
        "kind": kind,
        "level": level,
        "message": message,
        "time": datetime.now().isoformat(),
    })

# ══════════════════════════════════════════════════════════════════════════════
# Auth — چندکاربره با TOTP
# ══════════════════════════════════════════════════════════════════════════════
SESSION_COOKIE = "vexon_session"
SESSION_TTL = 60 * 60 * 24 * 365

# ساختار USERS: { "username": { "password_hash": str, "role": "admin"|"viewer", "totp_secret": str|None, "totp_enabled": bool, "created_at": str } }
USERS: dict = {}
USERS_LOCK = asyncio.Lock()

AUTH = {"password_changed": False}
SESSIONS: dict = {}
SESSIONS_LOCK = asyncio.Lock()

async def create_session(username: str) -> str:
    token = secrets.token_urlsafe(32)
    async with SESSIONS_LOCK:
        SESSIONS[token] = {"username": username, "expires": time.time() + SESSION_TTL}
    return token

async def is_valid_session(token: str | None) -> bool:
    if not token:
        return False
    async with SESSIONS_LOCK:
        sess = SESSIONS.get(token)
        if sess is None:
            return False
        if sess["expires"] < time.time():
            SESSIONS.pop(token, None)
            return False
        return True

async def get_session_user(token: str | None) -> str | None:
    if not token:
        return None
    async with SESSIONS_LOCK:
        sess = SESSIONS.get(token)
        if sess and sess["expires"] >= time.time():
            return sess["username"]
    return None

async def destroy_session(token: str | None):
    if not token:
        return
    async with SESSIONS_LOCK:
        SESSIONS.pop(token, None)

async def require_auth(request: Request):
    token = request.cookies.get(SESSION_COOKIE)
    if not await is_valid_session(token):
        raise HTTPException(status_code=401, detail="unauthorized")
    return token

async def require_admin(request: Request):
    token = await require_auth(request)
    username = await get_session_user(token)
    if not username:
        raise HTTPException(status_code=401, detail="unauthorized")
    user = USERS.get(username)
    if not user or user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="دسترسی مدیر لازم است")
    return token

# ── Rate limiting لاگین ────────────────────────────────────────────────────────
LOGIN_ATTEMPTS: dict = {}
LOGIN_MAX_ATTEMPTS = 5
LOGIN_WINDOW_SEC = 5 * 60

def _check_login_rate(ip: str) -> bool:
    now = time.time()
    entry = LOGIN_ATTEMPTS.get(ip)
    if entry is None or now - entry[1] > LOGIN_WINDOW_SEC:
        LOGIN_ATTEMPTS[ip] = (1, now)
        return True
    count, first = entry
    if count >= LOGIN_MAX_ATTEMPTS:
        return False
    LOGIN_ATTEMPTS[ip] = (count + 1, first)
    return True

# ── رمز پیش‌فرض رندوم ────────────────────────────────────────────────────────
def _load_or_create_admin_password() -> str:
    env_pw = os.environ.get("ADMIN_PASSWORD")
    if env_pw:
        return env_pw
    try:
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        if ADMIN_PW_FILE.exists():
            existing = ADMIN_PW_FILE.read_text(encoding="utf-8").strip()
            if existing:
                return existing
        new_pw = secrets.token_urlsafe(8)
        ADMIN_PW_FILE.write_text(new_pw, encoding="utf-8")
        return new_pw
    except Exception as e:
        logger.warning(f"Could not persist admin password: {e}")
        return secrets.token_urlsafe(8)

_initial_admin_pw = _load_or_create_admin_password()

# ══════════════════════════════════════════════════════════════════════════════
# Startup / Shutdown
# ══════════════════════════════════════════════════════════════════════════════
@app.on_event("startup")
async def startup():
    global http_client
    limits = httpx.Limits(max_connections=500, max_keepalive_connections=100)
    timeout = httpx.Timeout(30.0, connect=10.0)
    http_client = httpx.AsyncClient(
        limits=limits, timeout=timeout, follow_redirects=True, http2=True,
    )
    await load_state()
    # اگر هیچ کاربری وجود نداشت، کاربر admin پیش‌فرض بساز
    async with USERS_LOCK:
        if not USERS:
            USERS["admin"] = {
                "password_hash": hash_password(_initial_admin_pw),
                "role": "admin",
                "totp_secret": None,
                "totp_enabled": False,
                "created_at": datetime.now().isoformat(),
            }
            await save_state()
    await _tg_start_bot()
    log_activity("system", "سرور راه‌اندازی شد", "ok")
    logger.info(f"Vexon-panel v1.0.0 started on port {CONFIG['port']}")
    if not AUTH.get("password_changed"):
        logger.info(f"🔑 رمز اولیه پنل (admin): {_initial_admin_pw}")
        logger.info(f"🔑 اگر رمز رندوم بود، حتماً آن را یادداشت کنید!")

@app.on_event("shutdown")
async def shutdown():
    await save_state()
    await _tg_stop_bot()
    if http_client:
        await http_client.aclose()

# ══════════════════════════════════════════════════════════════════════════════
# Helpers
# ══════════════════════════════════════════════════════════════════════════════
def get_host(request: Request | None = None) -> str:
    if request is not None:
        h = request.headers.get("x-forwarded-host") or request.headers.get("host")
        if h:
            h = h.split(":")[0]
            CONFIG["host"] = h
            return h
    return os.environ.get("RAILWAY_PUBLIC_DOMAIN", CONFIG["host"])

def generate_uuid() -> str:
    h = secrets.token_hex(16)
    return f"{h[:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:32]}"

def now_ir() -> datetime:
    return datetime.now(IRAN_TZ)

def generate_vless_link(
    uuid: str,
    host: str,
    remark: str = "Vexon",
    protocol: str = DEFAULT_PROTOCOL,
    fingerprint: str | None = None,
    alpn: str | None = None,
    port: int | None = None,
) -> str:
    fp = (fingerprint or DEFAULT_FINGERPRINT).strip() or DEFAULT_FINGERPRINT
    if fp not in FINGERPRINTS:
        fp = DEFAULT_FINGERPRINT
    alpn_val = (alpn or "").strip() or DEFAULT_ALPN_BY_PROTOCOL.get(protocol, "http/1.1")
    port_val = port or DEFAULT_PORT
    if not (MIN_PORT <= port_val <= MAX_PORT):
        port_val = DEFAULT_PORT

    if protocol == "vless-ws":
        path = f"/ws/{uuid}"
        params = {
            "encryption": "none",
            "security": "tls",
            "type": "ws",
            "host": host,
            "path": path,
            "sni": host,
            "fp": fp,
            "alpn": alpn_val,
        }
    else:
        path = f"/xhttp/{uuid}"
        params = {
            "encryption": "none",
            "security": "tls",
            "type": "xhttp",
            "mode": "auto",
            "host": host,
            "path": path,
            "sni": host,
            "fp": fp,
            "alpn": alpn_val,
        }
    query = "&".join(f"{k}={quote(str(v))}" for k, v in params.items())
    return f"vless://{uuid}@{host}:{port_val}?{query}#{quote(remark)}"

def vless_link_for_link(link: dict, uid: str, host: str) -> str:
    proto = link.get("protocol", DEFAULT_PROTOCOL)
    return generate_vless_link(
        uid, host,
        remark=f"Vexon-{link.get('label','')}",
        protocol=proto,
        fingerprint=link.get("fingerprint"),
        alpn=link.get("alpn"),
        port=link.get("port"),
    )

def uptime() -> str:
    secs = int(time.time() - stats["start_time"])
    h, m, s = secs // 3600, (secs % 3600) // 60, secs % 60
    return f"{h:02d}:{m:02d}:{s:02d}"

def parse_size_to_bytes(value: float, unit: str) -> int:
    unit = unit.upper()
    if unit == "GB": return int(value * 1024 ** 3)
    if unit == "MB": return int(value * 1024 ** 2)
    if unit == "KB": return int(value * 1024)
    return int(value)

def parse_speed_to_bytes(value: float, unit: str) -> int:
    if value <= 0:
        return 0
    unit = (unit or "MBIT").upper()
    if unit == "MBIT":
        return int(value * 1024 * 1024 / 8)
    if unit == "KB":
        return int(value * 1024)
    if unit == "MB":
        return int(value * 1024 * 1024)
    return int(value)

def is_link_expired(link: dict) -> bool:
    exp = link.get("expires_at")
    if not exp:
        return False
    try:
        return datetime.now() > datetime.fromisoformat(exp)
    except Exception:
        return False

def is_link_allowed(link: dict | None) -> bool:
    if link is None:
        return False
    if not link.get("active", True):
        return False
    if is_link_expired(link):
        return False
    lb = link.get("limit_bytes", 0)
    if lb > 0 and link.get("used_bytes", 0) >= lb:
        return False
    return True

def fmt_bytes(b: int) -> str:
    if b < 1024: return f"{b} B"
    if b < 1024**2: return f"{b/1024:.1f} KB"
    if b < 1024**3: return f"{b/1024**2:.2f} MB"
    return f"{b/1024**3:.2f} GB"

def unique_ips_for_uuid(uuid: str) -> set:
    return {c.get("ip") for c in connections.values() if c.get("uuid") == uuid and c.get("ip")}

def is_ip_allowed(link: dict | None, uuid: str, ip: str) -> bool:
    if link is None:
        return False
    limit = int(link.get("ip_limit", 0) or 0)
    if limit <= 0:
        return True
    ips = unique_ips_for_uuid(uuid)
    if ip in ips:
        return True
    return len(ips) < limit

def client_ip(request: Request) -> str:
    fwd = request.headers.get("x-forwarded-for")
    if fwd:
        return fwd.split(",")[0].strip()
    real_ip = request.headers.get("x-real-ip")
    if real_ip:
        return real_ip.strip()
    return request.client.host if request.client else "نامشخص"

# ══════════════════════════════════════════════════════════════════════════════
# Basic endpoints
# ══════════════════════════════════════════════════════════════════════════════
@app.get("/")
async def root():
    return {"service": "Vexon-panel", "version": "1.0.0", "status": "active"}

@app.get("/health")
async def health():
    return {"status": "ok", "connections": len(connections), "uptime": uptime()}

# ══════════════════════════════════════════════════════════════════════════════
# Subscription
# ══════════════════════════════════════════════════════════════════════════════
@app.get("/sub/{uuid}")
async def subscription_single(uuid: str, request: Request):
    async with LINKS_LOCK:
        link = LINKS.get(uuid)
    if not link or not is_link_allowed(link):
        raise HTTPException(status_code=404, detail="not found or inactive")
    host = get_host(request)
    vless = vless_link_for_link(link, uuid, host)
    content = base64.b64encode(vless.encode()).decode()
    return Response(content=content, media_type="text/plain",
                    headers={"profile-title": quote(link["label"])})

@app.get("/sub-all")
async def subscription_all(request: Request, _=Depends(require_auth)):
    host = get_host(request)
    async with LINKS_LOCK:
        lines = [
            vless_link_for_link(d, uid, host)
            for uid, d in LINKS.items()
            if is_link_allowed(d)
        ]
    content = base64.b64encode("\n".join(lines).encode()).decode()
    return Response(content=content, media_type="text/plain")

# ══════════════════════════════════════════════════════════════════════════════
# Auth endpoints
# ══════════════════════════════════════════════════════════════════════════════
@app.post("/api/login")
async def api_login(request: Request):
    body = await request.json()
    ip = client_ip(request)
    if not _check_login_rate(ip):
        log_activity("auth", f"قفل شدن لاگین از {ip} (بیش از {LOGIN_MAX_ATTEMPTS} تلاش)", "err")
        raise HTTPException(status_code=429, detail="تعداد تلاش‌های ورود بیش از حد مجاز است. لطفاً چند دقیقه صبر کنید")
    username = str(body.get("username", "")).strip()
    password = str(body.get("password", ""))
    totp_code = str(body.get("totp", "")).strip() if body.get("totp") else None
    if not username or not password:
        raise HTTPException(status_code=401, detail="نام کاربری و رمز عبور الزامی است")
    async with USERS_LOCK:
        user = USERS.get(username)
    if not user or not verify_password(password, user["password_hash"]):
        log_activity("auth", f"تلاش ورود ناموفق از {ip} (کاربر: {username})", "err")
        raise HTTPException(status_code=401, detail="نام کاربری یا رمز عبور اشتباه است")
    # بررسی TOTP اگر فعال باشه
    if user.get("totp_enabled") and user.get("totp_secret"):
        if not totp_code:
            return JSONResponse({"ok": False, "totp_required": True, "detail": "کد یک‌بار مصرف TOTP را وارد کنید"})
        if not pyotp:
            raise HTTPException(status_code=500, detail="TOTP در دسترس نیست (پکیج pyotp نصب نیست)")
        totp = pyotp.TOTP(user["totp_secret"])
        if not totp.verify(totp_code, valid_window=1):
            log_activity("auth", f"کد TOTP نامعتبر از {ip} (کاربر: {username})", "err")
            raise HTTPException(status_code=401, detail="کد یک‌بار مصرف اشتباه است")
    # مهاجرت خودکار هش قدیمی
    if not _is_pbkdf2_hash(user["password_hash"]):
        async with USERS_LOCK:
            user["password_hash"] = _migrate_hash_if_needed(password, user["password_hash"])
            await save_state()
        logger.info(f"Password hash migrated for user: {username}")
    LOGIN_ATTEMPTS.pop(ip, None)
    token = await create_session(username)
    log_activity("auth", f"ورود موفق به پنل از {ip} (کاربر: {username})", "ok")
    resp = JSONResponse({"ok": True})
    resp.set_cookie(SESSION_COOKIE, token, max_age=SESSION_TTL, httponly=True, samesite="lax", path="/")
    return resp

@app.post("/api/logout")
async def api_logout(request: Request):
    await destroy_session(request.cookies.get(SESSION_COOKIE))
    resp = JSONResponse({"ok": True})
    resp.delete_cookie(SESSION_COOKIE, path="/")
    return resp

@app.get("/api/me")
async def api_me(request: Request):
    token = request.cookies.get(SESSION_COOKIE)
    if not await is_valid_session(token):
        return {"authenticated": False}
    username = await get_session_user(token)
    user = USERS.get(username, {})
    return {"authenticated": True, "username": username, "role": user.get("role", "viewer"), "totp_enabled": user.get("totp_enabled", False)}

@app.get("/api/init-password")
async def api_init_password():
    if AUTH.get("password_changed"):
        return {"show": False}
    return {"show": True, "password": _initial_admin_pw}

# ── مدیریت کاربران ────────────────────────────────────────────────────────────
@app.get("/api/users")
async def list_users(_=Depends(require_admin)):
    result = []
    for uname, u in USERS.items():
        result.append({
            "username": uname,
            "role": u.get("role", "viewer"),
            "totp_enabled": u.get("totp_enabled", False),
            "created_at": u.get("created_at", ""),
        })
    return {"users": result}

@app.post("/api/users")
async def create_user(request: Request, _=Depends(require_admin)):
    body = await request.json()
    username = str(body.get("username", "")).strip()
    password = str(body.get("password", ""))
    role = str(body.get("role", "viewer")).strip()
    if not username or len(username) < 3:
        raise HTTPException(status_code=400, detail="نام کاربری باید حداقل ۳ کاراکتر باشد")
    if not password or len(password) < 6:
        raise HTTPException(status_code=400, detail="رمز عبور باید حداقل ۶ کاراکتر باشد")
    if role not in ("admin", "viewer"):
        role = "viewer"
    async with USERS_LOCK:
        if username in USERS:
            raise HTTPException(status_code=409, detail="این نام کاربری قبلاً ثبت شده")
        USERS[username] = {
            "password_hash": hash_password(password),
            "role": role,
            "totp_secret": None,
            "totp_enabled": False,
            "created_at": datetime.now().isoformat(),
        }
        await save_state()
    log_activity("auth", f"کاربر جدید «{username}» با نقش «{role}» ساخته شد", "ok")
    return {"ok": True}

@app.delete("/api/users/{username}")
async def delete_user(username: str, _=Depends(require_admin)):
    if username == "admin":
        raise HTTPException(status_code=400, detail="نمی‌توان کاربر admin اصلی را حذف کرد")
    async with USERS_LOCK:
        if username not in USERS:
            raise HTTPException(status_code=404, detail="کاربر یافت نشد")
        del USERS[username]
        await save_state()
    log_activity("auth", f"کاربر «{username}» حذف شد", "warn")
    return {"ok": True}

@app.patch("/api/users/{username}")
async def update_user(username: str, request: Request, _=Depends(require_admin)):
    body = await request.json()
    async with USERS_LOCK:
        if username not in USERS:
            raise HTTPException(status_code=404, detail="کاربر یافت نشد")
        user = USERS[username]
        if "role" in body:
            new_role = str(body["role"])
            if new_role in ("admin", "viewer"):
                user["role"] = new_role
        if "password" in body and body["password"]:
            pw = str(body["password"])
            if len(pw) < 6:
                raise HTTPException(status_code=400, detail="رمز عبور باید حداقل ۶ کاراکتر باشد")
            user["password_hash"] = hash_password(pw)
        await save_state()
    return {"ok": True}

# ── TOTP ──────────────────────────────────────────────────────────────────────
@app.post("/api/totp/setup")
async def totp_setup(request: Request, token=Depends(require_auth)):
    username = await get_session_user(token)
    if not username:
        raise HTTPException(status_code=401, detail="unauthorized")
    if not pyotp:
        raise HTTPException(status_code=500, detail="TOTP در دسترس نیست (پکیج pyotp نصب نیست)")
    async with USERS_LOCK:
        user = USERS.get(username)
        if not user:
            raise HTTPException(status_code=404, detail="کاربر یافت نشد")
        secret = pyotp.random_base32()
        user["totp_secret"] = secret
        await save_state()
    totp = pyotp.TOTP(secret)
    provisioning_uri = totp.provisioning_uri(name=username, issuer_name="Vexon-panel")
    return {"secret": secret, "otpauth_url": provisioning_uri}

@app.post("/api/totp/verify")
async def totp_verify(request: Request, token=Depends(require_auth)):
    body = await request.json()
    code = str(body.get("code", "")).strip()
    username = await get_session_user(token)
    if not username or not code:
        raise HTTPException(status_code=400, detail="کد الزامی است")
    if not pyotp:
        raise HTTPException(status_code=500, detail="TOTP در دسترس نیست")
    async with USERS_LOCK:
        user = USERS.get(username)
        if not user or not user.get("totp_secret"):
            raise HTTPException(status_code=400, detail="ابتدا TOTP را راه‌اندازی کنید")
        totp = pyotp.TOTP(user["totp_secret"])
        if not totp.verify(code, valid_window=1):
            raise HTTPException(status_code=400, detail="کد یک‌بار مصرف اشتباه است")
        user["totp_enabled"] = True
        await save_state()
    log_activity("auth", f"TOTP فعال شد برای کاربر {username}", "ok")
    return {"ok": True}

@app.post("/api/totp/disable")
async def totp_disable(request: Request, token=Depends(require_auth)):
    body = await request.json()
    password = str(body.get("password", "")).strip()
    username = await get_session_user(token)
    if not username or not password:
        raise HTTPException(status_code=400, detail="رمز عبور الزامی است")
    async with USERS_LOCK:
        user = USERS.get(username)
        if not user or not verify_password(password, user["password_hash"]):
            raise HTTPException(status_code=400, detail="رمز عبور اشتباه است")
        user["totp_secret"] = None
        user["totp_enabled"] = False
        await save_state()
    log_activity("auth", f"TOTP غیرفعال شد برای کاربر {username}", "ok")
    return {"ok": True}

@app.post("/api/change-password")
async def api_change_password(request: Request, token=Depends(require_auth)):
    body = await request.json()
    username = await get_session_user(token)
    if not username:
        raise HTTPException(status_code=401, detail="unauthorized")
    async with USERS_LOCK:
        user = USERS.get(username)
        if not user:
            raise HTTPException(status_code=404, detail="کاربر یافت نشد")
        if not verify_password(str(body.get("current_password", "")), user["password_hash"]):
            raise HTTPException(status_code=400, detail="رمز فعلی اشتباه است")
        new = str(body.get("new_password", ""))
        if len(new) < 4:
            raise HTTPException(status_code=400, detail="رمز جدید باید حداقل ۴ کاراکتر باشد")
        user["password_hash"] = hash_password(new)
        AUTH["password_changed"] = True
        # ریست همه سشن‌ها به‌جز سشن فعلی
        async with SESSIONS_LOCK:
            SESSIONS.clear()
            SESSIONS[token] = {"username": username, "expires": time.time() + SESSION_TTL}
        await save_state()
    log_activity("auth", f"رمز عبور کاربر {username} تغییر کرد", "ok")
    return {"ok": True}

# ══════════════════════════════════════════════════════════════════════════════
# Stats
# ══════════════════════════════════════════════════════════════════════════════
@app.get("/stats")
async def get_stats(_=Depends(require_auth)):
    async with LINKS_LOCK:
        snap = dict(LINKS)
    return {
        "active_connections": len(connections),
        "total_traffic_mb": round(stats["total_bytes"] / (1024 ** 2), 2),
        "total_requests": stats["total_requests"],
        "total_errors": stats["total_errors"],
        "uptime": uptime(),
        "timestamp": datetime.now().isoformat(),
        "hourly": dict(hourly_traffic),
        "recent_errors": list(error_logs)[-10:],
        "links_count": len(snap),
        "active_links": sum(1 for l in snap.values() if is_link_allowed(l)),
        "expired_links": sum(1 for l in snap.values() if is_link_expired(l)),
    }

# ══════════════════════════════════════════════════════════════════════════════
# Activity Logs
# ══════════════════════════════════════════════════════════════════════════════
@app.get("/api/activity")
async def get_activity(_=Depends(require_auth)):
    return {"logs": list(activity_logs)[-150:]}

# ══════════════════════════════════════════════════════════════════════════════
# Live connections
# ══════════════════════════════════════════════════════════════════════════════
@app.get("/api/connections")
async def get_connections(_=Depends(require_auth)):
    async with LINKS_LOCK:
        snap = dict(LINKS)

    by_uuid: dict[str, dict] = {}
    for conn_id, c in connections.items():
        uid = c.get("uuid", "نامشخص")
        ip = c.get("ip", "نامشخص")
        link = snap.get(uid)
        label = link.get("label") if link else "کانفیگ حذف‌شده"
        proto = link.get("protocol", DEFAULT_PROTOCOL) if link else "?"

        cfg = by_uuid.get(uid)
        if cfg is None:
            cfg = {
                "uuid": uid,
                "label": label,
                "protocol": proto,
                "sessions": 0,
                "bytes": 0,
                "ips": {},
                "first_connected_at": c.get("connected_at"),
                "last_connected_at": c.get("connected_at"),
            }
            by_uuid[uid] = cfg
        cfg["sessions"] += 1
        cfg["bytes"] += c.get("bytes", 0)

        ip_entry = cfg["ips"].get(ip)
        if ip_entry is None:
            ip_entry = {
                "ip": ip, "sessions": 0, "bytes": 0, "transports": set(),
                "first_connected_at": c.get("connected_at"),
                "last_connected_at": c.get("connected_at"),
            }
            cfg["ips"][ip] = ip_entry
        ip_entry["sessions"] += 1
        ip_entry["bytes"] += c.get("bytes", 0)
        ip_entry["transports"].add(c.get("transport", "vless-ws"))

        ca = c.get("connected_at")
        for entry in (cfg, ip_entry):
            if ca:
                if not entry["first_connected_at"] or ca < entry["first_connected_at"]:
                    entry["first_connected_at"] = ca
                if not entry["last_connected_at"] or ca > entry["last_connected_at"]:
                    entry["last_connected_at"] = ca

    configs = []
    for uid, cfg in by_uuid.items():
        ip_list = []
        for ip, e in cfg["ips"].items():
            ip_list.append({
                "ip": ip,
                "sessions": e["sessions"],
                "bytes": e["bytes"],
                "bytes_fmt": fmt_bytes(e["bytes"]),
                "transports": sorted(e["transports"]),
                "connected_at": e["first_connected_at"],
                "last_connected_at": e["last_connected_at"],
            })
        ip_list.sort(key=lambda x: x.get("last_connected_at") or "", reverse=True)
        configs.append({
            "uuid": uid,
            "label": cfg["label"],
            "protocol": cfg["protocol"],
            "ip_count": len(ip_list),
            "sessions": cfg["sessions"],
            "bytes": cfg["bytes"],
            "bytes_fmt": fmt_bytes(cfg["bytes"]),
            "connected_at": cfg["first_connected_at"],
            "last_connected_at": cfg["last_connected_at"],
            "connections": ip_list,
        })
    configs.sort(key=lambda x: x.get("last_connected_at") or "", reverse=True)

    return {
        "configs": configs,
        "count": len(configs),
        "raw_count": len(connections),
    }

# ══════════════════════════════════════════════════════════════════════════════
# Link Management
# ══════════════════════════════════════════════════════════════════════════════
async def make_link(
    label: str = "لینک جدید",
    limit_bytes: int = 0,
    expires_at: str | None = None,
    note: str = "",
    protocol: str = DEFAULT_PROTOCOL,
    fingerprint: str = DEFAULT_FINGERPRINT,
    alpn: str = "",
    port: int = DEFAULT_PORT,
    ip_limit: int = 0,
    speed_limit_bytes: int = 0,
) -> tuple[str, dict]:
    if protocol not in PROTOCOLS:
        protocol = DEFAULT_PROTOCOL
    fingerprint = (fingerprint or DEFAULT_FINGERPRINT).strip().lower()
    if fingerprint not in FINGERPRINTS:
        fingerprint = DEFAULT_FINGERPRINT
    if not (MIN_PORT <= port <= MAX_PORT):
        port = DEFAULT_PORT
    uid = generate_uuid()
    async with LINKS_LOCK:
        LINKS[uid] = {
            "label": (label or "لینک جدید").strip()[:60] or "لینک جدید",
            "limit_bytes": max(0, limit_bytes),
            "used_bytes": 0,
            "created_at": datetime.now().isoformat(),
            "active": True,
            "expires_at": expires_at,
            "note": (note or "").strip()[:200],
            "is_default": False,
            "protocol": protocol,
            "fingerprint": fingerprint,
            "alpn": (alpn or "").strip()[:100],
            "port": port,
            "ip_limit": max(0, ip_limit),
            "speed_limit_bytes": max(0, speed_limit_bytes),
        }
    asyncio.create_task(save_state())
    log_activity("link", f"کانفیگ «{LINKS[uid]['label']}» ساخته شد", "ok")
    return uid, LINKS[uid]

async def remove_link(uid: str) -> str | None:
    async with LINKS_LOCK:
        if uid not in LINKS:
            return None
        label = LINKS[uid].get("label", uid)
        del LINKS[uid]
    asyncio.create_task(save_state())
    log_activity("link", f"کانفیگ «{label}» حذف شد", "err")
    return label

async def set_link_active(uid: str, active: bool) -> dict | None:
    async with LINKS_LOCK:
        if uid not in LINKS:
            return None
        LINKS[uid]["active"] = bool(active)
        label = LINKS[uid]["label"]
    log_activity("link", f"کانفیگ «{label}» {'فعال' if active else 'غیرفعال'} شد", "ok" if active else "warn")
    asyncio.create_task(save_state())
    return LINKS[uid]

@app.post("/api/links")
async def create_link(request: Request, _=Depends(require_auth)):
    body = await request.json()
    lv = float(body.get("limit_value") or 0)
    lu = body.get("limit_unit") or "GB"
    limit_bytes = 0 if lv <= 0 else parse_size_to_bytes(lv, lu)
    exp_days = int(body.get("expires_days") or 0)
    expires_at = (datetime.now() + timedelta(days=exp_days)).isoformat() if exp_days > 0 else None
    try:
        port = int(body.get("port") or DEFAULT_PORT)
    except (TypeError, ValueError):
        port = DEFAULT_PORT
    try:
        ip_limit = int(body.get("ip_limit") or 0)
    except (TypeError, ValueError):
        ip_limit = 0

    sv = float(body.get("speed_limit_value") or 0)
    su = body.get("speed_limit_unit") or "MBIT"
    speed_limit_bytes = 0 if sv <= 0 else parse_speed_to_bytes(sv, su)

    uid, link = await make_link(
        label=body.get("label") or "لینک جدید",
        limit_bytes=limit_bytes,
        expires_at=expires_at,
        note=body.get("note") or "",
        protocol=body.get("protocol") or DEFAULT_PROTOCOL,
        fingerprint=body.get("fingerprint") or DEFAULT_FINGERPRINT,
        alpn=body.get("alpn") or "",
        port=port,
        ip_limit=ip_limit,
        speed_limit_bytes=speed_limit_bytes,
    )

    host = get_host(request)
    return {
        "uuid": uid,
        **link,
        "expired": False,
        "vless_link": vless_link_for_link(link, uid, host),
        "sub_url": f"https://{host}/p/{uid}",
        "raw_sub_url": f"https://{host}/sub/{uid}",
    }

@app.get("/api/links")
async def list_links(request: Request, _=Depends(require_auth)):
    host = get_host(request)
    async with LINKS_LOCK:
        snap = dict(LINKS)
    result = []
    for uid, d in snap.items():
        proto = d.get("protocol", DEFAULT_PROTOCOL)
        result.append({
            "uuid": uid,
            **d,
            "protocol": proto,
            "expired": is_link_expired(d),
            "vless_link": vless_link_for_link(d, uid, host),
            "sub_url": f"https://{host}/p/{uid}",
            "raw_sub_url": f"https://{host}/sub/{uid}",
            "connected_ips": len(unique_ips_for_uuid(uid)),
        })
    result.sort(key=lambda x: x["created_at"], reverse=True)
    return {"links": result}

@app.patch("/api/links/{uid}")
async def update_link(uid: str, request: Request, _=Depends(require_auth)):
    body = await request.json()
    async with LINKS_LOCK:
        if uid not in LINKS:
            raise HTTPException(status_code=404, detail="link not found")
        link = LINKS[uid]
        label = link.get("label")
        if "active" in body:
            link["active"] = bool(body["active"])
            log_activity("link", f"کانفیگ «{label}» {'فعال' if link['active'] else 'غیرفعال'} شد", "ok" if link["active"] else "warn")
        if "label" in body:
            link["label"] = str(body["label"])[:60]
        if "note" in body:
            link["note"] = str(body["note"])[:200]
        if "reset_usage" in body and body["reset_usage"]:
            link["used_bytes"] = 0
            log_activity("link", f"مصرف کانفیگ «{label}» ریست شد", "info")
        if "limit_value" in body:
            lv = float(body.get("limit_value") or 0)
            lu = body.get("limit_unit") or "GB"
            link["limit_bytes"] = 0 if lv <= 0 else parse_size_to_bytes(lv, lu)
        if "expires_days" in body:
            ed = int(body["expires_days"] or 0)
            link["expires_at"] = (datetime.now() + timedelta(days=ed)).isoformat() if ed > 0 else None
        if "fingerprint" in body:
            fp = str(body.get("fingerprint") or DEFAULT_FINGERPRINT).strip().lower()
            link["fingerprint"] = fp if fp in FINGERPRINTS else DEFAULT_FINGERPRINT
        if "alpn" in body:
            link["alpn"] = str(body.get("alpn") or "").strip()[:100]
        if "port" in body:
            try:
                p = int(body.get("port") or DEFAULT_PORT)
            except (TypeError, ValueError):
                p = DEFAULT_PORT
            link["port"] = p if (MIN_PORT <= p <= MAX_PORT) else DEFAULT_PORT
        if "ip_limit" in body:
            try:
                il = int(body.get("ip_limit") or 0)
            except (TypeError, ValueError):
                il = 0
            link["ip_limit"] = max(0, il)
        if "speed_limit_value" in body:
            sv = float(body.get("speed_limit_value") or 0)
            su = body.get("speed_limit_unit") or "MBIT"
            link["speed_limit_bytes"] = 0 if sv <= 0 else parse_speed_to_bytes(sv, su)
            from speed_limit import reset_bucket
            reset_bucket(uid)
        if any(k in body for k in ("label", "note", "limit_value", "expires_days", "fingerprint", "alpn", "port", "ip_limit", "speed_limit_value")):
            log_activity("link", f"کانفیگ «{link['label']}» ویرایش شد", "info")

    asyncio.create_task(save_state())
    return {"ok": True}

@app.delete("/api/links/{uid}")
async def delete_link(uid: str, _=Depends(require_auth)):
    label = await remove_link(uid)
    if label is None:
        raise HTTPException(status_code=404, detail="link not found")
    return {"ok": True, "deleted": uid}

# ── Export CSV ────────────────────────────────────────────────────────────────
@app.get("/api/links/export/csv")
async def export_links_csv(_=Depends(require_auth)):
    async with LINKS_LOCK:
        snap = dict(LINKS)
    lines = ["uuid,label,protocol,active,used_bytes,limit_bytes,speed_limit_bytes,ip_limit,expires_at,created_at"]
    for uid, d in snap.items():
        exp = d.get("expires_at", "")
        lines.append(f"{uid},{d.get('label','')},{d.get('protocol','vless-ws')},{d.get('active',True)},{d.get('used_bytes',0)},{d.get('limit_bytes',0)},{d.get('speed_limit_bytes',0)},{d.get('ip_limit',0)},{exp},{d.get('created_at','')}")
    content = "\n".join(lines)
    return Response(
        content=content,
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=vexon_links.csv"},
    )

# ══════════════════════════════════════════════════════════════════════════════
# Relay (imported modules)
# ══════════════════════════════════════════════════════════════════════════════
from relay_vless import (
    RELAY_BUF,
    parse_vless_header,
    check_and_use,
    relay_ws_to_tcp,
    relay_tcp_to_ws,
    websocket_tunnel,
)

app.add_api_websocket_route("/ws/{uuid}", websocket_tunnel)

from xhttp import router as xhttp_router
app.include_router(xhttp_router)

from telegram_bot import start_bot as _tg_start_bot, stop_bot as _tg_stop_bot

# ══════════════════════════════════════════════════════════════════════════════
# HTTP Proxy — پشت احراز هویت ادمین
# ══════════════════════════════════════════════════════════════════════════════
_HOP = {"connection","keep-alive","proxy-authenticate","proxy-authorization",
        "te","trailers","transfer-encoding","upgrade","content-encoding","content-length"}

@app.api_route("/proxy/{target_url:path}", methods=["GET","POST","PUT","DELETE","PATCH","HEAD","OPTIONS"])
async def http_proxy(target_url: str, request: Request, _=Depends(require_admin)):
    if not target_url.startswith("http"):
        target_url = "https://" + target_url
    try:
        body = await request.body()
        headers = {k: v for k, v in request.headers.items() if k.lower() not in _HOP and k.lower() != "host"}
        resp = await http_client.request(method=request.method, url=target_url, headers=headers, content=body)
        stats["total_bytes"] += len(resp.content)
        stats["total_requests"] += 1
        hourly_traffic[now_ir().strftime("%H:00")] += len(resp.content)
        return Response(content=resp.content, status_code=resp.status_code,
                        headers={k: v for k, v in resp.headers.items() if k.lower() not in _HOP})
    except Exception as exc:
        stats["total_errors"] += 1
        error_logs.append({"error": str(exc), "url": target_url, "time": datetime.now().isoformat()})
        raise HTTPException(status_code=502, detail=f"Proxy error: {exc}")

# ══════════════════════════════════════════════════════════════════════════════
# Public sub page — با پشتیبانی کامل رمز
# ══════════════════════════════════════════════════════════════════════════════
@app.get("/p/{uuid_key}", response_class=HTMLResponse)
async def public_sub_page(uuid_key: str, request: Request):
    from pages import get_public_page_html
    async with LINKS_LOCK:
        exists = uuid_key in LINKS
    if not exists:
        return HTMLResponse("<h2 style='font-family:sans-serif;padding:40px'>کانفیگ پیدا نشد</h2>", status_code=404)
    return HTMLResponse(content=get_public_page_html(uuid_key))

@app.get("/api/public/sub/{uuid_key}")
async def public_sub_data(uuid_key: str, request: Request):
    async with LINKS_LOCK:
        link = LINKS.get(uuid_key)
    if not link:
        raise HTTPException(status_code=404, detail="not found")

    host = get_host(request)
    allowed = is_link_allowed(link)
    conn_count = sum(1 for c in connections.values() if c.get("uuid") == uuid_key)
    proto = link.get("protocol", DEFAULT_PROTOCOL)
    sub_pw = link.get("sub_password", "")
    link_out = {
        "uuid": uuid_key,
        "label": link["label"],
        "active": allowed,
        "protocol": proto,
        "used_bytes": link.get("used_bytes", 0),
        "used_fmt": fmt_bytes(link.get("used_bytes", 0)),
        "limit_bytes": link.get("limit_bytes", 0),
        "limit_fmt": "∞" if link.get("limit_bytes", 0) == 0 else fmt_bytes(link["limit_bytes"]),
        "expires_at": link.get("expires_at"),
        "vless_link": vless_link_for_link(link, uuid_key, host),
        "sub_url": f"https://{host}/sub/{uuid_key}",
        "connections": conn_count,
        "ip_limit": link.get("ip_limit", 0),
        "speed_limit_bytes": link.get("speed_limit_bytes", 0),
    }

    return {
        "locked": bool(sub_pw),
        "name": link["label"],
        "desc": link.get("note", ""),
        "sub_url": f"https://{host}/p/{uuid_key}",
        "active_connections": conn_count,
        "total_used_fmt": fmt_bytes(link.get("used_bytes", 0)),
        "links": [link_out],
    }

@app.post("/api/public/sub/{uuid_key}/unlock")
async def public_sub_unlock(uuid_key: str, request: Request):
    body = await request.json()
    password = str(body.get("password", "")).strip()
    async with LINKS_LOCK:
        link = LINKS.get(uuid_key)
    if not link:
        raise HTTPException(status_code=404, detail="not found")
    sub_pw = link.get("sub_password", "")
    if not sub_pw:
        return {"ok": True, "locked": False}
    if not password:
        raise HTTPException(status_code=401, detail="رمز عبور الزامی است")
    if not verify_password(password, sub_pw):
        raise HTTPException(status_code=401, detail="رمز عبور اشتباه است")
    return {"ok": True, "locked": False}

# ── تنظیم رمز ساب صفحه پابلیک ────────────────────────────────────────────────
@app.post("/api/links/{uid}/sub-password")
async def set_sub_password(uid: str, request: Request, _=Depends(require_auth)):
    body = await request.json()
    password = str(body.get("password", "")).strip()
    async with LINKS_LOCK:
        if uid not in LINKS:
            raise HTTPException(status_code=404, detail="link not found")
        if password:
            LINKS[uid]["sub_password"] = hash_password(password)
        else:
            LINKS[uid].pop("sub_password", None)
    asyncio.create_task(save_state())
    return {"ok": True, "locked": bool(password)}

# ══════════════════════════════════════════════════════════════════════════════
# HTML Pages
# ══════════════════════════════════════════════════════════════════════════════
from pages import LOGIN_HTML, DASHBOARD_HTML

@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    if await is_valid_session(request.cookies.get(SESSION_COOKIE)):
        return RedirectResponse(url="/dashboard")
    return HTMLResponse(content=LOGIN_HTML)

@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request):
    if not await is_valid_session(request.cookies.get(SESSION_COOKIE)):
        return RedirectResponse(url="/login")
    return HTMLResponse(content=DASHBOARD_HTML)

@app.get("/test-ws", response_class=HTMLResponse)
async def test_ws_redirect():
    return HTMLResponse(content="<script>location.href='/dashboard'</script>")

# ══════════════════════════════════════════════════════════════════════════════
# Prometheus metrics
# ══════════════════════════════════════════════════════════════════════════════
@app.get("/metrics")
async def prometheus_metrics():
    uptime_secs = int(time.time() - stats["start_time"])
    metrics = f"""# HELP vexon_connections_active تعداد اتصالات فعال
# TYPE vexon_connections_active gauge
vexon_connections_active {len(connections)}
# HELP vexon_bytes_total کل بایت‌های انتقال‌یافته
# TYPE vexon_bytes_total counter
vexon_bytes_total {stats["total_bytes"]}
# HELP vexon_requests_total کل درخواست‌ها
# TYPE vexon_requests_total counter
vexon_requests_total {stats["total_requests"]}
# HELP vexon_errors_total کل خطاها
# TYPE vexon_errors_total counter
vexon_errors_total {stats["total_errors"]}
# HELP vexon_links_total تعداد کل کانفیگ‌ها
# TYPE vexon_links_total gauge
vexon_links_total {len(LINKS)}
# HELP vexon_uptime_seconds آپتایم سرور به ثانیه
# TYPE vexon_uptime_seconds gauge
vexon_uptime_seconds {uptime_secs}
# HELP vexon_users_total تعداد کل کاربران
# TYPE vexon_users_total gauge
vexon_users_total {len(USERS)}
"""
    return Response(content=metrics, media_type="text/plain; version=0.0.4; charset=utf-8")

if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=CONFIG["port"], log_level="info", workers=1)
