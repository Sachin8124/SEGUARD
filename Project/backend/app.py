"""
se_guard_backend/app.py
========================
SE-GUARD — Flask REST API Server

Endpoints:
  POST /api/detect/profile    — Fake profile detection
  POST /api/detect/message    — Message abuse / threat detection
  POST /api/detect/review     — Fake review detection
  POST /api/detect/payment    — Suspicious payment detection
  POST /api/detect/product    — Fake product listing detection
  POST /api/detect/batch      — Run all detectors at once

  POST /api/auth/register     — Register user (bcrypt hashed)
  POST /api/auth/login        — Login → JWT token

  GET  /api/health            — Health check
  GET  /api/stats             — Detection statistics
"""

import os, sys, time, datetime, logging, json, asyncio, inspect, atexit, base64, re
from functools import wraps
from collections import defaultdict, OrderedDict
from concurrent.futures import ThreadPoolExecutor
from hashlib import sha256
from threading import Lock, Thread
from uuid import uuid4
from typing import Any, Optional, Dict, Tuple, cast

from flask import Flask, request, jsonify, send_from_directory, g
from flask_cors import CORS
import bcrypt, jwt
from pymongo import MongoClient
from bson import ObjectId
from dotenv import load_dotenv
from werkzeug.exceptions import HTTPException

try:
    import certifi
except ImportError:
    certifi = None

try:
    import redis
except ImportError:
    redis = None

try:
    from motor.motor_asyncio import AsyncIOMotorClient
except ImportError:
    AsyncIOMotorClient = None

try:
    from flask_compress import Compress
except ImportError:
    Compress = None

try:
    from apscheduler.schedulers.background import BackgroundScheduler
except ImportError:
    BackgroundScheduler = None

# ─────────────────────────────────────────────────────────────────────────────
logging.basicConfig(level=logging.INFO, format="[SE-GUARD] %(levelname)s %(message)s")
log = logging.getLogger(__name__)

load_dotenv()

app = Flask(__name__, static_folder=None)
CORS(app, resources={r"/api/*": {"origins": "*"}})
if Compress is not None:
    Compress(app)

BACKEND_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(BACKEND_DIR)
FRONTEND_DIR = os.path.join(PROJECT_ROOT, "frontend")

SECRET_KEY = os.getenv("SE_GUARD_SECRET", "se-guard-super-secret-dev-key-2025")

USER_CACHE_TTL_SECONDS = int(os.getenv("USER_CACHE_TTL_SECONDS", "300"))
JWT_CACHE_TTL_CAP_SECONDS = int(os.getenv("JWT_CACHE_TTL_CAP_SECONDS", "86400"))
BCRYPT_ROUNDS = int(os.getenv("BCRYPT_ROUNDS", "10"))
AUTH_REQUEST_TIMEOUT_SECONDS = float(os.getenv("AUTH_REQUEST_TIMEOUT_SECONDS", "3"))
AUTH_RATE_LIMIT_PER_MINUTE = int(os.getenv("AUTH_RATE_LIMIT_PER_MINUTE", "10"))
AUTH_CIRCUIT_BREAKER_THRESHOLD = int(os.getenv("AUTH_CIRCUIT_BREAKER_THRESHOLD", "5"))
AUTH_CIRCUIT_BREAKER_OPEN_SECONDS = int(os.getenv("AUTH_CIRCUIT_BREAKER_OPEN_SECONDS", "30"))
MONGO_BUILD_INDEXES = os.getenv("MONGO_BUILD_INDEXES", "1") == "1"
ALLOWED_APP_ROLES = {"business", "client", "freelancer"}


class TTLCache:
    """Small in-memory TTL cache used as fallback when Redis is unavailable."""
    def __init__(self, max_size: int = 5000):
        self.max_size = max_size
        self._data = OrderedDict()
        self._lock = Lock()

    def get(self, key):
        now = time.time()
        with self._lock:
            item = self._data.get(key)
            if not item:
                return None
            expires_at, value = item
            if expires_at <= now:
                self._data.pop(key, None)
                return None
            self._data.move_to_end(key)
            return value

    def set(self, key, value, ttl_seconds: int):
        expires_at = time.time() + max(1, int(ttl_seconds))
        with self._lock:
            self._data[key] = (expires_at, value)
            self._data.move_to_end(key)
            if len(self._data) > self.max_size:
                self._data.popitem(last=False)

    def delete(self, key):
        with self._lock:
            self._data.pop(key, None)

    def prune(self):
        now = time.time()
        removed = 0
        with self._lock:
            keys = [k for k, (expires_at, _) in self._data.items() if expires_at <= now]
            for key in keys:
                self._data.pop(key, None)
                removed += 1
        return removed

    def clear(self):
        with self._lock:
            self._data.clear()


class AsyncCircuitBreaker:
    """Basic async circuit breaker for MongoDB operations."""
    def __init__(self, failure_threshold: int, open_seconds: int):
        self.failure_threshold = max(1, failure_threshold)
        self.open_seconds = max(1, open_seconds)
        self._lock = Lock()
        self._failures = 0
        self._opened_until = 0.0

    def _is_open(self):
        now = time.time()
        return self._opened_until > now

    async def call(self, operation_name: str, operation):
        with self._lock:
            if self._is_open():
                raise RuntimeError(f"Circuit open for {operation_name}")

        try:
            result = await asyncio.wait_for(operation(), timeout=AUTH_REQUEST_TIMEOUT_SECONDS)
        except Exception:
            with self._lock:
                self._failures += 1
                if self._failures >= self.failure_threshold:
                    self._opened_until = time.time() + self.open_seconds
                    log.warning(f"[CircuitBreaker] Opened for {operation_name}")
            raise

        with self._lock:
            self._failures = 0
            self._opened_until = 0.0
        return result


LOCAL_USER_CACHE = TTLCache(max_size=8000)
LOCAL_TOKEN_CACHE = TTLCache(max_size=8000)
AUTH_POOL = ThreadPoolExecutor(max_workers=4)
_detection_models_module = None
AUTH_CIRCUIT_BREAKER = AsyncCircuitBreaker(
    failure_threshold=AUTH_CIRCUIT_BREAKER_THRESHOLD,
    open_seconds=AUTH_CIRCUIT_BREAKER_OPEN_SECONDS,
)
RATE_LIMIT_LOCAL = {}
RATE_LIMIT_LOCK = Lock()
ASYNC_LOOP = None
ASYNC_LOOP_THREAD = None
INDEX_BUILD_STARTED = False
INDEX_BUILD_LOCK = Lock()


def _get_models(load_if_missing=True):
    """Lazy-load detection models module to keep app startup fast and responsive."""
    global _detection_models_module
    if _detection_models_module is None:
        from models import detection_models as detection_models_module
        _detection_models_module = detection_models_module
    return _detection_models_module.get_models(load_if_missing=load_if_missing)


def _json_loads_safe(value):
    try:
        return json.loads(value)
    except Exception:
        return None


def _json_dumps_safe(value):
    try:
        return json.dumps(value)
    except Exception:
        return None


def _cache_user_key(email: str) -> str:
    return f"seguard:user:{email}"


def _cache_token_key(token: str) -> str:
    digest = sha256(token.encode("utf-8")).hexdigest()
    return f"seguard:jwt:{digest}"


def _cache_rate_limit_key(action: str, ip: str, email: str) -> str:
    return f"seguard:rl:{action}:{ip}:{email or 'anon'}"


def _init_redis_client():
    redis_url = os.getenv("REDIS_URL", "").strip()
    if redis is None or not redis_url:
        return None
    try:
        client = redis.from_url(redis_url, decode_responses=True)
        client.ping()
        log.info("[Cache] Redis connected")
        return client
    except Exception as e:
        log.warning(f"[Cache] Redis unavailable: {e}. Falling back to local TTL cache.")
        return None


redis_client = _init_redis_client()


def _cache_get(key: str):
    if redis_client is not None:
        try:
            value = redis_client.get(key)
            if value is not None:
                return _json_loads_safe(value)
        except Exception as e:
            log.warning(f"[Cache] Redis GET failed for {key}: {e}")
    if key.startswith("seguard:user:"):
        return LOCAL_USER_CACHE.get(key)
    return LOCAL_TOKEN_CACHE.get(key)


def _cache_set(key: str, value, ttl_seconds: int):
    if redis_client is not None:
        encoded = _json_dumps_safe(value)
        if encoded is not None:
            try:
                redis_client.setex(key, max(1, int(ttl_seconds)), encoded)
            except Exception as e:
                log.warning(f"[Cache] Redis SET failed for {key}: {e}")
    if key.startswith("seguard:user:"):
        LOCAL_USER_CACHE.set(key, value, ttl_seconds)
    else:
        LOCAL_TOKEN_CACHE.set(key, value, ttl_seconds)


def _cache_delete(key: str):
    if redis_client is not None:
        try:
            redis_client.delete(key)
        except Exception:
            pass
    if key.startswith("seguard:user:"):
        LOCAL_USER_CACHE.delete(key)
    else:
        LOCAL_TOKEN_CACHE.delete(key)


def _rate_limit_hit(action: str, ip: str, email: str, max_requests: int, window_seconds: int):
    key = _cache_rate_limit_key(action, ip, email)

    if redis_client is not None:
        try:
            new_value = redis_client.incr(key)
            if new_value == 1:
                redis_client.expire(key, window_seconds)
            return int(new_value) > max_requests
        except Exception as e:
            log.warning(f"[RateLimit] Redis failed: {e}. Falling back to local limiter.")

    now = time.time()
    with RATE_LIMIT_LOCK:
        expires_at, count = RATE_LIMIT_LOCAL.get(key, (now + window_seconds, 0))
        if expires_at <= now:
            expires_at = now + window_seconds
            count = 0
        count += 1
        RATE_LIMIT_LOCAL[key] = (expires_at, count)
        return count > max_requests


def _cleanup_rate_limit_local():
    now = time.time()
    with RATE_LIMIT_LOCK:
        expired = [k for k, (expires_at, _) in RATE_LIMIT_LOCAL.items() if expires_at <= now]
        for key in expired:
            RATE_LIMIT_LOCAL.pop(key, None)


def _cleanup_local_caches():
    user_removed = LOCAL_USER_CACHE.prune()
    token_removed = LOCAL_TOKEN_CACHE.prune()
    _cleanup_rate_limit_local()
    if user_removed or token_removed:
        log.info(f"[Cache] Cleanup removed user={user_removed}, token={token_removed}")


SCHEDULER = None
if BackgroundScheduler is not None:
    try:
        SCHEDULER = BackgroundScheduler(daemon=True)
        SCHEDULER.add_job(_cleanup_local_caches, "interval", minutes=5, id="local-cache-cleanup", replace_existing=True)
        SCHEDULER.start()
    except Exception as e:
        log.warning(f"[Scheduler] Failed to start APScheduler: {e}")
        SCHEDULER = None


def _hash_password(password: str) -> str:
    future = AUTH_POOL.submit(
        lambda: bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=BCRYPT_ROUNDS)).decode()
    )
    return future.result()


def _check_password(password: str, hashed: str) -> bool:
    future = AUTH_POOL.submit(lambda: bcrypt.checkpw(password.encode(), hashed.encode()))
    return bool(future.result())


async def _hash_password_async(password: str) -> str:
    return await asyncio.wait_for(asyncio.to_thread(_hash_password, password), timeout=AUTH_REQUEST_TIMEOUT_SECONDS)


async def _check_password_async(password: str, hashed: str) -> bool:
    return await asyncio.wait_for(asyncio.to_thread(_check_password, password, hashed), timeout=AUTH_REQUEST_TIMEOUT_SECONDS)


def _ensure_async_loop():
    global ASYNC_LOOP, ASYNC_LOOP_THREAD
    if ASYNC_LOOP is not None:
        return ASYNC_LOOP

    loop = asyncio.new_event_loop()

    def run_loop():
        asyncio.set_event_loop(loop)
        loop.run_forever()

    thread = Thread(target=run_loop, name="seguard-async-loop", daemon=True)
    thread.start()
    ASYNC_LOOP = loop
    ASYNC_LOOP_THREAD = thread
    return ASYNC_LOOP


def _shutdown_async_loop():
    global ASYNC_LOOP
    if ASYNC_LOOP is not None and ASYNC_LOOP.is_running():
        ASYNC_LOOP.call_soon_threadsafe(ASYNC_LOOP.stop)


atexit.register(_shutdown_async_loop)


def _run_async(coro):
    """Execute a coroutine from sync Flask handlers using a persistent loop."""
    loop = _ensure_async_loop()
    future = asyncio.run_coroutine_threadsafe(coro, loop)
    return future.result(timeout=max(1.0, AUTH_REQUEST_TIMEOUT_SECONDS + 1.0))


def _token_payload(email: str, role: str) -> dict:
    return {
        "sub": email,
        "role": role,
        "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=24)
    }


def _decode_jwt_cached(token: str):
    cache_key = _cache_token_key(token)
    cached_payload = _cache_get(cache_key)
    if isinstance(cached_payload, dict):
        return cached_payload

    payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
    exp = int(payload.get("exp", 0))
    ttl = max(1, min(JWT_CACHE_TTL_CAP_SECONDS, exp - int(time.time())))
    _cache_set(cache_key, payload, ttl)
    return payload


def _warm_mongo_pool():
    """Prime the pool so the first auth request avoids cold connection latency."""
    if not MONGO_ENABLED or users_col is None or mongo_client is None:
        return
    try:
        mongo_client.admin.command('ping')
        users_col.find_one({}, {"_id": 1})
        log.info("[MongoDB] Connection pool warm-up complete")
    except Exception as e:
        log.warning(f"[MongoDB] Connection pool warm-up failed: {e}")

# ─── MongoDB Connection ───────────────────────────────────────────────────
MONGO_URI = os.getenv("MONGO_URI", "mongodb+srv://Seguard:admin8124@seguard.yfe5rgq.mongodb.net/?appName=Seguard")
DB_NAME = os.getenv("MONGO_DB_NAME", os.getenv("DB_NAME", "seguard")).strip()
mongo_kwargs: Dict[str, Any] = {
    "serverSelectionTimeoutMS": 3000,
    "connectTimeoutMS": 3000,
    "socketTimeoutMS": 3000,
    "maxPoolSize": int(os.getenv("MONGO_MAX_POOL_SIZE", "80")),
    "minPoolSize": int(os.getenv("MONGO_MIN_POOL_SIZE", "10")),
    "waitQueueTimeoutMS": 2000,
    "retryWrites": True,
}

try:
    if certifi is not None:
        mongo_kwargs["tlsCAFile"] = certifi.where()
    mongo_client = MongoClient(MONGO_URI, **mongo_kwargs)
    mongo_client.admin.command('ping')
    db = mongo_client[DB_NAME]
    log.info(f"[MongoDB] Connected successfully - Database: {DB_NAME}")
    MONGO_ENABLED = True
except Exception as e:
    log.warning(f"[MongoDB] Connection failed: {e}. Using in-memory storage.")
    mongo_client = None
    db = None
    MONGO_ENABLED = False

# ─── Collection References (Section-wise) ─────────────────────────────────
# Users collection (all user profiles)
users_col = db["users"] if (MONGO_ENABLED and db is not None) else None

motor_client = None
async_db = None
async_users_col = None
ASYNC_MONGO_ENABLED = False

if AsyncIOMotorClient is not None:
    try:
        motor_client = AsyncIOMotorClient(MONGO_URI, **mongo_kwargs)
        async_db = motor_client[DB_NAME]
        async_users_col = async_db["users"]
        ASYNC_MONGO_ENABLED = True
    except Exception as e:
        log.warning(f"[MongoDB] Async client init failed: {e}. Using sync auth fallback.")
        ASYNC_MONGO_ENABLED = False

def _create_users_indexes():
    if not MONGO_ENABLED or users_col is None:
        return
    try:
        users_col.create_index("email", unique=True, background=True)
        users_col.create_index([("email", 1), ("role", 1)], background=True)
        users_col.create_index("created_at", background=True)
        log.info("[MongoDB] Users indexes ensured")
    except Exception as e:
        log.warning(f"[MongoDB] Failed to create users indexes: {e}")


def _start_background_index_build():
    global INDEX_BUILD_STARTED
    if not MONGO_BUILD_INDEXES or not MONGO_ENABLED or users_col is None:
        return

    with INDEX_BUILD_LOCK:
        if INDEX_BUILD_STARTED:
            return
        INDEX_BUILD_STARTED = True

    Thread(target=_create_users_indexes, name="seguard-index-builder", daemon=True).start()


@app.before_request
def _ensure_background_index_build():
    _start_background_index_build()

# Section-wise data collections
business_data_col = db["business_data"] if (MONGO_ENABLED and db is not None) else None
client_data_col = db["client_data"] if (MONGO_ENABLED and db is not None) else None
freelancer_data_col = db["freelancer_data"] if (MONGO_ENABLED and db is not None) else None

# Shared collections
products_col = db["products"] if (MONGO_ENABLED and db is not None) else None
orders_col = db["orders"] if (MONGO_ENABLED and db is not None) else None
payments_col = db["payments"] if (MONGO_ENABLED and db is not None) else None
messages_col = db["messages"] if (MONGO_ENABLED and db is not None) else None
messages_extended_col = db["messages_extended"] if (MONGO_ENABLED and db is not None) else None
conversations_col = db["conversations"] if (MONGO_ENABLED and db is not None) else None
presence_col = db["presence"] if (MONGO_ENABLED and db is not None) else None
notification_settings_col = db["notification_settings"] if (MONGO_ENABLED and db is not None) else None
reviews_col = db["reviews"] if (MONGO_ENABLED and db is not None) else None
reports_col = db["reports"] if (MONGO_ENABLED and db is not None) else None

# Detection logs collection
detection_logs_col = db["detection_logs"] if (MONGO_ENABLED and db is not None) else None

# ─── In-memory stores (fallback when MongoDB is unavailable) ──────────────
USERS     = {}   # email → {hash, role, created_at}
LOG_STORE = []   # detection audit log (last 500)
STATS     = defaultdict(lambda: defaultdict(int))  # stats[endpoint][verdict]
MESSAGES_EXTENDED_STORE = []
CONVERSATIONS_STORE = {}
PRESENCE_STORE = {}
NOTIFICATION_SETTINGS_STORE = {}
MESSAGE_RATE_LIMIT_STORE = defaultdict(list)
MESSAGE_RATE_LIMIT_LOCK = Lock()

MESSAGE_MAX_PER_MINUTE = int(os.getenv("MESSAGE_MAX_PER_MINUTE", "20"))
MESSAGE_EDIT_WINDOW_MINUTES = int(os.getenv("MESSAGE_EDIT_WINDOW_MINUTES", "15"))
MESSAGE_DEFAULT_PAGE_SIZE = int(os.getenv("MESSAGE_DEFAULT_PAGE_SIZE", "30"))
MESSAGE_MAX_PAGE_SIZE = int(os.getenv("MESSAGE_MAX_PAGE_SIZE", "100"))
MESSAGE_ENCRYPTION_KEY = os.getenv("MESSAGE_ENCRYPTION_KEY", SECRET_KEY)


# ─────────────────────────────────────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────────────────────────────────────
def _ok(data: dict, status: int = 200):
    data["status"] = "ok"
    data["timestamp"] = datetime.datetime.utcnow().isoformat() + "Z"
    return jsonify(data), status

def _err(msg: str, status: int = 400):
    return jsonify({"status": "error", "message": msg,
                    "timestamp": datetime.datetime.utcnow().isoformat()+"Z"}), status


def _safe_int(value, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _normalize_role(role_value, default_role: str = "client") -> str:
    role = str(role_value or "").strip().lower()
    if role in ALLOWED_APP_ROLES:
        return role
    return default_role


def _normalized_roles(user: dict):
    if not isinstance(user, dict):
        return ["client"]
    roles = user.get("roles")
    if isinstance(roles, list):
        normalized = []
        for value in roles:
            role = _normalize_role(value, default_role="")
            if role and role not in normalized:
                normalized.append(role)
        if normalized:
            return normalized
    legacy_role = _normalize_role(user.get("role"), default_role="client")
    return [legacy_role]


def _safe_mongo_uri_for_status(uri: str):
    """Return a redacted Mongo URI so credentials are never exposed via API."""
    if not uri or "://" not in uri:
        return None
    try:
        scheme, rest = uri.split("://", 1)
        at_index = rest.find("@")
        if at_index == -1:
            return f"{scheme}://{rest}"
        return f"{scheme}://***:***@{rest[at_index + 1:]}"
    except Exception:
        return "***"


def _iso_now() -> str:
    return datetime.datetime.utcnow().isoformat() + "Z"


def _dt_now() -> datetime.datetime:
    return datetime.datetime.utcnow()


def _parse_iso(value):
    if not value:
        return None
    if isinstance(value, datetime.datetime):
        return value
    try:
        normalized = str(value).replace("Z", "")
        return datetime.datetime.fromisoformat(normalized)
    except Exception:
        return None


def _sensitive_message(text: str) -> bool:
    if not isinstance(text, str):
        return False
    patterns = [
        r"\b\d{12,19}\b",  # possible card-like sequence
        r"\b\d{10}\b",  # phone-like sequence
        r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",  # email
    ]
    return any(re.search(p, text) for p in patterns)


def _cipher_text(value: str, key: str) -> str:
    raw = value.encode("utf-8")
    key_bytes = key.encode("utf-8") or b"seguard"
    mixed = bytes([raw[i] ^ key_bytes[i % len(key_bytes)] for i in range(len(raw))])
    return base64.b64encode(mixed).decode("utf-8")


def _decipher_text(value: str, key: str) -> str:
    enc = base64.b64decode(value.encode("utf-8"))
    key_bytes = key.encode("utf-8") or b"seguard"
    raw = bytes([enc[i] ^ key_bytes[i % len(key_bytes)] for i in range(len(enc))])
    return raw.decode("utf-8", errors="ignore")


def _encrypt_for_storage(text: str):
    if not isinstance(text, str):
        return text, False
    if not _sensitive_message(text):
        return text, False
    return f"enc:{_cipher_text(text, MESSAGE_ENCRYPTION_KEY)}", True


def _decrypt_from_storage(text: Any):
    if not isinstance(text, str):
        return text
    if not text.startswith("enc:"):
        return text
    try:
        return _decipher_text(text[4:], MESSAGE_ENCRYPTION_KEY)
    except Exception:
        return ""


def _serialize_doc(value: Any) -> Any:
    if isinstance(value, ObjectId):
        return str(value)
    if isinstance(value, datetime.datetime):
        return value.isoformat() + "Z"
    if isinstance(value, list):
        return [_serialize_doc(v) for v in value]
    if isinstance(value, dict):
        return {k: _serialize_doc(v) for k, v in value.items()}
    return value


def _auth_identity():
    payload = getattr(g, "jwt_payload", None) or {}
    email = str(payload.get("sub", "")).strip().lower()
    role = _normalize_role(payload.get("role", ""), default_role="client")
    user = _run_async(get_user_async(email)) if email else {}
    full_name = f"{str(user.get('firstName', '')).strip()} {str(user.get('lastName', '')).strip()}".strip() if isinstance(user, dict) else ""
    if not full_name:
        full_name = email.split("@")[0] if email else "User"
    return {
        "user_id": email,
        "email": email,
        "role": role,
        "name": full_name,
    }


def _participants_key(participants):
    normalized = sorted({str(p).strip().lower() for p in participants if str(p).strip()})
    return "::".join(normalized)


def _message_rate_limited(user_id: str) -> bool:
    now = time.time()
    with MESSAGE_RATE_LIMIT_LOCK:
        window = MESSAGE_RATE_LIMIT_STORE[user_id]
        cutoff = now - 60
        while window and window[0] < cutoff:
            window.pop(0)
        if len(window) >= MESSAGE_MAX_PER_MINUTE:
            return True
        window.append(now)
        return False


def _build_conversation_doc(participants, title="", created_by=""):
    now_iso = _iso_now()
    normalized = sorted({str(p).strip().lower() for p in participants if str(p).strip()})
    auto_title = title.strip() if isinstance(title, str) else ""
    if not auto_title:
        auto_title = "Conversation"
    return {
        "participants": normalized,
        "title": auto_title,
        "last_message_preview": "",
        "last_message_at": None,
        "is_group": len(normalized) > 2,
        "group_avatar_url": "",
        "notification_settings": {},
        "created_at": now_iso,
        "updated_at": now_iso,
        "archived_for_user_ids": [],
        "muted_for_user_ids": [],
        "pinned_for_user_ids": [],
        "created_by": created_by,
        "participants_key": _participants_key(normalized),
    }


def _find_or_create_conversation(participants, title="", created_by="") -> Tuple[Optional[str], Optional[Dict[str, Any]]]:
    normalized = sorted({str(p).strip().lower() for p in participants if str(p).strip()})
    if len(normalized) < 2:
        return None, None

    participants_key = _participants_key(normalized)
    if MONGO_ENABLED and conversations_col is not None:
        existing = conversations_col.find_one({"participants_key": participants_key})
        if existing:
            return str(existing.get("_id")), _serialize_doc(existing)
        doc = _build_conversation_doc(normalized, title=title, created_by=created_by)
        inserted = conversations_col.insert_one(doc)
        doc["_id"] = inserted.inserted_id
        return str(inserted.inserted_id), _serialize_doc(doc)

    for cid, convo in CONVERSATIONS_STORE.items():
        if convo.get("participants_key") == participants_key:
            return cid, _serialize_doc(convo)

    conv_id = str(uuid4())
    doc = _build_conversation_doc(normalized, title=title, created_by=created_by)
    doc["_id"] = conv_id
    CONVERSATIONS_STORE[conv_id] = doc
    return conv_id, _serialize_doc(doc)


def _get_conversation_by_id(conversation_id: str) -> Optional[Dict[str, Any]]:
    if not conversation_id:
        return None
    if MONGO_ENABLED and conversations_col is not None:
        try:
            oid = ObjectId(conversation_id)
            convo = conversations_col.find_one({"_id": oid})
            return cast(Optional[Dict[str, Any]], _serialize_doc(convo) if convo else None)
        except Exception:
            convo = conversations_col.find_one({"_id": conversation_id})
            return cast(Optional[Dict[str, Any]], _serialize_doc(convo) if convo else None)
    convo = CONVERSATIONS_STORE.get(conversation_id)
    return cast(Optional[Dict[str, Any]], _serialize_doc(convo) if convo else None)


def _update_conversation_after_message(conversation_id: str, message_text: str):
    preview = (message_text or "").strip()
    if len(preview) > 120:
        preview = preview[:117] + "..."
    now_iso = _iso_now()
    if MONGO_ENABLED and conversations_col is not None:
        try:
            oid = ObjectId(conversation_id)
            conversations_col.update_one(
                {"_id": oid},
                {"$set": {"last_message_preview": preview, "last_message_at": now_iso, "updated_at": now_iso}},
            )
            return
        except Exception:
            conversations_col.update_one(
                {"_id": conversation_id},
                {"$set": {"last_message_preview": preview, "last_message_at": now_iso, "updated_at": now_iso}},
            )
            return
    convo = CONVERSATIONS_STORE.get(conversation_id)
    if convo:
        convo["last_message_preview"] = preview
        convo["last_message_at"] = now_iso
        convo["updated_at"] = now_iso


@app.errorhandler(HTTPException)
def handle_http_error(error):
    return _err(error.description or "Request failed", error.code or 500)


@app.errorhandler(Exception)
def handle_unexpected_error(error):
    if isinstance(error, HTTPException):
        return _err(error.description or "Request failed", error.code or 500)
    log.exception(f"[Unhandled] {error}")
    return _err("Internal server error", 500)

def _log_detection(endpoint: str, result: dict, raw_input: dict):
    entry = {
        "endpoint"  : endpoint,
        "verdict"   : result.get("verdict", "UNKNOWN"),
        "risk"      : result.get("risk_level", "-"),
        "action"    : result.get("action", "-"),
        "input_keys": list(raw_input.keys()),
        "ts"        : time.time(),
        "timestamp" : datetime.datetime.utcnow()
    }
    
    # Store in MongoDB if available
    if MONGO_ENABLED and detection_logs_col is not None:
        try:
            detection_logs_col.insert_one(entry)
        except Exception as e:
            log.warning(f"[MongoDB] Failed to log detection: {e}")
    
    # Also keep in-memory for quick stats
    LOG_STORE.append(entry)
    if len(LOG_STORE) > 500:
        LOG_STORE.pop(0)
    STATS[endpoint][result.get("verdict","?")] += 1


# ─── MongoDB Helper Functions ─────────────────────────────────────────────
def save_user(email: str, user_data: dict):
    """Save or update user in MongoDB."""
    if MONGO_ENABLED and users_col is not None:
        try:
            users_col.update_one(
                {"email": email},
                {"$set": user_data},
                upsert=True
            )
            _cache_set(_cache_user_key(email), user_data, USER_CACHE_TTL_SECONDS)
        except Exception as e:
            log.warning(f"[MongoDB] Failed to save user: {e}")
    else:
        USERS[email] = user_data
        _cache_set(_cache_user_key(email), user_data, USER_CACHE_TTL_SECONDS)


def get_user(email: str) -> Optional[Dict[str, Any]]:
    """Get user from MongoDB or in-memory."""
    cache_key = _cache_user_key(email)
    cached_user = _cache_get(cache_key)
    if isinstance(cached_user, dict):
        return cached_user

    if MONGO_ENABLED and users_col is not None:
        try:
            user = users_col.find_one(
                {"email": email},
                {
                    "_id": 0,
                    "email": 1,
                    "hash": 1,
                    "role": 1,
                    "roles": 1,
                    "role_profiles": 1,
                    "firstName": 1,
                    "lastName": 1,
                    "created_at": 1,
                    "last_login_at": 1,
                    "login_count": 1,
                },
            )
            if user:
                _cache_set(cache_key, user, USER_CACHE_TTL_SECONDS)
                return user
        except Exception as e:
            log.warning(f"[MongoDB] Failed to get user: {e}")
    fallback_user = USERS.get(email)
    if isinstance(fallback_user, dict):
        _cache_set(cache_key, fallback_user, USER_CACHE_TTL_SECONDS)
    return fallback_user if isinstance(fallback_user, dict) else None


async def get_user_async(email: str) -> Optional[Dict[str, Any]]:
    cache_key = _cache_user_key(email)
    cached_user = _cache_get(cache_key)
    if isinstance(cached_user, dict):
        return cached_user

    async_users = async_users_col
    if ASYNC_MONGO_ENABLED and async_users is not None:
        try:
            user = await AUTH_CIRCUIT_BREAKER.call(
                "get_user_async",
                lambda: async_users.find_one(
                    {"email": email},
                    {
                        "_id": 0,
                        "email": 1,
                        "hash": 1,
                        "role": 1,
                        "roles": 1,
                        "role_profiles": 1,
                        "firstName": 1,
                        "lastName": 1,
                        "created_at": 1,
                        "last_login_at": 1,
                        "login_count": 1,
                    },
                ),
            )
            if user:
                _cache_set(cache_key, user, USER_CACHE_TTL_SECONDS)
                return user
        except Exception as e:
            log.warning(f"[MongoDB] Async get user failed: {e}")

    return await asyncio.to_thread(get_user, email)


async def save_user_async(email: str, user_data: dict):
    async_users = async_users_col
    if ASYNC_MONGO_ENABLED and async_users is not None:
        try:
            await AUTH_CIRCUIT_BREAKER.call(
                "save_user_async",
                lambda: async_users.update_one(
                    {"email": email},
                    {"$set": user_data},
                    upsert=True,
                ),
            )
            _cache_set(_cache_user_key(email), user_data, USER_CACHE_TTL_SECONDS)
            return
        except Exception as e:
            log.warning(f"[MongoDB] Async save user failed: {e}")

    await asyncio.to_thread(save_user, email, user_data)


def save_section_data(section: str, data: dict):
    """Save data to section-specific collection.
    Sections: business, client, freelancer
    """
    if not MONGO_ENABLED:
        return
    
    collection_map = {
        "business": business_data_col,
        "client": client_data_col,
        "freelancer": freelancer_data_col
    }
    
    collection = collection_map.get(section)
    if collection is not None:
        try:
            data["timestamp"] = datetime.datetime.utcnow()
            result = collection.insert_one(data)
            return str(result.inserted_id)
        except Exception as e:
            log.warning(f"[MongoDB] Failed to save {section} data: {e}")
    return None


def get_section_data(section: str, query: Optional[Dict[str, Any]] = None, limit: int = 100):
    """Get data from section-specific collection."""
    if not MONGO_ENABLED:
        return []
    
    collection_map = {
        "business": business_data_col,
        "client": client_data_col,
        "freelancer": freelancer_data_col
    }
    
    collection = collection_map.get(section)
    if collection is not None:
        try:
            cursor = collection.find(query or {}).limit(limit).sort("timestamp", -1)
            results = []
            for doc in cursor:
                doc["_id"] = str(doc["_id"])
                results.append(doc)
            return results
        except Exception as e:
            log.warning(f"[MongoDB] Failed to get {section} data: {e}")
    return []


def save_to_collection(collection_name: str, data: dict):
    """Save data to a specific collection."""
    if not MONGO_ENABLED or db is None:
        return None
    
    try:
        collection = db[collection_name]
        data["timestamp"] = datetime.datetime.utcnow()
        result = collection.insert_one(data)
        return str(result.inserted_id)
    except Exception as e:
        log.warning(f"[MongoDB] Failed to save to {collection_name}: {e}")
    return None


def get_from_collection(collection_name: str, query: Optional[Dict[str, Any]] = None, limit: int = 100):
    """Get data from a specific collection."""
    if not MONGO_ENABLED or db is None:
        return []
    
    try:
        collection = db[collection_name]
        cursor = collection.find(query or {}).limit(limit).sort("timestamp", -1)
        results = []
        for doc in cursor:
            doc["_id"] = str(doc["_id"])
            results.append(doc)
        return results
    except Exception as e:
        log.warning(f"[MongoDB] Failed to get from {collection_name}: {e}")
    return []

def _require_json(f):
    if inspect.iscoroutinefunction(f):
        @wraps(f)
        async def async_wrapper(*a, **kw):
            if not request.is_json:
                return _err("Content-Type must be application/json")
            return await f(*a, **kw)
        return async_wrapper

    @wraps(f)
    def sync_wrapper(*a, **kw):
        if not request.is_json:
            return _err("Content-Type must be application/json")
        return f(*a, **kw)
    return sync_wrapper


def _jwt_required(f):
    if inspect.iscoroutinefunction(f):
        @wraps(f)
        async def async_wrapper(*a, **kw):
            token = request.headers.get("Authorization", "").replace("Bearer ", "")
            if not token:
                return _err("Missing token", 401)
            try:
                g.jwt_payload = _decode_jwt_cached(token)
            except jwt.ExpiredSignatureError:
                return _err("Token expired", 401)
            except jwt.InvalidTokenError:
                return _err("Invalid token", 401)
            except Exception as e:
                log.warning(f"[Auth] Token decode failed: {e}")
                return _err("Invalid token", 401)
            return await f(*a, **kw)
        return async_wrapper

    @wraps(f)
    def sync_wrapper(*a, **kw):
        token = request.headers.get("Authorization", "").replace("Bearer ", "")
        if not token:
            return _err("Missing token", 401)
        try:
            g.jwt_payload = _decode_jwt_cached(token)
        except jwt.ExpiredSignatureError:
            return _err("Token expired", 401)
        except jwt.InvalidTokenError:
            return _err("Invalid token", 401)
        except Exception as e:
            log.warning(f"[Auth] Token decode failed: {e}")
            return _err("Invalid token", 401)
        return f(*a, **kw)
    return sync_wrapper


def _auth_rate_limit(action: str, max_requests: int = AUTH_RATE_LIMIT_PER_MINUTE, window_seconds: int = 60):
    def decorator(f):
        if inspect.iscoroutinefunction(f):
            @wraps(f)
            async def async_wrapper(*a, **kw):
                ip = (request.headers.get("X-Forwarded-For", request.remote_addr or "unknown").split(",")[0].strip())
                data = request.get_json(silent=True) or {}
                email = (data.get("email", "") if isinstance(data, dict) else "").strip().lower()
                if _rate_limit_hit(action, ip, email, max_requests, window_seconds):
                    return _err("Too many authentication attempts. Please try again later.", 429)
                return await f(*a, **kw)
            return async_wrapper

        @wraps(f)
        def sync_wrapper(*a, **kw):
            ip = (request.headers.get("X-Forwarded-For", request.remote_addr or "unknown").split(",")[0].strip())
            data = request.get_json(silent=True) or {}
            email = (data.get("email", "") if isinstance(data, dict) else "").strip().lower()
            if _rate_limit_hit(action, ip, email, max_requests, window_seconds):
                return _err("Too many authentication attempts. Please try again later.", 429)
            return f(*a, **kw)
        return sync_wrapper
    return decorator


def _measure_auth_latency(name: str):
    def decorator(f):
        if inspect.iscoroutinefunction(f):
            @wraps(f)
            async def async_wrapper(*a, **kw):
                started = time.perf_counter()
                try:
                    return await f(*a, **kw)
                finally:
                    elapsed_ms = round((time.perf_counter() - started) * 1000, 2)
                    log.info(f"[Perf] auth.{name}={elapsed_ms}ms")
            return async_wrapper

        @wraps(f)
        def sync_wrapper(*a, **kw):
            started = time.perf_counter()
            try:
                return f(*a, **kw)
            finally:
                elapsed_ms = round((time.perf_counter() - started) * 1000, 2)
                log.info(f"[Perf] auth.{name}={elapsed_ms}ms")
        return sync_wrapper
    return decorator


# ─────────────────────────────────────────────────────────────────────────────
# AUTH ENDPOINTS
# ─────────────────────────────────────────────────────────────────────────────
@app.route("/api/auth/register", methods=["POST"])
@_require_json
@_auth_rate_limit("register", max_requests=8, window_seconds=60)
@_measure_auth_latency("register")
def register():
    data  = request.get_json()
    email = data.get("email", "").strip().lower()
    pwd   = data.get("password", "")
    # New accounts always start as client; additional roles are enabled via /api/auth/roles/add.
    role  = "client"
    fname = data.get("firstName", "")
    lname = data.get("lastName", "")

    if not email or "@" not in email:
        return _err("Invalid email address")
    if len(pwd) < 8:
        return _err("Password must be at least 8 characters")
    
    # Check if user exists in MongoDB or in-memory
    existing_user = _run_async(get_user_async(email))
    if existing_user:
        return _err("Email already registered", 409)

    hashed = _run_async(_hash_password_async(pwd))
    now_iso = datetime.datetime.utcnow().isoformat()
    user_data = {
        "hash"      : hashed,
        "role"      : role,
        "roles"     : [role],
        "role_profiles": {
            role: {
                "status": "active",
                "registered_at": now_iso,
                "details": {
                    "firstName": fname,
                    "lastName": lname,
                },
            }
        },
        "firstName" : fname,
        "lastName"  : lname,
        "created_at": now_iso,
        "email"     : email
    }
    
    # Save to MongoDB, with in-memory fallback only if MongoDB is unavailable
    _run_async(save_user_async(email, user_data))

    token = jwt.encode(_token_payload(email, role), SECRET_KEY, algorithm="HS256")

    log.info(f"Registered: {email} ({role})")
    return _ok({
        "message"       : "Account created successfully",
        "token"         : token,
        "role"          : role,
        "roles"         : [role],
        "initial_trust" : {
            "verdict": "REVIEW",
            "risk_level": "LOW",
            "recommendation": "ALLOW"
        }
    }, 201)


@app.route("/api/auth/login", methods=["POST"])
@_require_json
@_auth_rate_limit("login", max_requests=AUTH_RATE_LIMIT_PER_MINUTE, window_seconds=60)
@_measure_auth_latency("login")
def login():
    data  = request.get_json(silent=True) or {}
    if not isinstance(data, dict):
        return _err("Invalid JSON payload", 400)
    email = data.get("email", "").strip().lower()
    pwd   = data.get("password", "")
    requested_role = _normalize_role(data.get("role", ""), default_role="")

    user = _run_async(get_user_async(email))
    if not user:
        return _err("Invalid email or password", 401)

    stored_hash = user.get("hash") if isinstance(user, dict) else None
    if not isinstance(stored_hash, str) or not stored_hash:
        log.warning(f"[Auth] User record missing hash for {email}")
        return _err("Invalid email or password", 401)

    try:
        is_valid_password = _run_async(_check_password_async(pwd, stored_hash))
    except Exception as e:
        log.warning(f"[Auth] Password hash validation failed for {email}: {e}")
        return _err("Invalid email or password", 401)

    if not is_valid_password:
        return _err("Invalid email or password", 401)

    roles = _normalized_roles(user)
    if requested_role and requested_role not in roles:
        return _err("Role not enabled for this account. Please complete role registration first.", 403)
    active_role = requested_role or roles[0]

    updated_user = {
        **user,
        "role": active_role,
        "roles": roles,
        "last_login_at": datetime.datetime.utcnow().isoformat(),
        "login_count": _safe_int(user.get("login_count", 0), 0) + 1,
    }
    _run_async(save_user_async(email, updated_user))

    token = jwt.encode(
        _token_payload(email, active_role),
        SECRET_KEY,
        algorithm="HS256"
    )

    log.info(f"Login: {email}")
    return _ok({
        "message": "Login successful",
        "token"  : token,
        "role"   : active_role,
        "roles"  : roles,
        "name"   : f"{updated_user.get('firstName', '')} {updated_user.get('lastName', '')}".strip() or email
    })


@app.route("/api/auth/logout", methods=["POST"])
@_jwt_required
@_measure_auth_latency("logout")
def logout():
    """Logout endpoint. Invalidates session on client."""
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    try:
        payload = getattr(g, "jwt_payload", None) or _decode_jwt_cached(token)
        _cache_delete(_cache_token_key(token))
        email = payload.get("sub")
        log.info(f"Logout: {email}")
        return _ok({"message": "Logout successful"})
    except Exception as e:
        log.warning(f"[Auth] Logout failed: {e}")
        return _err("Logout failed", 400)


@app.route("/api/auth/profile", methods=["GET"])
@_jwt_required
@_measure_auth_latency("profile")
def get_profile():
    """Get current user profile data."""
    try:
        payload = getattr(g, "jwt_payload", None)
        if payload is None:
            token = request.headers.get("Authorization", "").replace("Bearer ", "")
            payload = _decode_jwt_cached(token)
        email = payload.get("sub")
        role = payload.get("role")
        
        user = _run_async(get_user_async(str(email)))
        if not user:
            return _err("User not found", 404)

        roles = _normalized_roles(user)
        role_profiles = user.get("role_profiles") if isinstance(user.get("role_profiles"), dict) else {}
        
        # Fetch role-specific data
        section_data = {}
        if role in ["business", "client", "freelancer"]:
            section_data = get_section_data(role, {"user_email": email}, 50)
        
        # Return user profile with role data
        return _ok({
            "user": {
                "email": email,
                "firstName": user.get("firstName", ""),
                "lastName": user.get("lastName", ""),
                "role": role,
                "roles": roles,
                "role_profiles": role_profiles,
                "created_at": user.get("created_at"),
                "last_login_at": user.get("last_login_at"),
                "login_count": user.get("login_count", 0)
            },
            "role_data": section_data
        })
    except jwt.ExpiredSignatureError:
        return _err("Token expired", 401)
    except Exception as e:
        log.warning(f"[Auth] Profile fetch failed: {e}")
        return _err("Profile fetch failed", 400)


@app.route("/api/auth/refresh", methods=["POST"])
@_jwt_required
@_measure_auth_latency("refresh")
def refresh_token():
    """Refresh JWT token (extends validity by 24 hours)."""
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    try:
        payload = getattr(g, "jwt_payload", None) or _decode_jwt_cached(token)
        _cache_delete(_cache_token_key(token))
        email = payload.get("sub")
        role = payload.get("role")
        
        new_token = jwt.encode(_token_payload(str(email), str(role)), SECRET_KEY, algorithm="HS256")
        
        log.info(f"Token refreshed: {email}")
        return _ok({
            "message": "Token refreshed",
            "token": new_token
        })
    except Exception as e:
        log.warning(f"[Auth] Token refresh failed: {e}")
        return _err("Token refresh failed", 400)


@app.route("/api/auth/roles/add", methods=["POST"])
@_require_json
@_jwt_required
@_auth_rate_limit("add-role", max_requests=6, window_seconds=60)
@_measure_auth_latency("add-role")
def add_role():
    """Enable a new role for an existing account after role-specific registration."""
    payload = getattr(g, "jwt_payload", None) or {}
    email = str(payload.get("sub", "")).strip().lower()
    if not email:
        return _err("Invalid user token", 401)

    data = request.get_json(silent=True) or {}
    if not isinstance(data, dict):
        return _err("Invalid JSON payload", 400)

    new_role = _normalize_role(data.get("role", ""), default_role="")
    if new_role not in ALLOWED_APP_ROLES:
        return _err("Invalid role. Use one of: business, client, freelancer", 400)

    role_details = data.get("profile")
    if role_details is None or not isinstance(role_details, dict):
        role_details = {}

    user = _run_async(get_user_async(email))
    if not user:
        return _err("User not found", 404)

    roles = _normalized_roles(user)
    if new_role in roles:
        return _ok({
            "message": f"Role '{new_role}' is already enabled",
            "role": new_role,
            "roles": roles,
        })

    updated_roles = [*roles, new_role]
    role_profiles = cast(Dict[str, Any], user.get("role_profiles") if isinstance(user.get("role_profiles"), dict) else {})
    role_profiles[new_role] = {
        "status": "active",
        "registered_at": datetime.datetime.utcnow().isoformat(),
        "details": role_details,
    }

    updated_user = {
        **user,
        "roles": updated_roles,
        "role_profiles": role_profiles,
    }
    _run_async(save_user_async(email, updated_user))

    return _ok({
        "message": f"Role '{new_role}' enabled successfully",
        "role": new_role,
        "roles": updated_roles,
        "role_profiles": role_profiles,
    }, 201)


# ─────────────────────────────────────────────────────────────────────────────
# DETECTION ENDPOINTS
# ─────────────────────────────────────────────────────────────────────────────
@app.route("/api/detect/profile", methods=["POST"])
@_require_json
def detect_profile():
    """
    Detect whether a user profile is fake.

    Body (all optional):
    {
      "account_age_days"    : 3,
      "posts"               : 0,
      "completeness"        : 0.1,
      "email_domain_score"  : 0.3,
      "phone_verified"      : 0,
      "photo_uploaded"      : 0,
      "reviews_count"       : 0,
      "avg_rating"          : 5.0,
      "login_frequency"     : 0.05,
      "ip_country_mismatch" : 1
    }
    """
    data   = request.get_json()
    result = _get_models()["profile"].predict(data)
    _log_detection("profile", result, data)
    return _ok({"detection": result, "model": "RandomForest", "version": "1.0"})


@app.route("/api/detect/message", methods=["POST"])
@_require_json
def detect_message():
    """
    Detect abusive / threatening / pressure messages.

    Body:
    { "text": "pay me right now or else" }
    """
    data = request.get_json()
    text = data.get("text", "").strip()
    if not text:
        return _err("Field 'text' is required")
    result = _get_models()["message"].predict(text)
    _log_detection("message", result, data)
    return _ok({"detection": result, "model": "TF-IDF + LogisticRegression", "version": "1.0"})


@app.route("/api/detect/review", methods=["POST"])
@_require_json
def detect_review():
    """
    Detect fake reviews / testimonials.

    Body:
    {
      "text"  : "absolutely amazing best product ever!!",
      "rating": 5
    }
    """
    data   = request.get_json()
    text   = data.get("text", "").strip()
    rating = int(data.get("rating", 5))
    if not text:
        return _err("Field 'text' is required")
    result = _get_models()["review"].predict(text, rating)
    _log_detection("review", result, data)
    return _ok({"detection": result, "model": "TF-IDF + LinearSVC", "version": "1.0"})


@app.route("/api/detect/payment", methods=["POST"])
@_require_json
def detect_payment():
    """
    Detect suspicious payment transactions.

    Body:
    {
      "amount"                    : 150000,
      "hour_of_day"               : 2,
      "retries"                   : 5,
      "new_device"                : 1,
      "vpn_flag"                  : 1,
      "amount_vs_history_ratio"   : 8.0,
      "time_since_last_txn_min"   : 1
    }
    """
    data   = request.get_json()
    result = _get_models()["payment"].predict(data)
    _log_detection("payment", result, data)
    return _ok({"detection": result, "model": "IsolationForest", "version": "1.0"})


@app.route("/api/detect/product", methods=["POST"])
@_require_json
def detect_product():
    """
    Detect fake product listings.

    Body:
    {
      "price_vs_category_avg_ratio" : 0.05,
      "description_length"          : 5,
      "image_count"                 : 0,
      "seller_age_days"             : 2,
      "seller_rating"               : 5.0,
      "seller_total_sales"          : 0,
      "discount_pct"                : 95,
      "has_contact_info_in_desc"    : 1
    }
    """
    data   = request.get_json()
    result = _get_models()["product"].predict(data)
    _log_detection("product", result, data)
    return _ok({"detection": result, "model": "RandomForest", "version": "1.0"})


@app.route("/api/detect/batch", methods=["POST"])
@_require_json
def detect_batch():
    """
    Run multiple detectors in one call.

    Body:
    {
      "profile" : { ... },
      "message" : { "text": "..." },
      "review"  : { "text": "...", "rating": 5 },
      "payment" : { ... },
      "product" : { ... }
    }
    Only keys present in the body are processed.
    """
    data    = request.get_json()
    models  = _get_models()
    results = {}

    if "profile" in data:
        r = models["profile"].predict(data["profile"])
        results["profile"] = r
        _log_detection("profile", r, data["profile"])

    if "message" in data:
        txt = data["message"].get("text", "")
        r = models["message"].predict(txt)
        results["message"] = r
        _log_detection("message", r, data["message"])

    if "review" in data:
        txt    = data["review"].get("text", "")
        rating = int(data["review"].get("rating", 5))
        r = models["review"].predict(txt, rating)
        results["review"] = r
        _log_detection("review", r, data["review"])

    if "payment" in data:
        r = models["payment"].predict(data["payment"])
        results["payment"] = r
        _log_detection("payment", r, data["payment"])

    if "product" in data:
        r = models["product"].predict(data["product"])
        results["product"] = r
        _log_detection("product", r, data["product"])

    # Overall risk summary
    risk_levels = [v.get("risk_level", "LOW") for v in results.values()]
    overall = "HIGH" if "HIGH" in risk_levels else "MEDIUM" if "MEDIUM" in risk_levels else "LOW"

    return _ok({"results": results, "overall_risk": overall})


# ─────────────────────────────────────────────────────────────────────────────
# SECTION-WISE DATA STORAGE ENDPOINTS
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/api/data/<section>", methods=["POST"])
@_require_json
def save_section_data_endpoint(section):
    """
    Save data to section-specific collection.
    Sections: business, client, freelancer
    
    Body: Any JSON data to be stored
    """
    if section not in ["business", "client", "freelancer"]:
        return _err("Invalid section. Use: business, client, or freelancer", 400)
    
    data = request.get_json()
    data["section"] = section
    
    # Add user info if available in token
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    if token:
        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
            data["user_email"] = payload.get("sub")
            data["user_role"] = payload.get("role")
        except:
            pass
    
    inserted_id = save_section_data(section, data)
    
    if inserted_id:
        return _ok({
            "message": f"Data saved to {section} collection",
            "id": inserted_id
        }, 201)
    else:
        # Fallback: store in memory if MongoDB is unavailable
        if section not in ["business", "client", "freelancer"]:
            return _err("Invalid section", 400)
        return _ok({
            "message": f"Data received for {section} (MongoDB unavailable)",
            "data": data
        }, 201)


@app.route("/api/data/<section>", methods=["GET"])
def get_section_data_endpoint(section):
    """
    Get data from section-specific collection.
    Sections: business, client, freelancer
    
    Query params: limit (default 100)
    """
    if section not in ["business", "client", "freelancer"]:
        return _err("Invalid section. Use: business, client, or freelancer", 400)
    
    limit = request.args.get("limit", 100, type=int)
    
    # Build query based on user role if token provided
    query = {}
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    if token:
        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
            user_role = payload.get("role")
            user_email = payload.get("sub")
            # Users can only see their own data unless they're admin
            if user_role != "admin":
                query["user_email"] = user_email
        except:
            pass
    
    results = get_section_data(section, query, limit)
    
    return _ok({
        "section": section,
        "count": len(results),
        "data": results
    })


@app.route("/api/collection/<collection_name>", methods=["POST"])
@_require_json
def save_collection_data(collection_name):
    """
    Save data to a specific collection.
    Collections: products, orders, payments, messages, reviews, reports
    
    Body: Any JSON data to be stored
    """
    valid_collections = [
        "products",
        "orders",
        "payments",
        "messages",
        "reviews",
        "reports",
        "inquiries",
        "checkout_sessions",
        "marketplace_invoices",
        "business_notifications",
    ]
    if collection_name not in valid_collections:
        return _err(f"Invalid collection. Use: {', '.join(valid_collections)}", 400)
    
    data = request.get_json()
    
    # Add user info if available
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    if token:
        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
            data["user_email"] = payload.get("sub")
            data["user_role"] = payload.get("role")
        except:
            pass
    
    inserted_id = save_to_collection(collection_name, data)
    
    if inserted_id:
        return _ok({
            "message": f"Data saved to {collection_name}",
            "id": inserted_id
        }, 201)
    else:
        return _ok({
            "message": f"Data received for {collection_name} (MongoDB unavailable)",
            "data": data
        }, 201)


@app.route("/api/collection/<collection_name>", methods=["GET"])
def get_collection_data(collection_name):
    """
    Get data from a specific collection.
    Collections: products, orders, payments, messages, reviews, reports
    
    Query params: limit (default 100)
    """
    valid_collections = [
        "products",
        "orders",
        "payments",
        "messages",
        "reviews",
        "reports",
        "inquiries",
        "checkout_sessions",
        "marketplace_invoices",
        "business_notifications",
    ]
    if collection_name not in valid_collections:
        return _err(f"Invalid collection. Use: {', '.join(valid_collections)}", 400)
    
    limit = request.args.get("limit", 100, type=int)
    
    # Build query based on user
    query = {}
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    if token:
        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
            user_role = payload.get("role")
            user_email = payload.get("sub")
            if user_role != "admin":
                query["user_email"] = user_email
        except:
            pass
    
    results = get_from_collection(collection_name, query, limit)
    
    return _ok({
        "collection": collection_name,
        "count": len(results),
        "data": results
    })


def _get_message_doc(message_id: str):
    if not message_id:
        return None, None
    if MONGO_ENABLED and messages_extended_col is not None:
        try:
            oid = ObjectId(message_id)
            doc = messages_extended_col.find_one({"_id": oid})
            if doc:
                return oid, _serialize_doc(doc)
            return None, None
        except Exception:
            doc = messages_extended_col.find_one({"_id": message_id})
            if doc:
                return message_id, _serialize_doc(doc)
            return None, None
    for idx, item in enumerate(MESSAGES_EXTENDED_STORE):
        if str(item.get("_id")) == str(message_id):
            return idx, _serialize_doc(item)
    return None, None


def _save_message_doc(ref, updates: dict):
    if MONGO_ENABLED and messages_extended_col is not None:
        messages_extended_col.update_one({"_id": ref}, {"$set": updates})
        return
    if isinstance(ref, int) and 0 <= ref < len(MESSAGES_EXTENDED_STORE):
        MESSAGES_EXTENDED_STORE[ref].update(updates)


@app.route("/api/messages/send", methods=["POST"])
@_require_json
@_jwt_required
def send_message():
    identity = _auth_identity()
    sender_id = identity.get("user_id")
    if not sender_id:
        return _err("Unauthorized sender", 401)

    if _message_rate_limited(sender_id):
        return _err(f"Message rate limit exceeded ({MESSAGE_MAX_PER_MINUTE}/min)", 429)

    data = request.get_json(silent=True) or {}
    if not isinstance(data, dict):
        return _err("Invalid JSON payload", 400)

    receiver_id = str(data.get("receiver_id", "")).strip().lower()
    receiver_name = str(data.get("receiver_name", "")).strip() or "User"
    receiver_role = _normalize_role(data.get("receiver_role", "client"), default_role="client")
    message_text_raw = str(data.get("message_text", "")).strip()
    message_type = str(data.get("message_type", "text")).strip().lower() or "text"
    attachments = data.get("attachments") if isinstance(data.get("attachments"), list) else []
    thread_parent_id = str(data.get("thread_parent_id", "")).strip() or None
    reply_to_message_id = str(data.get("reply_to_message_id", "")).strip() or None

    if not message_text_raw and not attachments:
        return _err("Message text or attachment is required", 400)
    if len(message_text_raw) > 5000:
        return _err("Message exceeds max length (5000 chars)", 400)

    conversation_id = str(data.get("conversation_id", "")).strip()
    if conversation_id:
        conversation = _get_conversation_by_id(conversation_id)
        if not conversation:
            return _err("Conversation not found", 404)
        if sender_id not in conversation.get("participants", []):
            return _err("You are not a participant of this conversation", 403)
    else:
        if not receiver_id:
            return _err("receiver_id is required when conversation_id is missing", 400)
        conversation_id, conversation = _find_or_create_conversation(
            [sender_id, receiver_id],
            title=str(data.get("conversation_title", "")).strip(),
            created_by=sender_id,
        )
        if not conversation_id:
            return _err("Unable to create conversation", 500)

    encrypted_text, is_encrypted = _encrypt_for_storage(message_text_raw)
    created_at = _iso_now()
    message_doc = {
        "conversation_id": conversation_id,
        "sender_id": sender_id,
        "sender_name": identity.get("name") or "User",
        "sender_role": identity.get("role") or "client",
        "receiver_id": receiver_id,
        "receiver_name": receiver_name,
        "receiver_role": receiver_role,
        "message_text": encrypted_text,
        "message_type": message_type,
        "attachments": attachments,
        "created_at": created_at,
        "edited_at": None,
        "deleted_at": None,
        "delivered_at": None,
        "read_at": None,
        "reactions": [],
        "thread_parent_id": thread_parent_id,
        "reply_to_message_id": reply_to_message_id,
        "is_pinned": False,
        "is_archived": False,
        "is_deleted": False,
        "is_encrypted": is_encrypted,
        "edit_history": [],
    }

    if MONGO_ENABLED and messages_extended_col is not None:
        inserted = messages_extended_col.insert_one(message_doc)
        message_id = str(inserted.inserted_id)
    else:
        message_id = str(uuid4())
        message_doc["_id"] = message_id
        MESSAGES_EXTENDED_STORE.append(message_doc)

    _update_conversation_after_message(conversation_id, message_text_raw)
    stored_message = cast(Dict[str, Any], _serialize_doc({**message_doc, "_id": message_id}))
    stored_message["message_text"] = _decrypt_from_storage(stored_message.get("message_text"))

    return _ok({
        "message": "Message sent",
        "conversation_id": conversation_id,
        "message_data": stored_message,
    }, 201)


@app.route("/api/messages/conversation/<conversation_id>", methods=["GET"])
@_jwt_required
def get_conversation_messages(conversation_id):
    identity = _auth_identity()
    user_id = identity.get("user_id")
    if not user_id:
        return _err("Unauthorized user", 401)

    conversation = _get_conversation_by_id(conversation_id)
    if not conversation:
        return _err("Conversation not found", 404)
    if user_id not in conversation.get("participants", []):
        return _err("Forbidden", 403)

    limit = request.args.get("limit", MESSAGE_DEFAULT_PAGE_SIZE, type=int) or MESSAGE_DEFAULT_PAGE_SIZE
    limit = max(1, min(limit, MESSAGE_MAX_PAGE_SIZE))
    before = request.args.get("before", "").strip()
    before_dt = _parse_iso(before)

    if MONGO_ENABLED and messages_extended_col is not None:
        query = {"conversation_id": conversation_id}
        if before_dt is not None:
            query["created_at"] = {"$lt": before_dt.isoformat() + "Z"}
        cursor = messages_extended_col.find(query).sort("created_at", -1).limit(limit)
        items = [_serialize_doc(doc) for doc in cursor]
    else:
        items = [
            cast(Dict[str, Any], _serialize_doc(msg))
            for msg in MESSAGES_EXTENDED_STORE
            if str(msg.get("conversation_id")) == str(conversation_id)
        ]
        if before_dt is not None:
            items = [m for m in items if isinstance(m, dict) and (_parse_iso(m.get("created_at")) or _dt_now()) < before_dt]
        items = sorted([m for m in items if isinstance(m, dict)], key=lambda x: x.get("created_at") or "", reverse=True)[:limit]

    items = list(reversed(items))
    for item in items:
        if item.get("is_deleted"):
            item["message_text"] = "This message was deleted"
        else:
            item["message_text"] = _decrypt_from_storage(item.get("message_text"))

    next_before = items[0].get("created_at") if items else None
    return _ok({
        "conversation_id": conversation_id,
        "count": len(items),
        "messages": items,
        "next_before": next_before,
    })


@app.route("/api/messages/<message_id>/edit", methods=["PUT"])
@_require_json
@_jwt_required
def edit_message(message_id):
    identity = _auth_identity()
    user_id = identity.get("user_id")
    data = request.get_json(silent=True) or {}
    new_text = str(data.get("message_text", "")).strip()
    if not new_text:
        return _err("message_text is required", 400)
    if len(new_text) > 5000:
        return _err("Message exceeds max length (5000 chars)", 400)

    ref, existing = _get_message_doc(message_id)
    if not existing:
        return _err("Message not found", 404)
    if str(existing.get("sender_id")) != str(user_id):
        return _err("You can only edit your own message", 403)
    if existing.get("is_deleted"):
        return _err("Deleted message cannot be edited", 400)

    created_dt = _parse_iso(existing.get("created_at")) or _dt_now()
    if (_dt_now() - created_dt).total_seconds() > MESSAGE_EDIT_WINDOW_MINUTES * 60:
        return _err(f"Edit window exceeded ({MESSAGE_EDIT_WINDOW_MINUTES} minutes)", 400)

    encrypted_text, is_encrypted = _encrypt_for_storage(new_text)
    edit_entry = {
        "edited_at": _iso_now(),
        "previous_text": existing.get("message_text"),
    }
    history = existing.get("edit_history") if isinstance(existing.get("edit_history"), list) else []
    history.append(edit_entry)
    updates = {
        "message_text": encrypted_text,
        "edited_at": _iso_now(),
        "is_encrypted": is_encrypted,
        "edit_history": history,
    }
    _save_message_doc(ref, updates)
    return _ok({"message": "Message edited", "message_id": str(message_id)})


@app.route("/api/messages/<message_id>", methods=["DELETE"])
@_jwt_required
def delete_message(message_id):
    identity = _auth_identity()
    user_id = identity.get("user_id")
    ref, existing = _get_message_doc(message_id)
    if not existing:
        return _err("Message not found", 404)
    if str(existing.get("sender_id")) != str(user_id):
        return _err("You can only delete your own message", 403)

    updates = {
        "is_deleted": True,
        "deleted_at": _iso_now(),
        "message_text": "This message was deleted",
    }
    _save_message_doc(ref, updates)
    return _ok({"message": "Message deleted", "message_id": str(message_id)})


@app.route("/api/messages/<message_id>/react", methods=["POST"])
@_require_json
@_jwt_required
def react_message(message_id):
    identity = _auth_identity()
    user_id = identity.get("user_id")
    data = request.get_json(silent=True) or {}
    emoji = str(data.get("emoji", "")).strip()
    if not emoji:
        return _err("emoji is required", 400)

    ref, existing = _get_message_doc(message_id)
    if not existing:
        return _err("Message not found", 404)

    reactions = existing.get("reactions") if isinstance(existing.get("reactions"), list) else []
    replaced = False
    for reaction in reactions:
        if str(reaction.get("user_id")) == str(user_id):
            reaction["emoji"] = emoji
            reaction["updated_at"] = _iso_now()
            replaced = True
            break
    if not replaced:
        reactions.append({"user_id": user_id, "emoji": emoji, "updated_at": _iso_now()})

    _save_message_doc(ref, {"reactions": reactions})
    return _ok({"message": "Reaction saved", "reactions": reactions})


@app.route("/api/messages/<message_id>/read", methods=["POST"])
@_jwt_required
def read_message(message_id):
    identity = _auth_identity()
    user_id = identity.get("user_id")
    ref, existing = _get_message_doc(message_id)
    if not existing:
        return _err("Message not found", 404)
    if str(existing.get("receiver_id")) != str(user_id):
        return _err("Only receiver can mark message as read", 403)

    now_iso = _iso_now()
    _save_message_doc(ref, {"read_at": now_iso, "delivered_at": now_iso})
    return _ok({"message": "Message marked as read", "read_at": now_iso})


@app.route("/api/messages/search", methods=["GET"])
@_jwt_required
def search_messages():
    identity = _auth_identity()
    user_id = identity.get("user_id")
    query = str(request.args.get("q", "")).strip().lower()
    conversation_id = str(request.args.get("conversation_id", "")).strip()
    limit = request.args.get("limit", 50, type=int) or 50
    limit = max(1, min(limit, MESSAGE_MAX_PAGE_SIZE))

    if not query:
        return _err("Search query 'q' is required", 400)

    if MONGO_ENABLED and messages_extended_col is not None:
        base_query = {
            "$or": [
                {"sender_id": user_id},
                {"receiver_id": user_id},
            ],
            "is_deleted": {"$ne": True},
        }
        if conversation_id:
            base_query["conversation_id"] = conversation_id
        docs = list(messages_extended_col.find(base_query).sort("created_at", -1).limit(300))
        candidates = [_serialize_doc(doc) for doc in docs]
    else:
        candidates = [
            _serialize_doc(msg)
            for msg in MESSAGES_EXTENDED_STORE
            if str(msg.get("sender_id")) == str(user_id) or str(msg.get("receiver_id")) == str(user_id)
        ]
        if conversation_id:
            candidates = [m for m in candidates if str(m.get("conversation_id")) == str(conversation_id)]

    results = []
    for msg in candidates:
        if msg.get("is_deleted"):
            continue
        plain_text = _decrypt_from_storage(msg.get("message_text") or "")
        if query in plain_text.lower():
            msg["message_text"] = plain_text
            results.append(msg)
        if len(results) >= limit:
            break

    return _ok({"query": query, "count": len(results), "messages": results})


@app.route("/api/conversations", methods=["GET"])
@_jwt_required
def list_conversations():
    identity = _auth_identity()
    user_id = identity.get("user_id")
    include_archived = request.args.get("include_archived", "false").lower() == "true"

    if MONGO_ENABLED and conversations_col is not None:
        query: Dict[str, Any] = {"participants": user_id}
        if not include_archived:
            query["archived_for_user_ids"] = {"$ne": user_id}
        docs = list(conversations_col.find(query).sort("updated_at", -1))
        conversations = [_serialize_doc(doc) for doc in docs]
    else:
        conversations = []
        for conv_id, convo in CONVERSATIONS_STORE.items():
            participants = convo.get("participants", [])
            if user_id not in participants:
                continue
            if (not include_archived) and user_id in convo.get("archived_for_user_ids", []):
                continue
            conversations.append(_serialize_doc({**convo, "_id": conv_id}))
        conversations = sorted(conversations, key=lambda c: c.get("updated_at") or "", reverse=True)

    unread_map = defaultdict(int)
    if MONGO_ENABLED and messages_extended_col is not None:
        unread_docs = messages_extended_col.find({"receiver_id": user_id, "read_at": None, "is_deleted": {"$ne": True}})
        for msg in unread_docs:
            unread_map[str(msg.get("conversation_id"))] += 1
    else:
        for msg in MESSAGES_EXTENDED_STORE:
            if str(msg.get("receiver_id")) == str(user_id) and not msg.get("read_at") and not msg.get("is_deleted"):
                unread_map[str(msg.get("conversation_id"))] += 1

    for convo in conversations:
        convo_id = str(convo.get("_id"))
        convo["unread_count"] = unread_map.get(convo_id, 0)

    return _ok({"count": len(conversations), "conversations": conversations})


@app.route("/api/conversations", methods=["POST"])
@_require_json
@_jwt_required
def create_conversation():
    identity = _auth_identity()
    user_id = str(identity.get("user_id") or "").strip().lower()
    if not user_id:
        return _err("Unauthorized user", 401)
    data = request.get_json(silent=True) or {}
    raw_participants = data.get("participants")
    participants = raw_participants if isinstance(raw_participants, list) else []
    participants = [str(p).strip().lower() for p in participants if str(p).strip()]
    if user_id not in participants:
        participants.append(user_id)
    if len(set(participants)) < 2:
        return _err("At least two participants are required", 400)

    conversation_id, convo = _find_or_create_conversation(
        participants,
        title=str(data.get("title", "")).strip(),
        created_by=user_id,
    )
    return _ok({"message": "Conversation ready", "conversation": convo, "conversation_id": conversation_id}, 201)


@app.route("/api/conversations/<conversation_id>", methods=["GET"])
@_jwt_required
def get_conversation(conversation_id):
    identity = _auth_identity()
    user_id = identity.get("user_id")
    convo = _get_conversation_by_id(conversation_id)
    if not convo:
        return _err("Conversation not found", 404)
    if user_id not in convo.get("participants", []):
        return _err("Forbidden", 403)
    return _ok({"conversation": convo})


@app.route("/api/conversations/<conversation_id>", methods=["PUT"])
@_require_json
@_jwt_required
def update_conversation(conversation_id):
    identity = _auth_identity()
    user_id = str(identity.get("user_id") or "").strip().lower()
    if not user_id:
        return _err("Unauthorized user", 401)
    data = request.get_json(silent=True) or {}
    convo = _get_conversation_by_id(conversation_id)
    if not convo:
        return _err("Conversation not found", 404)
    if user_id not in convo.get("participants", []):
        return _err("Forbidden", 403)

    updates: Dict[str, Any] = {"updated_at": _iso_now()}
    title_value = data.get("title")
    if isinstance(title_value, str) and title_value.strip():
        updates["title"] = title_value.strip()

    settings = data.get("notification_settings")
    if isinstance(settings, dict):
        existing = cast(Dict[str, Any], convo.get("notification_settings") if isinstance(convo.get("notification_settings"), dict) else {})
        existing[user_id] = settings
        updates["notification_settings"] = existing

    if MONGO_ENABLED and conversations_col is not None:
        try:
            conversations_col.update_one({"_id": ObjectId(conversation_id)}, {"$set": updates})
        except Exception:
            conversations_col.update_one({"_id": conversation_id}, {"$set": updates})
    else:
        if conversation_id in CONVERSATIONS_STORE:
            CONVERSATIONS_STORE[conversation_id].update(updates)

    return _ok({"message": "Conversation updated", "conversation_id": conversation_id})


@app.route("/api/conversations/<conversation_id>", methods=["DELETE"])
@_jwt_required
def archive_conversation(conversation_id):
    identity = _auth_identity()
    user_id = identity.get("user_id")
    convo = _get_conversation_by_id(conversation_id)
    if not convo:
        return _err("Conversation not found", 404)
    if user_id not in convo.get("participants", []):
        return _err("Forbidden", 403)

    archived = list(set((convo.get("archived_for_user_ids") or []) + [user_id]))
    updates = {"archived_for_user_ids": archived, "updated_at": _iso_now()}
    if MONGO_ENABLED and conversations_col is not None:
        try:
            conversations_col.update_one({"_id": ObjectId(conversation_id)}, {"$set": updates})
        except Exception:
            conversations_col.update_one({"_id": conversation_id}, {"$set": updates})
    else:
        if conversation_id in CONVERSATIONS_STORE:
            CONVERSATIONS_STORE[conversation_id].update(updates)

    return _ok({"message": "Conversation archived", "conversation_id": conversation_id})


@app.route("/api/conversations/<conversation_id>/mute", methods=["POST"])
@_jwt_required
def mute_conversation(conversation_id):
    identity = _auth_identity()
    user_id = identity.get("user_id")
    convo = _get_conversation_by_id(conversation_id)
    if not convo:
        return _err("Conversation not found", 404)
    muted = list(set((convo.get("muted_for_user_ids") or []) + [user_id]))
    updates = {"muted_for_user_ids": muted, "updated_at": _iso_now()}
    if MONGO_ENABLED and conversations_col is not None:
        try:
            conversations_col.update_one({"_id": ObjectId(conversation_id)}, {"$set": updates})
        except Exception:
            conversations_col.update_one({"_id": conversation_id}, {"$set": updates})
    else:
        if conversation_id in CONVERSATIONS_STORE:
            CONVERSATIONS_STORE[conversation_id].update(updates)
    return _ok({"message": "Conversation muted", "conversation_id": conversation_id})


@app.route("/api/conversations/<conversation_id>/pin", methods=["POST"])
@_jwt_required
def pin_conversation(conversation_id):
    identity = _auth_identity()
    user_id = identity.get("user_id")
    convo = _get_conversation_by_id(conversation_id)
    if not convo:
        return _err("Conversation not found", 404)
    pinned = list(set((convo.get("pinned_for_user_ids") or []) + [user_id]))
    updates = {"pinned_for_user_ids": pinned, "updated_at": _iso_now()}
    if MONGO_ENABLED and conversations_col is not None:
        try:
            conversations_col.update_one({"_id": ObjectId(conversation_id)}, {"$set": updates})
        except Exception:
            conversations_col.update_one({"_id": conversation_id}, {"$set": updates})
    else:
        if conversation_id in CONVERSATIONS_STORE:
            CONVERSATIONS_STORE[conversation_id].update(updates)
    return _ok({"message": "Conversation pinned", "conversation_id": conversation_id})


@app.route("/api/presence/online", methods=["POST"])
@_require_json
@_jwt_required
def set_presence_online():
    identity = _auth_identity()
    user_id = identity.get("user_id")
    data = request.get_json(silent=True) or {}
    online = bool(data.get("online", True))
    payload = {
        "user_id": user_id,
        "online": online,
        "last_seen": _iso_now(),
        "updated_at": _iso_now(),
    }
    if MONGO_ENABLED and presence_col is not None:
        presence_col.update_one({"user_id": user_id}, {"$set": payload}, upsert=True)
    else:
        PRESENCE_STORE[user_id] = payload
    return _ok({"message": "Presence updated", "presence": payload})


@app.route("/api/presence/typing", methods=["POST"])
@_require_json
@_jwt_required
def set_presence_typing():
    identity = _auth_identity()
    user_id = identity.get("user_id")
    data = request.get_json(silent=True) or {}
    conversation_id = str(data.get("conversation_id", "")).strip()
    is_typing = bool(data.get("is_typing", True))
    if not conversation_id:
        return _err("conversation_id is required", 400)

    payload = {
        "user_id": user_id,
        "conversation_id": conversation_id,
        "is_typing": is_typing,
        "updated_at": _iso_now(),
    }
    key = f"typing::{conversation_id}::{user_id}"
    if MONGO_ENABLED and presence_col is not None:
        presence_col.update_one({"typing_key": key}, {"$set": {**payload, "typing_key": key}}, upsert=True)
    else:
        PRESENCE_STORE[key] = payload
    return _ok({"message": "Typing status updated", "typing": payload})


@app.route("/api/presence/status/<user_id>", methods=["GET"])
@_jwt_required
def get_presence_status(user_id):
    user_id = str(user_id or "").strip().lower()
    if not user_id:
        return _err("Invalid user_id", 400)
    if MONGO_ENABLED and presence_col is not None:
        doc = presence_col.find_one({"user_id": user_id})
        payload = _serialize_doc(doc) if doc else {"user_id": user_id, "online": False, "last_seen": None}
    else:
        payload = PRESENCE_STORE.get(user_id, {"user_id": user_id, "online": False, "last_seen": None})
    return _ok({"presence": payload})


@app.route("/api/notifications", methods=["GET"])
@_jwt_required
def get_notification_preferences():
    identity = _auth_identity()
    user_id = identity.get("user_id")
    if MONGO_ENABLED and notification_settings_col is not None:
        docs = list(notification_settings_col.find({"user_id": user_id}))
        settings = {_serialize_doc(doc).get("conversation_id"): _serialize_doc(doc).get("settings") for doc in docs}
    else:
        settings = {k.split("::", 1)[1]: v for k, v in NOTIFICATION_SETTINGS_STORE.items() if k.startswith(f"{user_id}::")}
    return _ok({"user_id": user_id, "settings": settings})


@app.route("/api/notifications/<conversation_id>", methods=["PUT"])
@_require_json
@_jwt_required
def update_notification_preferences(conversation_id):
    identity = _auth_identity()
    user_id = identity.get("user_id")
    data = request.get_json(silent=True) or {}
    settings = data.get("settings") if isinstance(data.get("settings"), dict) else {}
    doc = {
        "user_id": user_id,
        "conversation_id": str(conversation_id),
        "settings": settings,
        "updated_at": _iso_now(),
    }
    if MONGO_ENABLED and notification_settings_col is not None:
        notification_settings_col.update_one(
            {"user_id": user_id, "conversation_id": str(conversation_id)},
            {"$set": doc},
            upsert=True,
        )
    else:
        NOTIFICATION_SETTINGS_STORE[f"{user_id}::{conversation_id}"] = settings
    return _ok({"message": "Notification settings updated", "conversation_id": conversation_id, "settings": settings})


@app.route("/api/db/status", methods=["GET"])
def db_status():
    """Check MongoDB connection status."""
    return _ok({
        "mongodb_enabled": MONGO_ENABLED,
        "mongodb_uri": _safe_mongo_uri_for_status(MONGO_URI) if MONGO_ENABLED else None,
        "database_name": DB_NAME if MONGO_ENABLED else None,
        "collections": {
            "users": users_col is not None,
            "business_data": business_data_col is not None,
            "client_data": client_data_col is not None,
            "freelancer_data": freelancer_data_col is not None,
            "products": products_col is not None,
            "orders": orders_col is not None,
            "payments": payments_col is not None,
            "messages": messages_col is not None,
            "reviews": reviews_col is not None,
            "reports": reports_col is not None,
            "detection_logs": detection_logs_col is not None
        }
    })


# ─────────────────────────────────────────────────────────────────────────────
# UTILITY ENDPOINTS
# ─────────────────────────────────────────────────────────────────────────────
@app.route("/api/health", methods=["GET"])
def health():
    models  = _get_models(load_if_missing=False)
    return _ok({
        "service"     : "SE-GUARD ML Backend",
        "version"     : "1.0.0",
        "models_ready": list(models.keys()),
        "uptime_note" : "All models loaded and serving"
    })


@app.route("/api/runtime", methods=["GET"])
def runtime_info():
    return _ok({
        "app_file": os.path.abspath(__file__),
        "cwd": os.getcwd(),
        "python": sys.executable,
    })


@app.route("/api/stats", methods=["GET"])
def stats():
    return _ok({
        "total_detections": len(LOG_STORE),
        "by_endpoint"     : {k: dict(v) for k, v in STATS.items()},
        "recent_log"      : LOG_STORE[-20:]
    })


@app.route("/", methods=["GET"])
def index():
    """Serve the auth/login HTML file as the entry point."""
    return send_from_directory(FRONTEND_DIR, "index.html")


@app.route("/dashboard", methods=["GET"])
def dashboard_page():
    """Serve the main dashboard HTML file."""
    return send_from_directory(FRONTEND_DIR, "dashboard.html")


@app.route("/dashboard.html", methods=["GET"])
def dashboard_html_alias():
    """Serve dashboard HTML for direct filename access."""
    return send_from_directory(FRONTEND_DIR, "dashboard.html")


@app.route("/se-guard-dashboard.html", methods=["GET"])
def dashboard_html():
    """Backward-compatible route for older dashboard filename."""
    return send_from_directory(FRONTEND_DIR, "dashboard.html")


@app.route("/auth", methods=["GET"])
def auth_page():
    """Serve the auth/login HTML file."""
    return send_from_directory(FRONTEND_DIR, "index.html")


@app.route("/sg-favicon.svg", methods=["GET"])
def root_favicon():
    """Serve root favicon used by frontend pages."""
    return send_from_directory(PROJECT_ROOT, "sg-favicon.svg")


@app.route("/api.js", methods=["GET"])
def frontend_api_js():
    """Serve dashboard helper script referenced by dashboard.html."""
    frontend_api_path = os.path.join(FRONTEND_DIR, "api.js")
    if os.path.exists(frontend_api_path):
        return send_from_directory(FRONTEND_DIR, "api.js")
    return send_from_directory(BACKEND_DIR, "api.js")


@app.route("/auth.js", methods=["GET"])
def frontend_auth_js():
    """Serve authentication helper script referenced by index.html."""
    return send_from_directory(FRONTEND_DIR, "auth.js")


@app.route("/dashboard-auth-integration.js", methods=["GET"])
def frontend_dashboard_auth_js():
    """Serve optional dashboard auth integration helper script."""
    return send_from_directory(FRONTEND_DIR, "dashboard-auth-integration.js")


@app.route("/static/<path:filename>", methods=["GET"])
def frontend_static(filename):
    """Serve static frontend assets (favicon, images, etc.)."""
    return send_from_directory(os.path.join(FRONTEND_DIR, "static"), filename)


@app.route("/api/detect/demo", methods=["GET"])
def demo():
    """Return example payloads for all detectors."""
    return _ok({
        "examples": {
            "profile": {
                "account_age_days": 2, "posts": 0, "completeness": 0.1,
                "email_domain_score": 0.2, "phone_verified": 0,
                "photo_uploaded": 0, "reviews_count": 0,
                "avg_rating": 5.0, "login_frequency": 0.02, "ip_country_mismatch": 1
            },
            "message": {"text": "pay me right now or i will destroy you"},
            "review" : {"text": "best product ever amazing wonderful perfect", "rating": 5},
            "payment": {
                "amount": 175000, "hour_of_day": 2, "retries": 6,
                "new_device": 1, "vpn_flag": 1,
                "amount_vs_history_ratio": 12.0, "time_since_last_txn_min": 0.5
            },
            "product": {
                "price_vs_category_avg_ratio": 0.04, "description_length": 4,
                "image_count": 0, "seller_age_days": 1, "seller_rating": 5.0,
                "seller_total_sales": 0, "discount_pct": 97, "has_contact_info_in_desc": 1
            }
        }
    })


# ─────────────────────────────────────────────────────────────────────────────
# STARTUP
# ─────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    log.info("=" * 60)
    log.info("  SE-GUARD ML Backend  |  Loading models …")
    log.info("=" * 60)
    log.info("=" * 60)
    log.info("  Server starting on  http://127.0.0.1:5000")
    log.info("  API docs at         http://127.0.0.1:5000/api/detect/demo")
    log.info("=" * 60)
    _start_background_index_build()
    _warm_mongo_pool()
    app.run(host="0.0.0.0", port=5000, debug=False)
