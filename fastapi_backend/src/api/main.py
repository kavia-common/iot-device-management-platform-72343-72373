import os
import json
import hashlib
import hmac
import logging
from datetime import datetime, timedelta, timezone
from typing import Optional, List, Dict, Any

from fastapi import FastAPI, Depends, HTTPException, status, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, EmailStr, ValidationError

# External integrations will be optionally imported to allow app to start even if env isn't set
# We gate their usage via config checks.
try:
    import jwt
except Exception:  # pragma: no cover - runtime availability
    jwt = None

try:
    import paho.mqtt.client as mqtt
except Exception:
    mqtt = None

try:
    import stripe as stripe_sdk
except Exception:
    stripe_sdk = None

try:
    import razorpay  # type: ignore
except Exception:
    razorpay = None

try:
    import firebase_admin
    from firebase_admin import credentials, firestore
except Exception:
    firebase_admin = None
    credentials = None
    firestore = None

from dotenv import load_dotenv

# Load .env if present
load_dotenv()

# ------------------------------------------------------------------------------
# Configuration and Logger
# ------------------------------------------------------------------------------
logger = logging.getLogger("iot-backend")
logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"))

# Environment variable keys expected:
# JWT_SECRET, JWT_ALG (default HS256), JWT_EXP_MIN (default 60)
# FIREBASE_CRED_JSON (path) or FIREBASE_CRED_BASE64 (base64 of json)
# STRIPE_API_KEY, STRIPE_WEBHOOK_SECRET
# RAZORPAY_KEY_ID, RAZORPAY_KEY_SECRET
# EMAIL_FROM, SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS (optional if using SMTP)
# MQTT_BROKER_HOST (default: broker.hivemq.com), MQTT_BROKER_PORT (default: 1883), MQTT_USERNAME, MQTT_PASSWORD, MQTT_TOPIC (default: iot/demo/telemetry/#)
# SITE_URL (used for webhook callback docs)
# PLAN_FREE_MAX_DEVICES, PLAN_FREE_EMAIL_NOTIF=false
# ROLLUP_CRON_DISABLED=false

JWT_SECRET = os.getenv("JWT_SECRET", "dev-secret-change-me")
JWT_ALG = os.getenv("JWT_ALG", "HS256")
JWT_EXP_MIN = int(os.getenv("JWT_EXP_MIN", "60"))

FIREBASE_CRED_JSON = os.getenv("FIREBASE_CRED_JSON")
FIREBASE_CRED_BASE64 = os.getenv("FIREBASE_CRED_BASE64")

STRIPE_API_KEY = os.getenv("STRIPE_API_KEY")
STRIPE_WEBHOOK_SECRET = os.getenv("STRIPE_WEBHOOK_SECRET")

RAZORPAY_KEY_ID = os.getenv("RAZORPAY_KEY_ID")
RAZORPAY_KEY_SECRET = os.getenv("RAZORPAY_KEY_SECRET")

EMAIL_FROM = os.getenv("EMAIL_FROM")
SMTP_HOST = os.getenv("SMTP_HOST")
SMTP_PORT = int(os.getenv("SMTP_PORT", "587")) if os.getenv("SMTP_PORT") else None
SMTP_USER = os.getenv("SMTP_USER")
SMTP_PASS = os.getenv("SMTP_PASS")

MQTT_BROKER_HOST = os.getenv("MQTT_BROKER_HOST", "broker.hivemq.com")
MQTT_BROKER_PORT = int(os.getenv("MQTT_BROKER_PORT", "1883"))
MQTT_USERNAME = os.getenv("MQTT_USERNAME")
MQTT_PASSWORD = os.getenv("MQTT_PASSWORD")
MQTT_TOPIC = os.getenv("MQTT_TOPIC", "iot/demo/telemetry/#")

SITE_URL = os.getenv("SITE_URL", "http://localhost:8000")

PLAN_FREE_MAX_DEVICES = int(os.getenv("PLAN_FREE_MAX_DEVICES", "2"))
PLAN_FREE_EMAIL_NOTIF = os.getenv("PLAN_FREE_EMAIL_NOTIF", "false").lower() == "true"

ROLLUP_CRON_DISABLED = os.getenv("ROLLUP_CRON_DISABLED", "false").lower() == "true"

# ------------------------------------------------------------------------------
# Firestore Initialization
# ------------------------------------------------------------------------------
_db = None


def _init_firestore_if_needed() -> Optional[Any]:
    global _db
    if _db is not None:
        return _db
    if firestore is None:
        logger.warning("Firestore SDK not installed; persistence disabled.")
        return None
    try:
        if not firebase_admin._apps:
            if FIREBASE_CRED_JSON and os.path.exists(FIREBASE_CRED_JSON):
                cred = credentials.Certificate(FIREBASE_CRED_JSON)
                firebase_admin.initialize_app(cred)
            elif FIREBASE_CRED_BASE64:
                import base64
                raw = base64.b64decode(FIREBASE_CRED_BASE64).decode("utf-8")
                data = json.loads(raw)
                cred = credentials.Certificate(data)
                firebase_admin.initialize_app(cred)
            else:
                firebase_admin.initialize_app()
        _db = firestore.client()
        logger.info("Firestore initialized.")
        return _db
    except Exception as e:
        logger.error(f"Failed to initialize Firestore: {e}")
        return None


# ------------------------------------------------------------------------------
# Security / Auth
# ------------------------------------------------------------------------------
bearer_scheme = HTTPBearer(auto_error=False)


# PUBLIC_INTERFACE
def create_jwt(user_id: str, email: Optional[str] = None, plan: str = "free") -> str:
    """Create a JWT for a given user."""
    if jwt is None:
        raise RuntimeError("PyJWT not installed. Please ensure requirements are installed.")
    now = datetime.now(tz=timezone.utc)
    payload = {
        "sub": user_id,
        "email": email,
        "plan": plan,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=JWT_EXP_MIN)).timestamp()),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALG)


# PUBLIC_INTERFACE
def decode_jwt(token: str) -> dict:
    """Decode a JWT and return payload."""
    if jwt is None:
        raise RuntimeError("PyJWT not installed.")
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALG])
    except Exception:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired token")


async def get_current_user(credentials: Optional[HTTPAuthorizationCredentials] = Depends(bearer_scheme)) -> dict:
    if not credentials:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing authorization")
    token = credentials.credentials
    payload = decode_jwt(token)
    return payload


# ------------------------------------------------------------------------------
# Pydantic Models
# ------------------------------------------------------------------------------
class AuthRequest(BaseModel):
    email: EmailStr = Field(..., description="User email")
    user_id: str = Field(..., description="Unique user id; typically from your identity layer.")


class AuthResponse(BaseModel):
    token: str = Field(..., description="JWT token")
    plan: str = Field(..., description="User plan: free or premium")


class DeviceCreate(BaseModel):
    name: str = Field(..., description="Human readable device name")
    description: Optional[str] = Field(None, description="Description")
    metadata: Optional[Dict[str, Any]] = Field(default_factory=dict, description="Additional metadata")


class DeviceUpdate(BaseModel):
    name: Optional[str] = Field(None, description="Name")
    description: Optional[str] = Field(None, description="Description")
    metadata: Optional[Dict[str, Any]] = Field(None, description="Metadata")


class DeviceOut(BaseModel):
    id: str
    owner_id: str
    name: str
    description: Optional[str] = None
    metadata: Dict[str, Any] = {}
    created_at: datetime


class Threshold(BaseModel):
    id: Optional[str] = None
    device_id: str = Field(..., description="Target device id")
    metric: str = Field(..., description="Metric name, e.g., temperature")
    operator: str = Field(..., description="One of: gt, gte, lt, lte, eq, neq")
    value: float = Field(..., description="Threshold value")
    enabled: bool = Field(default=True, description="Enable/disable")


class TelemetryIngest(BaseModel):
    device_id: str
    metric: str
    value: float
    ts: Optional[datetime] = None


class UsageQuery(BaseModel):
    device_id: str
    metric: Optional[str] = None
    start: Optional[datetime] = None
    end: Optional[datetime] = None
    rollup: Optional[str] = Field(None, description="None|hour|day")


class UsagePoint(BaseModel):
    ts: datetime
    metrics: Dict[str, float]


class AlertOut(BaseModel):
    id: str
    device_id: str
    metric: str
    rule_type: str
    message: str
    value: float
    ts: datetime


class PlanUpdate(BaseModel):
    plan: str = Field(..., description="free|premium")


class CheckoutSessionRequest(BaseModel):
    provider: str = Field(..., description="stripe|razorpay")
    price_id: Optional[str] = Field(None, description="Stripe: price id to create a session")
    notes: Optional[Dict[str, Any]] = None


# ------------------------------------------------------------------------------
# Utility Services: Firestore Collections
# ------------------------------------------------------------------------------
COL_DEVICES = "devices"
COL_TELEMETRY = "telemetry"
COL_ROLLUPS = "rollups"
COL_ALERTS = "alerts"
COL_THRESHOLDS = "thresholds"
COL_USER_PLANS = "user_plans"
COL_PAYMENTS = "payments"


def _user_plan(db, user_id: str) -> str:
    if db is None:
        return "free"
    doc = db.collection(COL_USER_PLANS).document(user_id).get()
    if doc.exists:
        data = doc.to_dict()
        return data.get("plan", "free")
    return "free"


def _enforce_plan_limits(db, user_id: str):
    plan = _user_plan(db, user_id)
    if plan == "premium":
        return
    # free plan device limit
    devices = db.collection(COL_DEVICES).where("owner_id", "==", user_id).stream() if db else []
    count = 0
    for _ in devices:
        count += 1
    if count >= PLAN_FREE_MAX_DEVICES:
        raise HTTPException(status_code=403, detail=f"Free plan limit reached: {PLAN_FREE_MAX_DEVICES} devices")


def _send_email(to_email: str, subject: str, body: str) -> None:
    # Simple SMTP sender if configured; otherwise log only.
    if not (SMTP_HOST and SMTP_PORT and SMTP_USER and SMTP_PASS and EMAIL_FROM):
        logger.info(f"[EMAIL] Would send to {to_email}: {subject} - {body}")
        return
    import smtplib
    from email.mime.text import MIMEText

    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"] = EMAIL_FROM
    msg["To"] = to_email
    try:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
            server.starttls()
            server.login(SMTP_USER, SMTP_PASS)
            server.sendmail(EMAIL_FROM, [to_email], msg.as_string())
        logger.info("Email sent successfully")
    except Exception as e:
        logger.error(f"Email send error: {e}")


# ------------------------------------------------------------------------------
# MQTT Ingestion and Processing
# ------------------------------------------------------------------------------
_mqtt_client = None


def _handle_telemetry_message(db, payload: dict):
    # Expected payload format matches TelemetryIngest
    try:
        telemetry = TelemetryIngest(**payload)
    except ValidationError as e:
        logger.warning(f"Invalid telemetry payload: {e}")
        return
    ts = telemetry.ts or datetime.now(tz=timezone.utc)
    doc = {
        "device_id": telemetry.device_id,
        "metric": telemetry.metric,
        "value": telemetry.value,
        "ts": ts,
    }
    if db:
        db.collection(COL_TELEMETRY).add(doc)
        _check_thresholds_and_anomaly(db, telemetry.device_id, telemetry.metric, telemetry.value, ts)


def _mqtt_on_connect(client, userdata, flags, rc):
    logger.info(f"MQTT connected with result code {rc}")
    try:
        client.subscribe(MQTT_TOPIC)
        logger.info(f"Subscribed to topic: {MQTT_TOPIC}")
    except Exception as e:
        logger.error(f"MQTT subscribe error: {e}")


def _mqtt_on_message(client, userdata, msg):
    db = _init_firestore_if_needed()
    try:
        payload = msg.payload.decode("utf-8")
        data = json.loads(payload)
        _handle_telemetry_message(db, data)
    except Exception as e:
        logger.error(f"MQTT message handling error: {e}")


def _start_mqtt():
    global _mqtt_client
    if mqtt is None:
        logger.warning("paho-mqtt not installed; MQTT listener disabled.")
        return
    try:
        _mqtt_client = mqtt.Client()
        if MQTT_USERNAME and MQTT_PASSWORD:
            _mqtt_client.username_pw_set(MQTT_USERNAME, MQTT_PASSWORD)
        _mqtt_client.on_connect = _mqtt_on_connect
        _mqtt_client.on_message = _mqtt_on_message
        _mqtt_client.connect(MQTT_BROKER_HOST, MQTT_BROKER_PORT, 60)
        _mqtt_client.loop_start()
        logger.info("MQTT client started.")
    except Exception as e:
        logger.error(f"MQTT start error: {e}")


# ------------------------------------------------------------------------------
# Alerts: Threshold & Simple Anomaly Detection (Z-score like)
# ------------------------------------------------------------------------------
def _store_alert(db, alert: Dict[str, Any]):
    if db:
        db.collection(COL_ALERTS).add(alert)


def _notify_if_premium(db, device_owner_id: str, subject: str, body: str):
    plan = _user_plan(db, device_owner_id)
    if plan == "premium":
        # For demo, we treat owner_id as email for notifications if valid
        to_email = device_owner_id if "@" in device_owner_id else None
        if to_email:
            _send_email(to_email, subject, body)
    else:
        if PLAN_FREE_EMAIL_NOTIF:
            to_email = device_owner_id if "@" in device_owner_id else None
            if to_email:
                _send_email(to_email, subject, body)


def _get_device_owner(db, device_id: str) -> Optional[str]:
    if db is None:
        return None
    doc = db.collection(COL_DEVICES).document(device_id).get()
    if doc.exists:
        data = doc.to_dict()
        return data.get("owner_id")
    return None


def _check_thresholds_and_anomaly(db, device_id: str, metric: str, value: float, ts: datetime):
    # Thresholds
    if db:
        thresholds = db.collection(COL_THRESHOLDS).where("device_id", "==", device_id).where("metric", "==", metric).where("enabled", "==", True).stream()
        for tdoc in thresholds:
            t = tdoc.to_dict()
            op = t.get("operator")
            th_val = float(t.get("value"))
            triggered = False
            if op == "gt" and value > th_val:
                triggered = True
            elif op == "gte" and value >= th_val:
                triggered = True
            elif op == "lt" and value < th_val:
                triggered = True
            elif op == "lte" and value <= th_val:
                triggered = True
            elif op == "eq" and value == th_val:
                triggered = True
            elif op == "neq" and value != th_val:
                triggered = True
            if triggered:
                alert = {
                    "device_id": device_id,
                    "metric": metric,
                    "rule_type": "threshold",
                    "message": f"{metric} {op} {th_val} triggered with value {value}",
                    "value": value,
                    "ts": ts,
                }
                _store_alert(db, alert)
                owner = _get_device_owner(db, device_id)
                if owner:
                    _notify_if_premium(db, owner, f"Threshold Alert: {device_id}/{metric}", alert["message"])

    # Simple anomaly detection: compute mean/std of last N points
    N = 30
    if db:
        series = db.collection(COL_TELEMETRY).where("device_id", "==", device_id).where("metric", "==", metric).order_by("ts", direction=firestore.Query.DESCENDING).limit(N).stream()
        values = []
        for doc in series:
            data = doc.to_dict()
            v = float(data.get("value", 0.0))
            values.append(v)
        if len(values) >= 10:
            mean = sum(values) / len(values)
            variance = sum((v - mean) ** 2 for v in values) / len(values)
            std = variance ** 0.5
            if std > 0:
                z = (value - mean) / std
                if abs(z) >= 3:
                    alert = {
                        "device_id": device_id,
                        "metric": metric,
                        "rule_type": "anomaly",
                        "message": f"Anomaly detected (|z|>=3). z={z:.2f}, value={value}, mean={mean:.2f}, std={std:.2f}",
                        "value": value,
                        "ts": ts,
                    }
                    _store_alert(db, alert)
                    owner = _get_device_owner(db, device_id)
                    if owner:
                        _notify_if_premium(db, owner, f"Anomaly Alert: {device_id}/{metric}", alert["message"])


# ------------------------------------------------------------------------------
# Rollups (hourly/daily)
# ------------------------------------------------------------------------------
def _rollup_range(db, device_id: str, metric: Optional[str], start: datetime, end: datetime, granularity: str) -> List[UsagePoint]:
    # Compute rollups from raw telemetry. Save them in rollups collection for caching.
    if db is None:
        return []

    # align to boundaries
    def floor_hour(dt: datetime) -> datetime:
        return dt.replace(minute=0, second=0, microsecond=0)

    def floor_day(dt: datetime) -> datetime:
        return dt.replace(hour=0, minute=0, second=0, microsecond=0)

    bucket_func = floor_hour if granularity == "hour" else floor_day
    # bucket_delta was previously unused; keeping logic simple without it

    buckets: Dict[datetime, Dict[str, List[float]]] = {}

    q = db.collection(COL_TELEMETRY).where("device_id", "==", device_id).where("ts", ">=", start).where("ts", "<=", end)
    if metric:
        q = q.where("metric", "==", metric)
    docs = q.stream()
    for d in docs:
        data = d.to_dict()
        m = data["metric"]
        v = float(data["value"])
        ts = data["ts"]
        b = bucket_func(ts)
        if b not in buckets:
            buckets[b] = {}
        if m not in buckets[b]:
            buckets[b][m] = []
        buckets[b][m].append(v)

    points: List[UsagePoint] = []
    for bucket_ts, metr in sorted(buckets.items(), key=lambda x: x[0]):
        metrics_avg = {m: (sum(vals) / len(vals)) for m, vals in metr.items() if len(vals) > 0}
        points.append(UsagePoint(ts=bucket_ts, metrics=metrics_avg))
        # Persist rollup
        rollup_doc = {
            "device_id": device_id,
            "ts": bucket_ts,
            "granularity": granularity,
            "metrics": metrics_avg,
        }
        db.collection(COL_ROLLUPS).add(rollup_doc)

    return points


def _get_usage(db, device_id: str, metric: Optional[str], start: Optional[datetime], end: Optional[datetime], rollup: Optional[str]) -> List[UsagePoint]:
    if db is None:
        return []
    if start is None:
        start = datetime.now(tz=timezone.utc) - timedelta(hours=24)
    if end is None:
        end = datetime.now(tz=timezone.utc)
    if rollup in ("hour", "day"):
        return _rollup_range(db, device_id, metric, start, end, rollup)
    # Raw usage aggregation: list points per timestamp (group by ts)
    q = db.collection(COL_TELEMETRY).where("device_id", "==", device_id).where("ts", ">=", start).where("ts", "<=", end)
    if metric:
        q = q.where("metric", "==", metric)
    docs = q.stream()
    tmp: Dict[datetime, Dict[str, float]] = {}
    for d in docs:
        data = d.to_dict()
        ts = data["ts"]
        m = data["metric"]
        v = float(data["value"])
        if ts not in tmp:
            tmp[ts] = {}
        tmp[ts][m] = v
    points = [UsagePoint(ts=k, metrics=v) for k, v in sorted(tmp.items(), key=lambda x: x[0])]
    return points


# ------------------------------------------------------------------------------
# Payments
# ------------------------------------------------------------------------------
def _set_user_plan(db, user_id: str, plan: str):
    if db is None:
        return
    db.collection(COL_USER_PLANS).document(user_id).set({"plan": plan, "updated_at": datetime.now(tz=timezone.utc)})


def _create_stripe_session(price_id: str, user_id: str) -> Dict[str, Any]:
    if not stripe_sdk or not STRIPE_API_KEY:
        raise HTTPException(status_code=400, detail="Stripe not configured")
    stripe_sdk.api_key = STRIPE_API_KEY
    # Use test mode price id
    session = stripe_sdk.checkout.Session.create(
        mode="subscription",
        line_items=[{"price": price_id, "quantity": 1}],
        success_url=f"{SITE_URL}/payments/success?session_id={{CHECKOUT_SESSION_ID}}",
        cancel_url=f"{SITE_URL}/payments/canceled",
        metadata={"user_id": user_id},
    )
    return {"id": session.id, "url": session.url}


def _verify_razorpay_signature(payload_body: bytes, signature: str, secret: str) -> bool:
    # For webhook verification
    digest = hmac.new(bytes(secret, "utf-8"), msg=payload_body, digestmod=hashlib.sha256).hexdigest()
    return hmac.compare_digest(digest, signature)


# ------------------------------------------------------------------------------
# FastAPI App
# ------------------------------------------------------------------------------
app = FastAPI(
    title="IoT Device Backend",
    description="IoT backend with MQTT ingestion, Firestore, JWT auth, device/threshold/alerts, rollups, and payments.",
    version="1.0.0",
    openapi_tags=[
        {"name": "Auth", "description": "Authentication and plan management"},
        {"name": "Devices", "description": "Device registration and management"},
        {"name": "Telemetry", "description": "Usage retrieval (raw and rollups)"},
        {"name": "Thresholds", "description": "Threshold CRUD"},
        {"name": "Alerts", "description": "Alerts retrieval"},
        {"name": "Payments", "description": "Checkout and webhooks"},
        {"name": "WebSocket/MQTT", "description": "Real-time ingestion via MQTT"},
        {"name": "Docs", "description": "Helpful documentation routes"},
    ],
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
def on_startup():
    # Init Firestore
    _init_firestore_if_needed()
    # Start MQTT
    _start_mqtt()
    logger.info("Application started.")


# Root Health
@app.get("/", summary="Health Check", tags=["Docs"])
def health_check():
    """Health check endpoint to verify the service is running."""
    return {"message": "Healthy"}


# PUBLIC_INTERFACE
@app.post("/auth/login", response_model=AuthResponse, summary="Login and receive JWT", tags=["Auth"])
def login(auth: AuthRequest):
    """Issue a JWT. This assumes upstream identity management; for demo we accept any email/user_id."""
    db = _init_firestore_if_needed()
    plan = _user_plan(db, auth.user_id)
    token = create_jwt(auth.user_id, auth.email, plan)
    return AuthResponse(token=token, plan=plan)


# PUBLIC_INTERFACE
@app.post("/auth/plan", summary="Set user plan (admin/demo)", tags=["Auth"])
def set_plan(update: PlanUpdate, user=Depends(get_current_user)):
    """Admin/demo endpoint to set current user's plan. Use for testing plan enforcement."""
    db = _init_firestore_if_needed()
    if update.plan not in ("free", "premium"):
        raise HTTPException(400, "Invalid plan")
    _set_user_plan(db, user["sub"], update.plan)
    return {"status": "ok", "plan": update.plan}


# Devices CRUD
# PUBLIC_INTERFACE
@app.post("/devices", response_model=DeviceOut, summary="Create device", tags=["Devices"])
def create_device(payload: DeviceCreate, user=Depends(get_current_user)):
    """Create a device for the authenticated user. Free plan limits enforce max device count."""
    db = _init_firestore_if_needed()
    if db is None:
        raise HTTPException(500, "Firestore not configured")
    _enforce_plan_limits(db, user["sub"])
    doc_ref = db.collection(COL_DEVICES).document()
    now = datetime.now(tz=timezone.utc)
    data = {
        "id": doc_ref.id,
        "owner_id": user["sub"],
        "name": payload.name,
        "description": payload.description,
        "metadata": payload.metadata or {},
        "created_at": now,
    }
    doc_ref.set(data)
    return DeviceOut(**data)


# PUBLIC_INTERFACE
@app.get("/devices", response_model=List[DeviceOut], summary="List my devices", tags=["Devices"])
def list_devices(user=Depends(get_current_user)):
    """List devices owned by the authenticated user."""
    db = _init_firestore_if_needed()
    if db is None:
        return []
    cur = db.collection(COL_DEVICES).where("owner_id", "==", user["sub"]).stream()
    out: List[DeviceOut] = []
    for d in cur:
        out.append(DeviceOut(**d.to_dict()))
    return out


# PUBLIC_INTERFACE
@app.get("/devices/{device_id}", response_model=DeviceOut, summary="Get device", tags=["Devices"])
def get_device(device_id: str, user=Depends(get_current_user)):
    """Get a specific device by id."""
    db = _init_firestore_if_needed()
    if db is None:
        raise HTTPException(404, "Device not found")
    doc = db.collection(COL_DEVICES).document(device_id).get()
    if not doc.exists:
        raise HTTPException(404, "Device not found")
    data = doc.to_dict()
    if data["owner_id"] != user["sub"]:
        raise HTTPException(403, "Forbidden")
    return DeviceOut(**data)


# PUBLIC_INTERFACE
@app.patch("/devices/{device_id}", response_model=DeviceOut, summary="Update device", tags=["Devices"])
def update_device(device_id: str, payload: DeviceUpdate, user=Depends(get_current_user)):
    """Update a device fields."""
    db = _init_firestore_if_needed()
    if db is None:
        raise HTTPException(404, "Device not found")
    ref = db.collection(COL_DEVICES).document(device_id)
    doc = ref.get()
    if not doc.exists:
        raise HTTPException(404, "Device not found")
    data = doc.to_dict()
    if data["owner_id"] != user["sub"]:
        raise HTTPException(403, "Forbidden")
    new_data = {}
    if payload.name is not None:
        new_data["name"] = payload.name
    if payload.description is not None:
        new_data["description"] = payload.description
    if payload.metadata is not None:
        new_data["metadata"] = payload.metadata
    if new_data:
        ref.update(new_data)
        data.update(new_data)
    return DeviceOut(**data)


# PUBLIC_INTERFACE
@app.delete("/devices/{device_id}", summary="Delete device", tags=["Devices"])
def delete_device(device_id: str, user=Depends(get_current_user)):
    """Delete a device."""
    db = _init_firestore_if_needed()
    if db is None:
        raise HTTPException(404, "Device not found")
    ref = db.collection(COL_DEVICES).document(device_id)
    doc = ref.get()
    if not doc.exists:
        raise HTTPException(404, "Device not found")
    data = doc.to_dict()
    if data["owner_id"] != user["sub"]:
        raise HTTPException(403, "Forbidden")
    ref.delete()
    return {"status": "deleted"}


# Telemetry / Usage
# PUBLIC_INTERFACE
@app.post("/telemetry/ingest", summary="Ingest telemetry via HTTP (alt to MQTT)", tags=["Telemetry"])
def ingest_http(payload: TelemetryIngest, user=Depends(get_current_user)):
    """Alternative HTTP ingestion; MQTT is preferred. Useful for testing."""
    db = _init_firestore_if_needed()
    _handle_telemetry_message(db, payload.dict())
    return {"status": "ok"}


# PUBLIC_INTERFACE
@app.post("/usage", response_model=List[UsagePoint], summary="Get usage data", tags=["Telemetry"])
def usage(query: UsageQuery, user=Depends(get_current_user)):
    """Retrieve raw or rollup usage data. rollup can be 'hour' or 'day'."""
    db = _init_firestore_if_needed()
    # ensure user owns device
    if db:
        doc = db.collection(COL_DEVICES).document(query.device_id).get()
        if not doc.exists:
            raise HTTPException(404, "Device not found")
        data = doc.to_dict()
        if data["owner_id"] != user["sub"]:
            raise HTTPException(403, "Forbidden")
    return _get_usage(db, query.device_id, query.metric, query.start, query.end, query.rollup)


# Thresholds CRUD
# PUBLIC_INTERFACE
@app.post("/thresholds", response_model=Threshold, summary="Create threshold", tags=["Thresholds"])
def add_threshold(t: Threshold, user=Depends(get_current_user)):
    """Create a threshold rule for a device/metric."""
    db = _init_firestore_if_needed()
    if db is None:
        raise HTTPException(500, "Firestore not configured")
    # check device ownership
    doc = db.collection(COL_DEVICES).document(t.device_id).get()
    if not doc.exists:
        raise HTTPException(404, "Device not found")
    if doc.to_dict().get("owner_id") != user["sub"]:
        raise HTTPException(403, "Forbidden")
    ref = db.collection(COL_THRESHOLDS).document()
    data = t.dict()
    data["id"] = ref.id
    ref.set(data)
    return Threshold(**data)


# PUBLIC_INTERFACE
@app.get("/thresholds", response_model=List[Threshold], summary="List thresholds for my devices", tags=["Thresholds"])
def list_thresholds(user=Depends(get_current_user)):
    """List all thresholds belonging to the authenticated user based on their devices."""
    db = _init_firestore_if_needed()
    if db is None:
        return []
    my_devs = [d.id for d in db.collection(COL_DEVICES).where("owner_id", "==", user["sub"]).stream()]
    if not my_devs:
        return []
    out: List[Threshold] = []
    for dev_id in my_devs:
        cur = db.collection(COL_THRESHOLDS).where("device_id", "==", dev_id).stream()
        for tdoc in cur:
            out.append(Threshold(**tdoc.to_dict()))
    return out


# PUBLIC_INTERFACE
@app.patch("/thresholds/{threshold_id}", response_model=Threshold, summary="Update threshold", tags=["Thresholds"])
def update_threshold(threshold_id: str, t: Threshold, user=Depends(get_current_user)):
    """Update threshold rule; the payload replaces fields provided."""
    db = _init_firestore_if_needed()
    if db is None:
        raise HTTPException(404, "Threshold not found")
    ref = db.collection(COL_THRESHOLDS).document(threshold_id)
    doc = ref.get()
    if not doc.exists:
        raise HTTPException(404, "Threshold not found")
    cur = doc.to_dict()
    # verify ownership via device
    dev = db.collection(COL_DEVICES).document(cur["device_id"]).get()
    if not dev.exists or dev.to_dict().get("owner_id") != user["sub"]:
        raise HTTPException(403, "Forbidden")
    new_data = {k: v for k, v in t.dict().items() if v is not None and k != "id"}
    ref.update(new_data)
    cur.update(new_data)
    return Threshold(**cur)


# PUBLIC_INTERFACE
@app.delete("/thresholds/{threshold_id}", summary="Delete threshold", tags=["Thresholds"])
def delete_threshold(threshold_id: str, user=Depends(get_current_user)):
    """Delete threshold rule."""
    db = _init_firestore_if_needed()
    if db is None:
        raise HTTPException(404, "Threshold not found")
    ref = db.collection(COL_THRESHOLDS).document(threshold_id)
    doc = ref.get()
    if not doc.exists:
        raise HTTPException(404, "Threshold not found")
    cur = doc.to_dict()
    dev = db.collection(COL_DEVICES).document(cur["device_id"]).get()
    if not dev.exists or dev.to_dict().get("owner_id") != user["sub"]:
        raise HTTPException(403, "Forbidden")
    ref.delete()
    return {"status": "deleted"}


# Alerts
# PUBLIC_INTERFACE
@app.get("/alerts/{device_id}", response_model=List[AlertOut], summary="Get device alerts", tags=["Alerts"])
def get_alerts(device_id: str, user=Depends(get_current_user)):
    """Get alerts for a device."""
    db = _init_firestore_if_needed()
    if db is None:
        return []
    dev = db.collection(COL_DEVICES).document(device_id).get()
    if not dev.exists:
        raise HTTPException(404, "Device not found")
    if dev.to_dict().get("owner_id") != user["sub"]:
        raise HTTPException(403, "Forbidden")
    cur = db.collection(COL_ALERTS).where("device_id", "==", device_id).order_by("ts", direction=firestore.Query.DESCENDING).limit(200).stream()
    out: List[AlertOut] = []
    for a in cur:
        data = a.to_dict()
        out.append(
            AlertOut(
                id=a.id,
                device_id=data["device_id"],
                metric=data["metric"],
                rule_type=data["rule_type"],
                message=data["message"],
                value=float(data["value"]),
                ts=data["ts"],
            )
        )
    return out


# Payments
# PUBLIC_INTERFACE
@app.post("/payments/checkout", summary="Create checkout session", tags=["Payments"])
def payments_checkout(req: CheckoutSessionRequest, user=Depends(get_current_user)):
    """Create a checkout session for premium subscription. Use provider 'stripe' with a test price_id or 'razorpay' (stub)."""
    _init_firestore_if_needed()
    provider = req.provider.lower()
    if provider == "stripe":
        if not req.price_id:
            raise HTTPException(400, "price_id required for Stripe")
        return _create_stripe_session(req.price_id, user["sub"])
    elif provider == "razorpay":
        # For simplicity, respond with a stub indicating client should create order on frontend using keys.
        if not (RAZORPAY_KEY_ID and RAZORPAY_KEY_SECRET):
            raise HTTPException(400, "Razorpay not configured")
        return {"status": "ok", "message": "Create Razorpay order on client; webhook will update plan."}
    else:
        raise HTTPException(400, "Unsupported provider")


# PUBLIC_INTERFACE
@app.post("/payments/stripe/webhook", summary="Stripe webhook", tags=["Payments"])
async def stripe_webhook(request: Request):
    """Handle Stripe webhooks in test mode to promote users to premium on completed checkout."""
    if not stripe_sdk or not STRIPE_WEBHOOK_SECRET:
        raise HTTPException(400, "Stripe webhook not configured")
    payload = await request.body()
    sig = request.headers.get("Stripe-Signature")
    try:
        event = stripe_sdk.Webhook.construct_event(payload, sig, STRIPE_WEBHOOK_SECRET)
    except Exception as e:
        logger.error(f"Stripe webhook error: {e}")
        return JSONResponse({"error": "invalid payload"}, status_code=400)

    if event["type"] in ("checkout.session.completed", "customer.subscription.created"):
        session = event["data"]["object"]
        user_id = session.get("metadata", {}).get("user_id")
        if user_id:
            db = _init_firestore_if_needed()
            _set_user_plan(db, user_id, "premium")
            if db:
                db.collection(COL_PAYMENTS).add({"provider": "stripe", "event": event["type"], "user_id": user_id, "raw": event, "ts": datetime.now(tz=timezone.utc)})
    return {"received": True}


# PUBLIC_INTERFACE
@app.post("/payments/razorpay/webhook", summary="Razorpay webhook", tags=["Payments"])
async def razorpay_webhook(request: Request):
    """Handle Razorpay webhooks to promote users to premium upon successful payment."""
    if not RAZORPAY_KEY_SECRET:
        raise HTTPException(400, "Razorpay webhook not configured")
    body = await request.body()
    sig = request.headers.get("X-Razorpay-Signature", "")
    if not _verify_razorpay_signature(body, sig, RAZORPAY_KEY_SECRET):
        return JSONResponse({"error": "invalid signature"}, status_code=400)
    try:
        event = await request.json()
    except Exception:
        event = {}
    status_evt = event.get("event")
    payload = event.get("payload", {})
    entity = payload.get("payment", {}).get("entity", {})
    notes = entity.get("notes", {}) if isinstance(entity, dict) else {}
    user_id = notes.get("user_id")
    if status_evt == "payment.captured" and user_id:
        db = _init_firestore_if_needed()
        _set_user_plan(db, user_id, "premium")
        if db:
            db.collection(COL_PAYMENTS).add({
                "provider": "razorpay",
                "event": status_evt,
                "user_id": user_id,
                "raw": event,
                "ts": datetime.now(tz=timezone.utc)
            })
    return {"received": True}


# Docs helper: MQTT usage
# PUBLIC_INTERFACE
@app.get("/docs/mqtt", summary="MQTT usage notes", tags=["Docs"])
def mqtt_docs():
    """Information on setting up MQTT broker and publishing telemetry.

    Usage:
    - Broker: set MQTT_BROKER_HOST and MQTT_BROKER_PORT in env. Defaults to public HiveMQ broker.
    - Topic subscribed: MQTT_TOPIC env (default 'iot/demo/telemetry/#').
    - Expected payload JSON:
        {
          "device_id": "<device-id>",
          "metric": "temperature",
          "value": 23.5,
          "ts": "2024-01-01T00:00:00Z" // optional
        }
    """
    return {
        "broker_host": MQTT_BROKER_HOST,
        "broker_port": MQTT_BROKER_PORT,
        "topic": MQTT_TOPIC,
        "payload_example": {"device_id": "DEVICE_ID", "metric": "temperature", "value": 23.5, "ts": datetime.now(tz=timezone.utc).isoformat()},
    }
