# IoT FastAPI Backend

This backend implements:
- MQTT telemetry ingestion (HiveMQ public broker default or local Mosquitto)
- JWT authentication
- Firestore persistence for devices, telemetry, rollups, thresholds, alerts, user plans, and payments
- Device CRUD
- Usage retrieval (raw and hourly/daily rollups)
- Threshold CRUD
- Alerts (threshold and simple anomaly detection via z-score)
- Email notifications (for premium users; optional SMTP config; can be enabled for free via PLAN_FREE_EMAIL_NOTIF)
- Payments integrations (Stripe, Razorpay) with webhooks
- Plan enforcement (free vs premium)
- Comprehensive OpenAPI docs

## Quickstart

1) Install dependencies (see requirements.txt)
2) Set environment variables (create `.env` from `.env.example` below)
3) Run: `uvicorn src.api.main:app --reload --host 0.0.0.0 --port 8000`
4) Visit OpenAPI docs at `/docs`

## Environment Variables

- JWT_SECRET, JWT_ALG (default HS256), JWT_EXP_MIN (default 60)
- FIREBASE_CRED_JSON (path to Firebase service account json), or FIREBASE_CRED_BASE64 (base64 of it)
- STRIPE_API_KEY, STRIPE_WEBHOOK_SECRET
- RAZORPAY_KEY_ID, RAZORPAY_KEY_SECRET
- EMAIL_FROM, SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS (optional for sending emails)
- MQTT_BROKER_HOST (default: broker.hivemq.com), MQTT_BROKER_PORT (default: 1883), MQTT_USERNAME, MQTT_PASSWORD
- MQTT_TOPIC (default: `iot/demo/telemetry/#`)
- SITE_URL (used in payment success/cancel URLs)
- PLAN_FREE_MAX_DEVICES (default 2), PLAN_FREE_EMAIL_NOTIF (default false)
- ROLLUP_CRON_DISABLED (default false)

### .env.example
```
JWT_SECRET=change-me
JWT_ALG=HS256
JWT_EXP_MIN=60

# Firestore
FIREBASE_CRED_JSON=/path/to/service-account.json
# or base64
# FIREBASE_CRED_BASE64=...

# Payments (Stripe)
STRIPE_API_KEY=sk_test_...
STRIPE_WEBHOOK_SECRET=whsec_...

# Payments (Razorpay)
RAZORPAY_KEY_ID=rzp_test_...
RAZORPAY_KEY_SECRET=...

# Email (SMTP)
EMAIL_FROM="IoT Backend <noreply@example.com>"
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=username
SMTP_PASS=password

# MQTT (HiveMQ public by default)
MQTT_BROKER_HOST=broker.hivemq.com
MQTT_BROKER_PORT=1883
MQTT_TOPIC=iot/demo/telemetry/#

SITE_URL=http://localhost:8000

PLAN_FREE_MAX_DEVICES=2
PLAN_FREE_EMAIL_NOTIF=false
```

## Firestore Collections

- devices: { id, owner_id, name, description, metadata, created_at }
- telemetry: { device_id, metric, value, ts }
- rollups: { device_id, ts, granularity: "hour"|"day", metrics: {metric: avg} }
- alerts: { device_id, metric, rule_type: "threshold"|"anomaly", message, value, ts }
- thresholds: { id, device_id, metric, operator, value, enabled }
- user_plans: { plan: "free"|"premium", updated_at }
- payments: { provider, event, user_id, raw, ts }

## MQTT

- The app subscribes to topic: `MQTT_TOPIC` (default: `iot/demo/telemetry/#`)
- Publish telemetry JSON with fields:
```
{
  "device_id": "<device-id>",
  "metric": "temperature",
  "value": 23.5,
  "ts": "2025-01-01T00:00:00Z" // optional
}
```
- For local Mosquitto: set `MQTT_BROKER_HOST=localhost` and run `mosquitto` with open 1883.

## JWT Auth

- POST /auth/login { email, user_id } -> token
- Use returned JWT as Bearer token for protected routes.

## Devices

- POST /devices
- GET /devices
- GET /devices/{id}
- PATCH /devices/{id}
- DELETE /devices/{id}

Free plan limit: PLAN_FREE_MAX_DEVICES devices max.

## Telemetry and Usage

- MQTT or POST /telemetry/ingest (for testing) to ingest data.
- POST /usage { device_id, metric?, start?, end?, rollup? } -> list of points
  - rollup: "hour" or "day" to compute rollups and store them.

## Thresholds

- POST /thresholds { device_id, metric, operator, value, enabled }
- GET /thresholds
- PATCH /thresholds/{id}
- DELETE /thresholds/{id}

Operators: gt, gte, lt, lte, eq, neq.

## Alerts

- GET /alerts/{device_id}
- Alerts generated on threshold breach or anomaly (|z| >= 3) based on recent values.

## Email Notifications

- Premium plan users receive email notifications on alerts (if SMTP configured).
- You can allow email for free via PLAN_FREE_EMAIL_NOTIF=true.

## Payments

- POST /payments/checkout { provider: "stripe"| "razorpay", price_id? }
  - For Stripe: provide test price_id, server returns checkout session URL.
  - For Razorpay: stub response; use client SDK to create order and include user_id in notes for webhook.
- POST /payments/stripe/webhook
- POST /payments/razorpay/webhook

On successful payment, user plan is set to premium.

## OpenAPI

- Visit /docs for complete API. See /docs/mqtt for MQTT usage notes.

## Development Notes

- App starts even if optional SDKs aren't installed; features requiring them will return friendly errors.
- Ensure Firebase Admin SDK and credentials are provided to enable persistence.
- For production, set secure JWT secret and configure HTTPS.
