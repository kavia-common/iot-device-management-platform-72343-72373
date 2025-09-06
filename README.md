# IoT Device Management Platform

This project includes a FastAPI backend implementing:
- MQTT telemetry ingestion (HiveMQ public or local Mosquitto)
- JWT authentication
- Firestore persistence for devices, telemetry, rollups, thresholds, alerts, user plans, and payments
- Device CRUD, Usage retrieval (raw and rollups), Threshold CRUD, Alerts
- Email notifications (premium), Plan enforcement
- Payments (Stripe, Razorpay) + webhooks
- Comprehensive OpenAPI documentation

Start here:
- Backend: `fastapi_backend` folder
- Run: `uvicorn src.api.main:app --reload --host 0.0.0.0 --port 8000`
- Docs: `http://localhost:8000/docs`

See detailed setup in `fastapi_backend/README.md`.