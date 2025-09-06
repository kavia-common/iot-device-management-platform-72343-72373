#!/bin/bash
cd /home/kavia/workspace/code-generation/iot-device-management-platform-72343-72373/fastapi_backend
source venv/bin/activate
flake8 .
LINT_EXIT_CODE=$?
if [ $LINT_EXIT_CODE -ne 0 ]; then
  exit 1
fi

