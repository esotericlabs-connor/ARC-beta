FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 \
    ARC_DATA_DIR=/data

WORKDIR /app
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY src/ ./src/
COPY static/ ./static/
COPY templates/ ./templates/

VOLUME ["/data"]

CMD [
  "uvicorn",
  "src.web:app",
  "--host",
  "0.0.0.0",
  "--port",
  "8443",
  "--ssl-keyfile",
  "/certs/key.pem",
  "--ssl-certfile",
  "/certs/cert.pem"
]