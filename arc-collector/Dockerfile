FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY src/ ./src/
COPY static/ ./static/
ENV PYTHONUNBUFFERED=1
CMD ["uvicorn", "src.web:app", "--host", "0.0.0.0", "--port", "8443", "--ssl-keyfile", "/certs/key.pem", "--ssl-certfile", "/certs/cert.pem"]