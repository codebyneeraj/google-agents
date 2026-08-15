FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application source code
COPY . .

# Set environment defaults for Cloud Run
ENV PORT=8080
ENV APP_ENV=production
ENV PYTHONUNBUFFERED=1

EXPOSE 8080

CMD exec uvicorn src.gateway.server:app --host 0.0.0.0 --port ${PORT}
