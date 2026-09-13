FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install Python requirements
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt "firebase-admin>=6.9.0"

# Copy application source
COPY . .

# Create reports and data directories
RUN mkdir -p reports data
ENV TRACEMAIL_FEEDBACK_STORE=/var/data/tracemail/user_feedback.jsonl
RUN mkdir -p /var/data/tracemail && chown -R 1000:1000 /var/data/tracemail

# Default environment for container (HF Spaces and cloud hosts)
ENV HOST=0.0.0.0
ENV PORT=7860
EXPOSE 7860

CMD ["python3", "app.py"]
