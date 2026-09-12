FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install Python requirements
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application source
COPY . .

# Create reports and data directories
RUN mkdir -p reports data

# Default environment for container (HF Spaces and cloud hosts)
ENV HOST=0.0.0.0
ENV PORT=7860
EXPOSE 7860

CMD ["python3", "app.py"]
