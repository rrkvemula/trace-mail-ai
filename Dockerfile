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

# Default port (Render/Railway will override with $PORT, default is 8899)
ENV PORT=8899
EXPOSE 8899

CMD ["python3", "app.py"]
