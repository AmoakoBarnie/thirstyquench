FROM python:3.11-slim

WORKDIR /app

# System deps for Pillow/openpyxl if needed
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential libmagic1 \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Data lives on a persistent Fly volume mounted at /data
ENV TQ_DATA_PATH=/data/store.json
ENV TQ_HOST=0.0.0.0

EXPOSE 8080

RUN chmod +x start.sh
CMD ["./start.sh"]
