FROM python:3.11-slim

# Sistem bağımlılıkları
RUN apt-get update && apt-get install -y build-essential libpq-dev fonts-dejavu-core libmagic1 && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Gereksinimler
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Uygulama
COPY . .

# D2 fix: Non-root kullanıcı ile çalıştır
RUN groupadd -r appuser && useradd -r -g appuser -d /app -s /sbin/nologin appuser \
    && mkdir -p /data/uploads \
    && chown -R appuser:appuser /app /data/uploads
USER appuser

# Prod'da Uvicorn
ENV PORT=8000
EXPOSE 8000
CMD ["uvicorn", "main:app", "--host=0.0.0.0", "--port=8000", "--proxy-headers"]
