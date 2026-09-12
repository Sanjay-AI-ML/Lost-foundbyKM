FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    gcc \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Create necessary directories
RUN mkdir -p database

# Run migrations and create default data
RUN python manage.py migrate || true

EXPOSE 8001

HEALTHCHECK --interval=15s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://127.0.0.1:8001/ || exit 1

CMD ["gunicorn", "--bind", "0.0.0.0:8001", "--workers", "4", "--timeout", "120", "lost_found_project.wsgi:application"]
