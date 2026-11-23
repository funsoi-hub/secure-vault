# syntax=docker/dockerfile:1
FROM python:3.13-slim AS build
WORKDIR /build
COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

FROM python:3.13-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 VAULT_ENV=production DATABASE_URL=sqlite:////data/vault.db
# Pick up OS security fixes released since the base image was built
RUN apt-get update && apt-get upgrade -y && rm -rf /var/lib/apt/lists/*
# Run as an unprivileged user, never root
RUN groupadd --system vault && useradd --system --gid vault --home /app --shell /usr/sbin/nologin vault \
    && mkdir -p /data && chown vault:vault /data
COPY --from=build /install /usr/local
WORKDIR /app
COPY --chown=root:root app ./app
USER vault
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=3s CMD python -c "import urllib.request;urllib.request.urlopen('http://127.0.0.1:8000/healthz')"
CMD ["uvicorn", "app.main:create_app", "--factory", "--host", "0.0.0.0", "--port", "8000", \
     "--proxy-headers", "--forwarded-allow-ips", "*", "--no-server-header"]
