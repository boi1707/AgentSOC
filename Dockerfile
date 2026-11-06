FROM node:22-alpine AS console
WORKDIR /console
COPY frontend/package*.json ./
RUN npm ci
COPY frontend/ ./
RUN npm run build

FROM python:3.12-slim
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends openssh-client \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --uid 10001 --create-home soc \
    && mkdir /app/data && chown soc:soc /app/data
COPY requirements.lock .
RUN pip install --no-cache-dir -r requirements.lock
COPY src ./src
COPY scripts ./scripts
COPY datasets/demo.jsonl ./datasets/demo.jsonl
COPY --from=console /console/dist ./frontend/dist
USER soc
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=3)"
CMD ["uvicorn", "src.api.main:app", "--host", "0.0.0.0", "--port", "8000", "--no-access-log"]
