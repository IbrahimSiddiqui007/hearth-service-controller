FROM node:22-alpine AS web
WORKDIR /build/web
COPY web/package*.json ./
RUN npm ci
COPY web/ ./
RUN npm run build

FROM python:3.13-slim
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends git && rm -rf /var/lib/apt/lists/*
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt && useradd --create-home --uid 10001 psc
COPY controller/ controller/
COPY shared/ shared/
COPY --from=web /build/web/dist web/dist
COPY web/public/favicon.svg web/public/favicon.svg
RUN mkdir -p data && chown -R psc:psc /app
USER psc
EXPOSE 8787
CMD ["python", "-m", "controller", "--host", "0.0.0.0", "--container-listener"]
