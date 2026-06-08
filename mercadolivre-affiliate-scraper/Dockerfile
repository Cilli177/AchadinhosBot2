FROM node:20-slim AS build
WORKDIR /app

COPY mercadolivre-affiliate-scraper/package*.json ./
RUN npm ci

COPY mercadolivre-affiliate-scraper/. .

FROM node:20-slim AS runtime
WORKDIR /app

COPY --from=build /app .

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
       curl ca-certificates libnss3 libatk1.0-0 libatk-bridge2.0-0 libcups2 libdrm2 libxkbcommon0 libxcomposite1 libxdamage1 libxrandr2 libgbm1 libasound2 libpangocairo-1.0-0 libgtk-3-0 libxss1 libxshmfence1 fonts-liberation \
    && rm -rf /var/lib/apt/lists/*

RUN npx playwright install chromium

ENV PORT=3002
EXPOSE 3002

CMD ["node", "server.js"]
