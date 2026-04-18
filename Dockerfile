# ── ビルドステージ ──────────────────────────────────────────────────────────────
FROM node:20-alpine AS builder
WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY . .
RUN npm run build

# ── 実行ステージ ────────────────────────────────────────────────────────────────
FROM node:20-alpine AS runner
WORKDIR /app
ENV NODE_ENV=production

# 必要なファイルだけをコピー
COPY package*.json ./
RUN npm ci --omit=dev
COPY --from=builder /app/public ./public
COPY --from=builder /app/.next ./.next

# Cloud Run の標準ポート 8080 を開ける
EXPOSE 8080

# ポート指定なしで起動（Cloud Run の PORT 変数に従う）
CMD ["npm", "start"]