# Build Stage
FROM node:20-slim AS deps
WORKDIR /app
# package.jsonがない状態でのビルドエラーを防ぐため、後のフェーズで作成
# COPY package*.json ./
# RUN npm ci

# Runner Stage
FROM node:20-slim AS runner
WORKDIR /app
ENV NODE_ENV=development
# ホットリロード用設定
ENV WATCHPACK_POLLING=true
EXPOSE 3000
CMD ["npm", "run", "dev", "--", "--host"]