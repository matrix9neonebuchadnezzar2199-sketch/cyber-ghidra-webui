FROM node:20-slim
WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci

COPY . .

ENV NODE_ENV=development
ENV WATCHPACK_POLLING=true
EXPOSE 3000

CMD ["npm", "run", "dev", "--", "--host"]
