FROM node:20-alpine

WORKDIR /app

COPY package.json package-lock.json* ./
RUN npm install

COPY tsconfig.json ./
COPY src ./src

EXPOSE 4001

CMD ["npx", "tsx", "watch", "src/index.ts"]
