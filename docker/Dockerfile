FROM node:22-alpine

WORKDIR /app
ENV NODE_ENV=production

COPY package*.json ./
RUN npm ci --omit=dev

COPY index.cjs ./index.cjs

EXPOSE 3001

CMD ["node", "index.cjs"]
