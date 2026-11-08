FROM node:22-alpine
ENV NODE_ENV=production BARRIO_WEB_ROOT=/app/public
WORKDIR /app
COPY apps/api/package*.json ./
RUN npm install --omit=dev && npm cache clean --force
COPY apps/api/src ./src
COPY apps/prototype ./public
USER node
EXPOSE 8080
CMD ["node", "src/server.mjs"]
