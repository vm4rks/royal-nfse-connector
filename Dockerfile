FROM node:24-bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends openssl ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --chown=node:node package.json server.mjs certificate.mjs ./
USER node
ENV NODE_ENV=production
EXPOSE 3002
CMD ["npm", "start"]
