FROM node:26-slim@sha256:14bf3eac4bf209d906d3c41256597d3ab1f926b2e93a79e9bdfe1efd32454239

# Build with the code-reviewer-pool directory as context.
WORKDIR /srv/shared
COPY shared/package.json shared/package-lock.json ./
RUN npm ci --omit=dev --ignore-scripts --no-audit --no-fund
COPY shared/*.mjs ./

WORKDIR /srv/manager
COPY manager/package.json manager/package-lock.json ./
RUN npm ci --omit=dev --ignore-scripts --no-audit --no-fund
COPY manager/*.mjs ./

EXPOSE 7780
CMD ["node", "server.mjs"]
