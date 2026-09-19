FROM node:26-slim@sha256:14bf3eac4bf209d906d3c41256597d3ab1f926b2e93a79e9bdfe1efd32454239

# The review agent: Google's Gemini CLI.
RUN npm install -g --ignore-scripts --no-audit --no-fund @google/gemini-cli@0.60.0

# Build with the code-reviewer-pool directory as context.
WORKDIR /srv/shared
COPY shared/package.json shared/package-lock.json ./
RUN npm ci --omit=dev --ignore-scripts --no-audit --no-fund
COPY shared/*.mjs ./

WORKDIR /srv/reviewer
COPY reviewer/package.json reviewer/package-lock.json ./
RUN npm ci --omit=dev --ignore-scripts --no-audit --no-fund
COPY reviewer/*.mjs ./

# Supply GEMINI_API_KEY at runtime (for example, from a Kubernetes Secret).
ENV GEMINI_CLI_TRUST_WORKSPACE=true

EXPOSE 7779
CMD ["node", "review_server.mjs"]
