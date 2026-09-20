FROM node:26-slim@sha256:14bf3eac4bf209d906d3c41256597d3ab1f926b2e93a79e9bdfe1efd32454239

RUN npm install -g --ignore-scripts --no-audit --no-fund @google/gemini-cli@0.60.0

WORKDIR /srv
COPY package.json package-lock.json agent_server.mjs ./
RUN npm ci --omit=dev --ignore-scripts --no-audit --no-fund

# Native Gemini MCP setup. Literal environment references expand at runtime;
# no credential is supplied to this build command or stored in the image.
RUN gemini mcp add --scope project --transport http --trust \
    --include-tools=find_remote_tools \
    --include-tools=describe_remote_tool \
    --include-tools=call_remote_tool \
    '--header=X-Sam-Authentication: Bearer ${SAM_API_TOKEN}' \
    sam-mesh '${SAM_NODE_URL}'

# GEMINI_API_KEY is injected at runtime by values.yaml.
ENV GEMINI_CLI_TRUST_WORKSPACE=true
EXPOSE 7779
CMD ["node", "agent_server.mjs"]
