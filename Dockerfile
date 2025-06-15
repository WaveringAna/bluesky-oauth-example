# syntax=docker/dockerfile:1
# ---- Build & runtime image using Bun ----
FROM oven/bun:1.1.8-slim AS runner

# Create app directory
WORKDIR /app

# Install dependencies first (leveraging Docker layer cache)
COPY package.json bun.lock* ./
RUN bun install --production

# Copy the rest of the source code
COPY . .

# Environment (override at runtime as needed)
ENV NODE_ENV=production

# The server listens on port 80 (see src/index.ts)
EXPOSE 80

# Default command - launch the Bun HTTP server
CMD ["bun", "src/index.ts"] 