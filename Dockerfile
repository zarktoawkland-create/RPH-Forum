FROM node:18-alpine AS builder

WORKDIR /app

# Install build dependencies for better-sqlite3
RUN apk add --no-cache python3 make g++

COPY package.json ./
RUN npm install --production

# --- Production stage ---
FROM node:18-alpine

WORKDIR /app

# Copy only compiled node_modules and app files
COPY --from=builder /app/node_modules ./node_modules
COPY package.json server.js database.js ./
COPY public/ ./public/

# Create data directory for SQLite persistence
RUN mkdir -p /app/data

ENV PORT=9191
ENV HOST=0.0.0.0
ENV DATA_DIR=/app/data
ENV NODE_ENV=production

EXPOSE 9191

CMD ["node", "server.js"]
