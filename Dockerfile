# Build stage
FROM node:20-alpine AS builder

WORKDIR /app

# Install build dependencies for better-sqlite3
RUN apk add --no-cache python3 make g++

# Copy package files
COPY package.json ./

# Install dependencies
RUN npm install --omit=dev

# Production stage
FROM node:20-alpine

WORKDIR /app

# Install runtime dependencies for better-sqlite3
RUN apk add --no-cache libstdc++

# Create non-root user
RUN addgroup -g 1001 -S nodejs && \
    adduser -S nodejs -u 1001

# Copy built node_modules
COPY --from=builder /app/node_modules ./node_modules

# Copy application files
COPY package.json ./
COPY src ./src
COPY public ./public

# Create data directory
RUN mkdir -p /app/data && chown -R nodejs:nodejs /app

# Switch to non-root user
USER nodejs

# Environment variables
ENV NODE_ENV=production
ENV PORT=3000
ENV DB_PATH=/app/data/2fa.db

# Expose port
EXPOSE 3000

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD wget --no-verbose --tries=1 --spider http://localhost:3000/health || exit 1

# Start application
CMD ["node", "src/server.js"]
