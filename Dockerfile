FROM node:20-slim

WORKDIR /app

# Copy package files and install
COPY backend/package*.json ./backend/
RUN cd backend && npm install --production

# Copy backend code
COPY backend/ ./backend/

# Build frontend
COPY frontend/package*.json ./frontend/
RUN cd frontend && npm install && npm run build

# Copy root files
COPY .gitignore ./

# Ensure audit log directory exists
RUN mkdir -p /app/lobstertrap

# Environment
ENV NODE_ENV=production
ENV PORT=3001
ENV AUDIT_LOG_PATH=/app/lobstertrap/audit.log
ENV POLICY_PATH=/app/lobstertrap/rugwatch_policy.yaml

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=15s \
  CMD node -e "require('http').get('http://localhost:3001/api/health', r => {process.exit(r.statusCode===200?0:1)}).on('error',()=>process.exit(1))"

EXPOSE 3001

CMD ["node", "backend/server.js"]
