require('dotenv').config({ path: __dirname + '/.env' });
const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const cors = require('cors');
const morgan = require('morgan');
const path = require('path');
const { v4: uuidv4 } = require('uuid');

const db = require('./models/database');
const scannerRoutes = require('./routes/scanner');
const agentRoutes = require('./routes/agents');
const securityRoutes = require('./routes/security');

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
  cors: { origin: '*', methods: ['GET', 'POST'] }
});

const PORT = process.env.PORT || 3001;

// Middleware
app.use(cors());
app.use(express.json());
app.use(morgan('dev'));

// Serve static frontend in production
const frontendPath = path.join(__dirname, '..', 'frontend', 'build');
app.use(express.static(frontendPath));

// Make io accessible in routes
app.set('io', io);

// Routes
app.use('/api/scanner', scannerRoutes);
app.use('/api/agents', agentRoutes);
app.use('/api/security', securityRoutes);

// Health check
app.get('/api/health', (req, res) => {
  res.json({
    status: 'ok',
    version: '1.0.0',
    uptime: process.uptime(),
    scans_today: db.prepare(
      "SELECT COUNT(*) as count FROM scans WHERE date(created_at, 'unixepoch') = date('now')"
    ).get()
  });
});

// Socket.io connection handling
io.on('connection', (socket) => {
  console.log(`Client connected: ${socket.id}`);

  socket.on('subscribe:scan', (scanId) => {
    socket.join(`scan:${scanId}`);
  });

  socket.on('disconnect', () => {
    console.log(`Client disconnected: ${socket.id}`);
  });
});

// Seed default API key if none exists
const existingKeys = db.prepare('SELECT COUNT(*) as count FROM api_keys').get();
if (existingKeys.count === 0) {
  const defaultKey = 'rw-' + uuidv4().replace(/-/g, '').substring(0, 16);
  db.prepare('INSERT INTO api_keys (key, name) VALUES (?, ?)').run(defaultKey, 'default');
  console.log(`Default API key created: ${defaultKey}`);
}

server.listen(PORT, () => {
  console.log(`RugWatch backend running on port ${PORT}`);
  console.log(`WebSocket ready for real-time updates`);
});
