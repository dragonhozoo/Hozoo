/**
 * WhatsApp 2026 Clone — Node.js Backend
 * Jalan: node server.js
 * Buka: http://localhost:3000
 */

const express = require('express');
const http = require('http');
const WebSocket = require('ws');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const multer = require('multer');

const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ server, path: '/ws' });

const DB_FILE = path.join(__dirname, 'wa2026.json');
const UPLOAD_DIR = path.join(__dirname, 'uploads');
if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR);

function loadDB() {
  try {
    if (fs.existsSync(DB_FILE)) return JSON.parse(fs.readFileSync(DB_FILE, 'utf8'));
  } catch (e) { console.warn('DB corrupt:', e.message); }
  return {
    users: [], chats: [], messages: [], statuses: [], calls: [],
    _nextUserId: 1, _nextChatId: 1, _nextMsgId: 1, _nextStatusId: 1, _nextCallId: 1
  };
}
let db = loadDB();
function saveDB() { fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2), 'utf8'); }

const SECRET = 'WA2026_SECRET_GANTI_INI';
function hashPassword(pw) { return crypto.createHash('sha256').update(pw + SECRET).digest('hex'); }
function generateToken(userId, email) {
  const payload = Buffer.from(JSON.stringify({ userId, email, exp: Date.now() + 7*24*60*60*1000 })).toString('base64');
  const sig = crypto.createHash('sha256').update(payload + SECRET).digest('hex');
  return payload + '.' + sig;
}
function verifyToken(token) {
  if (!token) return null;
  const parts = token.split('.');
  if (parts.length !== 2) return null;
  const expected = crypto.createHash('sha256').update(parts[0] + SECRET).digest('hex');
  if (parts[1] !== expected) return null;
  try {
    const data = JSON.parse(Buffer.from(parts[0], 'base64').toString());
    if (data.exp < Date.now()) return null;
    return data;
  } catch (e) { return null; }
}
function authMiddleware(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth || !auth.startsWith('Bearer ')) return res.status(401).json({ error: 'Unauthorized' });
  const data = verifyToken(auth.slice(7));
  if (!data) return res.status(401).json({ error: 'Invalid token' });
  req.user = data;
  next();
}

app.use(express.json({ limit: '2mb' }));
app.use(express.urlencoded({ extended: true }));
app.use('/uploads', express.static(UPLOAD_DIR));

const upload = multer({
  storage: multer.diskStorage({
    destination: (req, file, cb) => cb(null, UPLOAD_DIR),
    filename: (req, file, cb) => cb(null, Date.now() + '_' + file.originalname.replace(/[^a-zA-Z0-9._-]/g, '_'))
  }),
  limits: { fileSize: 20 * 1024 * 1024 }
});

// ==================== AUTH ====================
app.post('/api/register', (req, res) => {
  const { email, password, name } = req.body;
  if (!email || !password || !name) return res.status(400).json({ error: 'Email, password, name required' });
  if (password.length < 6) return res.status(400).json({ error: 'Password min 6 chars' });
  if (db.users.find(u => u.email === email)) return res.status(409).json({ error: 'Email already registered' });
  const user = {
    id: db._nextUserId++, email, password: hashPassword(password), name,
    status: 'Tersedia', photoURL: '', verified: false, wallpaper: '',
    createdAt: Date.now(), lastSeen: Date.now()
  };
  db.users.push(user); saveDB();
  const token = generateToken(user.id, user.email);
  res.status(201).json({ token, user: publicUser(user) });
});

app.post('/api/login', (req, res) => {
  const { email, password } = req.body;
  const user = db.users.find(u => u.email === email);
  if (!user || user.password !== hashPassword(password)) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }
  user.lastSeen = Date.now(); saveDB();
  res.json({ token: generateToken(user.id, user.email), user: publicUser(user) });
});

app.get('/api/me', authMiddleware, (req, res) => {
  const user = db.users.find(u => u.id === req.user.userId);
  if (!user) return res.status(404).json({ error: 'User not found' });
  res.json({ user: publicUser(user) });
});

function publicUser(u) {
  return {
    id: u.id, email: u.email, name: u.name, status: u.status,
    photoURL: u.photoURL, verified: !!u.verified, wallpaper: u.wallpaper || ''
  };
}

// ==================== USERS ====================
app.get('/api/users', authMiddleware, (req, res) => {
  const users = db.users.filter(u => u.id !== req.user.userId).map(publicUser);
  res.json({ users });
});

app.get('/api/users/:id', authMiddleware, (req, res) => {
  const user = db.users.find(u => u.id === Number(req.params.id));
  if (!user) return res.status(404).json({ error: 'User not found' });
  res.json({ user: publicUser(user) });
});

app.put('/api/users/profile', authMiddleware, (req, res) => {
  const user = db.users.find(u => u.id === req.user.userId);
  if (!user) return res.status(404).json({ error: 'User not found' });
  const { name, status, photoURL, verified, wallpaper } = req.body;
  if (name !== undefined) user.name = name;
  if (status !== undefined) user.status = status;
  if (photoURL !== undefined) user.photoURL = photoURL;
  if (verified !== undefined) user.verified = !!verified;
  if (wallpaper !== undefined) user.wallpaper = wallpaper;
  saveDB();
  res.json({ user: publicUser(user) });
});

// ==================== CHATS ====================
app.get('/api/chats', authMiddleware, (req, res) => {
  const uid = req.user.userId;
  const chats = db.chats
    .filter(c => c.user1_id === uid || c.user2_id === uid)
    .map(c => {
      const otherId = c.user1_id === uid ? c.user2_id : c.user1_id;
      const other = db.users.find(u => u.id === otherId) || { name: 'Unknown' };
      const msgs = db.messages.filter(m => m.chat_id === c.id);
      const last = msgs.sort((a,b) => b.created_at - a.created_at)[0];
      return {
        id: c.id, other_user_id: otherId, other_user_name: other.name,
        other_user_verified: !!other.verified,
        last_message: last ? last.text || '📎 Media' : null,
        last_message_at: last ? last.created_at : null,
        wallpaper: c.wallpaper || ''
      };
    }).sort((a,b) => (b.last_message_at || 0) - (a.last_message_at || 0));
  res.json({ chats });
});

app.post('/api/chats', authMiddleware, (req, res) => {
  const { targetEmail } = req.body;
  if (!targetEmail) return res.status(400).json({ error: 'targetEmail required' });
  const target = db.users.find(u => u.email === targetEmail);
  if (!target) return res.status(404).json({ error: 'User not found' });
  if (target.id === req.user.userId) return res.status(400).json({ error: 'Cannot chat with yourself' });
  const existing = db.chats.find(c =>
    (c.user1_id === req.user.userId && c.user2_id === target.id) ||
    (c.user1_id === target.id && c.user2_id === req.user.userId)
  );
  if (existing) return res.json({ chatId: existing.id, otherUid: target.id });
  const chat = {
    id: db._nextChatId++, user1_id: req.user.userId, user2_id: target.id,
    wallpaper: '', created_at: Date.now()
  };
  db.chats.push(chat); saveDB();
  res.status(201).json({ chatId: chat.id, otherUid: target.id });
});

app.get('/api/chats/:id/wallpaper', authMiddleware, (req, res) => {
  const chat = db.chats.find(c => c.id === Number(req.params.id));
  if (!chat) return res.status(404).json({ error: 'Chat not found' });
  res.json({ wallpaper: chat.wallpaper || '' });
});

app.put('/api/chats/:id/wallpaper', authMiddleware, (req, res) => {
  const chat = db.chats.find(c => c.id === Number(req.params.id) &&
    (c.user1_id === req.user.userId || c.user2_id === req.user.userId));
  if (!chat) return res.status(404).json({ error: 'Chat not found' });
  chat.wallpaper = req.body.wallpaper || '';
  saveDB();
  res.json({ ok: true, wallpaper: chat.wallpaper });
});

// ==================== MESSAGES ====================
app.get('/api/messages', authMiddleware, (req, res) => {
  const chatId = Number(req.query.chatId);
  if (!chatId) return res.status(400).json({ error: 'chatId required' });
  const chat = db.chats.find(c => c.id === chatId &&
    (c.user1_id === req.user.userId || c.user2_id === req.user.userId));
  if (!chat) return res.status(404).json({ error: 'Chat not found' });
  const messages = db.messages
    .filter(m => m.chat_id === chatId)
    .sort((a,b) => a.created_at - b.created_at)
    .map(m => {
      const sender = db.users.find(u => u.id === m.sender_id) || { name: 'Unknown' };
      return {
        id: m.id, text: m.text, media_url: m.media_url, media_type: m.media_type,
        media_name: m.media_name, created_at: m.created_at,
        sender_id: m.sender_id, sender_name: sender.name
      };
    });
  res.json({ messages });
});

app.post('/api/messages', authMiddleware, (req, res) => {
  const { chatId, text, media_url, media_type, media_name } = req.body;
  if (!chatId) return res.status(400).json({ error: 'chatId required' });
  if (!text && !media_url) return res.status(400).json({ error: 'text or media required' });
  const chat = db.chats.find(c => c.id === Number(chatId) &&
    (c.user1_id === req.user.userId || c.user2_id === req.user.userId));
  if (!chat) return res.status(404).json({ error: 'Chat not found' });
  const msg = {
    id: db._nextMsgId++, chat_id: Number(chatId), sender_id: req.user.userId,
    text: text || '', media_url: media_url || null, media_type: media_type || null,
    media_name: media_name || null, created_at: Date.now()
  };
  db.messages.push(msg); saveDB();
  broadcastToChat(Number(chatId), { type: 'new_message', chatId: Number(chatId), messageId: msg.id });
  res.status(201).json({ messageId: msg.id });
});

// ==================== STATUSES ====================
app.get('/api/statuses', authMiddleware, (req, res) => {
  const cutoff = Date.now() - 24 * 60 * 60 * 1000;
  const statuses = db.statuses
    .filter(s => s.createdAt > cutoff)
    .map(s => {
      const user = db.users.find(u => u.id === s.uid) || {};
      return { ...s, userName: user.name || 'Unknown', userPhoto: user.photoURL || '', verified: !!user.verified };
    });
  res.json({ statuses });
});

app.post('/api/statuses', authMiddleware, (req, res) => {
  const { mediaUrl, mediaType, caption } = req.body;
  if (!mediaUrl) return res.status(400).json({ error: 'mediaUrl required' });
  const status = {
    id: db._nextStatusId++, uid: req.user.userId,
    mediaUrl, mediaType: mediaType || 'image', caption: caption || '',
    createdAt: Date.now(), viewedBy: []
  };
  db.statuses.push(status); saveDB();
  res.status(201).json({ statusId: status.id });
});

app.post('/api/statuses/:id/view', authMiddleware, (req, res) => {
  const status = db.statuses.find(s => s.id === Number(req.params.id));
  if (!status) return res.status(404).json({ error: 'Status not found' });
  if (!status.viewedBy.includes(req.user.userId)) {
    status.viewedBy.push(req.user.userId); saveDB();
  }
  res.json({ ok: true });
});

// ==================== CALLS ====================
app.get('/api/calls', authMiddleware, (req, res) => {
  const calls = db.calls
    .filter(c => c.uid === req.user.userId)
    .sort((a,b) => b.createdAt - a.createdAt).slice(0, 50);
  res.json({ calls });
});

// ==================== UPLOAD ====================
app.post('/api/upload', authMiddleware, upload.single('file'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'file required' });
  const url = `${req.protocol}://${req.get('host')}/uploads/${req.file.filename}`;
  res.json({ url, filename: req.file.filename });
});

// ==================== WEBSOCKET ====================
const chatClients = new Map();
function broadcastToChat(chatId, data) {
  const clients = chatClients.get(Number(chatId));
  if (!clients) return;
  const msg = JSON.stringify(data);
  clients.forEach(ws => { if (ws.readyState === WebSocket.OPEN) ws.send(msg); });
}
wss.on('connection', (ws, req) => {
  const url = new URL(req.url, 'http://localhost');
  const chatId = Number(url.searchParams.get('chatId'));
  const token = url.searchParams.get('token');
  const auth = verifyToken(token);
  if (!auth) { ws.close(1008, 'Unauthorized'); return; }
  if (!chatClients.has(chatId)) chatClients.set(chatId, new Set());
  chatClients.get(chatId).add(ws);
  ws.on('close', () => {
    const set = chatClients.get(chatId);
    if (set) { set.delete(ws); if (!set.size) chatClients.delete(chatId); }
  });
  ws.send(JSON.stringify({ type: 'connected', chatId }));
});

// ==================== SERVE HTML ====================
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));

const PORT = process.env.PORT || 3000;
server.listen(PORT, '0.0.0.0', () => {
  console.log('');
  console.log('═══════════════════════════════════════');
  console.log('  WhatsApp 2026 Clone — RUNNING');
  console.log('  Local:   http://localhost:' + PORT);
  console.log('═══════════════════════════════════════');
  console.log('');
  console.log('  Publik: cloudflared tunnel --url http://localhost:' + PORT);
  console.log('  Atau:   ngrok http ' + PORT);
  console.log('');
});
