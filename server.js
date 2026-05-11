const express = require('express');
const app = express();
const http = require('http').createServer(app);
const io = require('socket.io')(http, {
  cors: { origin: "*", methods: ["GET", "POST"] },
  maxFileSize: 50 * 1024 * 1024 // 50MB для медиа
});
const initSqlJs = require('sql.js');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const helmet = require('helmet');
const cors = require('cors');
const fs = require('fs');
const path = require('path');
require('dotenv').config();

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'lightspeed_secret_key_2024';
const SALT_ROUNDS = 12;
const MESSAGE_LIMIT = 5000;

// Создаем папки для медиа
['uploads', 'uploads/photos', 'uploads/videos', 'uploads/voice', 'uploads/avatars'].forEach(dir => {
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
});

app.use(helmet({ 
  contentSecurityPolicy: false,
  crossOriginEmbedderPolicy: false 
}));
app.use(cors());
app.use(express.json({ limit: '50mb' }));
app.use(express.static('.'));
app.use('/uploads', express.static('uploads'));

const generateToken = (userId) => jwt.sign({ id: userId }, JWT_SECRET, { expiresIn: '7d' });
const verifyToken = (token) => {
  try { return jwt.verify(token, JWT_SECRET); } 
  catch { return null; }
};

const authenticateAPI = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  const decoded = verifyToken(token);
  if (!decoded) return res.status(401).json({ error: 'Не авторизован' });
  req.userId = decoded.id;
  next();
};

// База данных
let db;

async function initDatabase() {
  const SQL = await initSqlJs();
  
  if (fs.existsSync('lightspeed.db')) {
    db = new SQL.Database(fs.readFileSync('lightspeed.db'));
  } else {
    db = new SQL.Database();
  }
  
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      avatar_color TEXT DEFAULT '#00d4ff',
      avatar_url TEXT DEFAULT '',
      bio TEXT DEFAULT '',
      phone TEXT DEFAULT '',
      theme TEXT DEFAULT 'dark',
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      last_seen DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);
  
  db.run(`
    CREATE TABLE IF NOT EXISTS messages (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      sender_id INTEGER NOT NULL,
      receiver_id INTEGER NOT NULL,
      content TEXT NOT NULL,
      type TEXT DEFAULT 'text',
      file_url TEXT DEFAULT '',
      file_name TEXT DEFAULT '',
      file_size INTEGER DEFAULT 0,
      timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
      read_status INTEGER DEFAULT 0,
      FOREIGN KEY (sender_id) REFERENCES users(id),
      FOREIGN KEY (receiver_id) REFERENCES users(id)
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS group_chats (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      avatar_color TEXT DEFAULT '#7b2fff',
      created_by INTEGER,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS group_members (
      group_id INTEGER NOT NULL,
      user_id INTEGER NOT NULL,
      role TEXT DEFAULT 'member',
      PRIMARY KEY (group_id, user_id)
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS group_messages (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      group_id INTEGER NOT NULL,
      sender_id INTEGER NOT NULL,
      content TEXT NOT NULL,
      type TEXT DEFAULT 'text',
      file_url TEXT DEFAULT '',
      file_name TEXT DEFAULT '',
      timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);
  
  // Создаем тестовые чаты если БД пустая
  createTestChats();
  
  saveDatabase();
  setInterval(saveDatabase, 30000);
}

function createTestChats() {
  const userCount = dbGet('SELECT COUNT(*) as count FROM users');
  if (userCount.count > 0) return;
  
  // Создаем тестовых пользователей
  const testUsers = [
    { username: 'Chat_General', avatar_color: '#00d4ff', bio: 'Общий чат для всех' },
    { username: 'Tech_Support', avatar_color: '#7b2fff', bio: 'Техническая поддержка' },
    { username: 'Gaming_Zone', avatar_color: '#ff00ff', bio: 'Игровой чат' },
    { username: 'Music_Lovers', avatar_color: '#00ff88', bio: 'Музыкальное сообщество' },
    { username: 'Bot_News', avatar_color: '#ff6600', bio: 'Новости и обновления' }
  ];
  
  const hashedPassword = bcrypt.hashSync('test123', SALT_ROUNDS);
  
  testUsers.forEach(user => {
    dbRun(
      'INSERT INTO users (username, password_hash, avatar_color, bio) VALUES (?, ?, ?, ?)',
      [user.username, hashedPassword, user.avatar_color, user.bio]
    );
  });
  
  // Создаем групповые чаты
  dbRun("INSERT INTO group_chats (name, avatar_color) VALUES (?, ?)", ['💬 Общий чат', '#00d4ff']);
  dbRun("INSERT INTO group_chats (name, avatar_color) VALUES (?, ?)", ['🎮 Геймеры', '#ff00ff']);
  dbRun("INSERT INTO group_chats (name, avatar_color) VALUES (?, ?)", ['🎵 Музыка', '#00ff88']);
  dbRun("INSERT INTO group_chats (name, avatar_color) VALUES (?, ?)", ['📢 Новости', '#ff6600']);
  
  saveDatabase();
}

function saveDatabase() {
  if (db) fs.writeFileSync('lightspeed.db', Buffer.from(db.export()));
}

function dbGet(query, params = []) {
  const stmt = db.prepare(query);
  stmt.bind(params);
  if (stmt.step()) { const r = stmt.getAsObject(); stmt.free(); return r; }
  stmt.free(); return null;
}

function dbAll(query, params = []) {
  const stmt = db.prepare(query);
  stmt.bind(params);
  const results = [];
  while (stmt.step()) results.push(stmt.getAsObject());
  stmt.free(); return results;
}

function dbRun(query, params = []) {
  db.run(query, params);
  return dbGet('SELECT last_insert_rowid() as id').id;
}

// API
app.post('/api/register', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'Все поля обязательны' });
    if (username.length < 3 || username.length > 20) return res.status(400).json({ error: 'Имя 3-20 символов' });
    if (password.length < 6) return res.status(400).json({ error: 'Пароль минимум 6 символов' });
    
    if (dbGet('SELECT id FROM users WHERE username = ?', [username])) {
      return res.status(400).json({ error: 'Пользователь существует' });
    }
    
    const password_hash = await bcrypt.hash(password, SALT_ROUNDS);
    const colors = ['#00d4ff', '#7b2fff', '#ff00ff', '#00ff88', '#ff6600', '#ff3366'];
    const avatar_color = colors[Math.floor(Math.random() * colors.length)];
    
    const userId = dbRun(
      'INSERT INTO users (username, password_hash, avatar_color) VALUES (?, ?, ?)',
      [username, password_hash, avatar_color]
    );
    
    const token = generateToken(userId);
    saveDatabase();
    
    res.json({ token, user: { id: userId, username, avatar_color, bio: '', avatar_url: '' } });
  } catch (error) {
    res.status(500).json({ error: 'Ошибка сервера' });
  }
});

app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    const user = dbGet('SELECT * FROM users WHERE username = ?', [username]);
    if (!user || !(await bcrypt.compare(password, user.password_hash))) {
      return res.status(401).json({ error: 'Неверные данные' });
    }
    
    const token = generateToken(user.id);
    dbRun('UPDATE users SET last_seen = CURRENT_TIMESTAMP WHERE id = ?', [user.id]);
    
    res.json({
      token,
      user: {
        id: user.id, username: user.username,
        avatar_color: user.avatar_color, bio: user.bio || '',
        avatar_url: user.avatar_url || '', theme: user.theme || 'dark'
      }
    });
  } catch (error) {
    res.status(500).json({ error: 'Ошибка сервера' });
  }
});

app.get('/api/users', authenticateAPI, (req, res) => {
  const users = dbAll(
    'SELECT id, username, avatar_color, avatar_url, bio, last_seen FROM users WHERE id != ? ORDER BY username',
    [req.userId]
  );
  res.json({ users });
});

app.get('/api/user/:id', authenticateAPI, (req, res) => {
  const user = dbGet(
    'SELECT id, username, avatar_color, avatar_url, bio, phone, last_seen FROM users WHERE id = ?',
    [req.params.id]
  );
  if (!user) return res.status(404).json({ error: 'Не найден' });
  res.json({ user });
});

app.put('/api/profile', authenticateAPI, (req, res) => {
  const { bio, phone, theme } = req.body;
  dbRun('UPDATE users SET bio = ?, phone = ?, theme = ? WHERE id = ?', 
    [bio || '', phone || '', theme || 'dark', req.userId]);
  saveDatabase();
  res.json({ success: true });
});

app.post('/api/avatar', authenticateAPI, (req, res) => {
  const { image } = req.body;
  if (!image) return res.status(400).json({ error: 'Нет изображения' });
  
  const base64Data = image.replace(/^data:image\/\w+;base64,/, '');
  const filename = `avatar_${req.userId}_${Date.now()}.png`;
  fs.writeFileSync(`uploads/avatars/${filename}`, base64Data, 'base64');
  
  const url = `/uploads/avatars/${filename}`;
  dbRun('UPDATE users SET avatar_url = ? WHERE id = ?', [url, req.userId]);
  saveDatabase();
  
  res.json({ url });
});

app.get('/api/messages/:userId', authenticateAPI, (req, res) => {
  const messages = dbAll(`
    SELECT * FROM messages 
    WHERE (sender_id = ? AND receiver_id = ?) OR (sender_id = ? AND receiver_id = ?)
    ORDER BY timestamp ASC LIMIT 100
  `, [req.userId, req.params.userId, req.params.userId, req.userId]);
  
  dbRun('UPDATE messages SET read_status = 1 WHERE sender_id = ? AND receiver_id = ? AND read_status = 0',
    [req.params.userId, req.userId]);
  saveDatabase();
  res.json({ messages });
});

app.get('/api/unread', authenticateAPI, (req, res) => {
  const unread = dbAll(
    'SELECT sender_id, COUNT(*) as count FROM messages WHERE receiver_id = ? AND read_status = 0 GROUP BY sender_id',
    [req.userId]
  );
  res.json({ unread });
});

app.get('/api/groups', authenticateAPI, (req, res) => {
  const groups = dbAll(`
    SELECT g.*, 
      (SELECT COUNT(*) FROM group_members WHERE group_id = g.id) as members_count
    FROM group_chats g
    JOIN group_members gm ON g.id = gm.group_id
    WHERE gm.user_id = ?
  `, [req.userId]);
  res.json({ groups });
});

app.get('/api/groups/:id/messages', authenticateAPI, (req, res) => {
  const messages = dbAll(
    'SELECT gm.*, u.username, u.avatar_color, u.avatar_url FROM group_messages gm JOIN users u ON gm.sender_id = u.id WHERE gm.group_id = ? ORDER BY gm.timestamp ASC LIMIT 100',
    [req.params.id]
  );
  res.json({ messages });
});

// Загрузка файлов
app.post('/api/upload', authenticateAPI, (req, res) => {
  const { file, type } = req.body; // base64
  if (!file) return res.status(400).json({ error: 'Нет файла' });
  
  const ext = type === 'voice' ? 'webm' : type === 'video' ? 'mp4' : 'jpg';
  const folder = type === 'voice' ? 'voice' : type === 'video' ? 'videos' : 'photos';
  const filename = `${type}_${req.userId}_${Date.now()}.${ext}`;
  
  const base64Data = file.replace(/^data:.+;base64,/, '');
  fs.writeFileSync(`uploads/${folder}/${filename}`, base64Data, 'base64');
  
  res.json({ url: `/uploads/${folder}/${filename}`, filename });
});

// Socket.IO
const onlineUsers = new Map();

io.use((socket, next) => {
  const token = socket.handshake.auth.token;
  const decoded = verifyToken(token);
  if (!decoded) return next(new Error('Не авторизован'));
  
  socket.userId = decoded.id;
  const user = dbGet('SELECT username, avatar_color, avatar_url FROM users WHERE id = ?', [decoded.id]);
  if (!user) return next(new Error('Пользователь не найден'));
  
  socket.username = user.username;
  socket.avatar_color = user.avatar_color;
  socket.avatar_url = user.avatar_url;
  next();
});

io.on('connection', (socket) => {
  console.log(`✓ ${socket.username} подключился`);
  onlineUsers.set(socket.userId, socket.id);
  dbRun('UPDATE users SET last_seen = CURRENT_TIMESTAMP WHERE id = ?', [socket.userId]);
  
  io.emit('user_status', {
    userId: socket.userId, username: socket.username,
    avatar_color: socket.avatar_color, avatar_url: socket.avatar_url, online: true
  });
  
  socket.emit('online_users', Array.from(onlineUsers.keys()));
  
  socket.on('private_message', (data) => {
    const { receiverId, content, type, fileUrl, fileName } = data;
    if (!content && !fileUrl) return;
    
    const messageId = dbRun(
      'INSERT INTO messages (sender_id, receiver_id, content, type, file_url, file_name) VALUES (?, ?, ?, ?, ?, ?)',
      [socket.userId, receiverId, content || '', type || 'text', fileUrl || '', fileName || '']
    );
    
    const messageData = {
      id: messageId, sender_id: socket.userId, sender_username: socket.username,
      receiver_id: receiverId, content: content || '', type: type || 'text',
      file_url: fileUrl || '', file_name: fileName || '',
      timestamp: new Date().toISOString(), read: 0
    };
    
    socket.emit('new_message', messageData);
    const receiverSocketId = onlineUsers.get(receiverId);
    if (receiverSocketId) io.to(receiverSocketId).emit('new_message', messageData);
    
    saveDatabase();
  });
  
  socket.on('group_message', (data) => {
    const { groupId, content, type, fileUrl, fileName } = data;
    const messageId = dbRun(
      'INSERT INTO group_messages (group_id, sender_id, content, type, file_url, file_name) VALUES (?, ?, ?, ?, ?, ?)',
      [groupId, socket.userId, content || '', type || 'text', fileUrl || '', fileName || '']
    );
    
    const messageData = {
      id: messageId, group_id: groupId, sender_id: socket.userId,
      sender_username: socket.username, sender_avatar_color: socket.avatar_color,
      content, type: type || 'text', file_url: fileUrl || '', file_name: fileName || '',
      timestamp: new Date().toISOString()
    };
    
    io.emit('group_message', messageData);
    saveDatabase();
  });
  
  socket.on('join_group', (groupId) => {
    socket.join(`group_${groupId}`);
  });
  
  socket.on('typing', (data) => {
    const receiverSocketId = onlineUsers.get(data.receiverId);
    if (receiverSocketId) {
      io.to(receiverSocketId).emit('user_typing', { userId: socket.userId, username: socket.username });
    }
  });
  
  socket.on('stop_typing', (data) => {
    const receiverSocketId = onlineUsers.get(data.receiverId);
    if (receiverSocketId) {
      io.to(receiverSocketId).emit('user_stop_typing', { userId: socket.userId });
    }
  });
  
  socket.on('mark_read', (senderId) => {
    dbRun('UPDATE messages SET read_status = 1 WHERE sender_id = ? AND receiver_id = ? AND read_status = 0',
      [senderId, socket.userId]);
    saveDatabase();
  });
  
  socket.on('disconnect', () => {
    onlineUsers.delete(socket.userId);
    io.emit('user_status', { userId: socket.userId, online: false });
  });
});

async function start() {
  await initDatabase();
  http.listen(PORT, () => {
    console.log(`\n  ⚡ Light Speed Messenger 2.0 ⚡\n  http://localhost:${PORT}\n`);
  });
}

start().catch(console.error);