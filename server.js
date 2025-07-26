const express = require('express');
const path = require('path');
const fs = require('fs');
const fileUpload = require('express-fileupload');
const Database = require('better-sqlite3');
const bcrypt = require('bcrypt');
const session = require('express-session');
const SQLiteStore = require('connect-sqlite3')(session);

// 初始化
const app = express();
const PORT = 3000;
const db = new Database('files.db');

// 存储限制配置
const MAX_TOTAL_SIZE = 20 * 1024 * 1024 * 1024; // 系统总空间20GB
const MAX_SINGLE_FILE_SIZE = 200 * 1024 * 1024; // 单文件最大200MB
const DEFAULT_USER_QUOTA = 2 * 1024 * 1024 * 1024; // 默认用户配额2GB

// 确保上传目录存在
const uploadDir = path.join(__dirname, 'public', 'uploads');
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir, { recursive: true });
}

// 数据库初始化
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    is_admin BOOLEAN DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );
  
  CREATE TABLE IF NOT EXISTS user_quota (
    user_id INTEGER PRIMARY KEY,
    quota INTEGER NOT NULL DEFAULT ${DEFAULT_USER_QUOTA},
    FOREIGN KEY(user_id) REFERENCES users(id)
  );
  
  CREATE TABLE IF NOT EXISTS files (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    path TEXT NOT NULL,
    size INTEGER NOT NULL,
    user_id INTEGER NOT NULL,
    upload_time DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(user_id) REFERENCES users(id)
  );
`);

// 创建默认管理员账户
const adminCheck = db.prepare('SELECT * FROM users WHERE username = ?').get('admin');
if (!adminCheck) {
  const hashedPassword = bcrypt.hashSync('admin123', 10);
  db.prepare('INSERT INTO users (username, password, is_admin) VALUES (?, ?, ?)')
    .run('admin', hashedPassword, 1);
  const adminId = db.prepare('SELECT last_insert_rowid() as id').get().id;
  db.prepare('INSERT INTO user_quota (user_id, quota) VALUES (?, ?)')
    .run(adminId, 5 * 1024 * 1024 * 1024); // 管理员5GB配额
  console.log('已创建默认管理员账户: admin/admin123');
}

// 中间件
app.use(express.static('public'));
app.use(express.urlencoded({ extended: true }));
app.use(fileUpload({
  limits: { fileSize: MAX_SINGLE_FILE_SIZE },
  abortOnLimit: true
}));
app.use(session({
  store: new SQLiteStore({ db: 'sessions.db' }),
  secret: 'your-secret-key',
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 7 * 24 * 60 * 60 * 1000 }
}));
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// 防止页面被缓存，确保退出后不能返回
app.use((req, res, next) => {
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
  res.setHeader('Pragma', 'no-cache');
  res.setHeader('Expires', '0');
  res.setHeader('Surrogate-Control', 'no-store');
  next();
});


// 辅助函数
function formatFileSize(bytes) {
  if (bytes < 1024) return bytes + ' B';
  if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
  if (bytes < 1024 * 1024 * 1024) return (bytes / (1024 * 1024)).toFixed(1) + ' MB';
  return (bytes / (1024 * 1024 * 1024)).toFixed(1) + ' GB';
}

// 登录检查中间件
function requireLogin(req, res, next) {
  if (!req.session.user) {
    return res.redirect('/login');
  }
  next();
}

// 管理员检查中间件
function requireAdmin(req, res, next) {
  if (!req.session.user?.is_admin) {
    return res.status(403).send('无权访问');
  }
  next();
}

// 检查存储配额
function checkStorageLimit(userId, fileSize = 0) {
  const used = db.prepare(`
    SELECT COALESCE(SUM(size), 0) as total 
    FROM files 
    WHERE user_id = ?
  `).get(userId).total;
  
  const quota = db.prepare(`
    SELECT quota FROM user_quota WHERE user_id = ?
  `).get(userId)?.quota || DEFAULT_USER_QUOTA;
  
  return {
    canUpload: (used + fileSize) <= quota,
    used,
    quota,
    remaining: quota - used
  };
}

// 路由
app.get('/', requireLogin, (req, res) => {
  res.render('index', { user: req.session.user });
});

app.get('/login', (req, res) => {
  if (req.session.user) return res.redirect('/');

  res.render('login', { error: null, adminCheck: false });
});

app.post('/login', (req, res) => {
  const { username, password } = req.body;
  const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);

  if (user && bcrypt.compareSync(password, user.password)) {
    req.session.user = {
      id: user.id,
      username: user.username,
      is_admin: user.is_admin
    };
    res.redirect('/');
  } else {
    // 登录失败时也要传 adminCheck
    res.render('login', { error: '用户名或密码错误', adminCheck: false });
  }
});


app.get('/register', (req, res) => {
  if (req.session.user) return res.redirect('/');
  res.render('register', { error: null });
});

app.post('/register', (req, res) => {
  const { username, password } = req.body;

  // 用户名合法性验证：3-20个字符，必须是字母或数字
  const usernameRegex = /^[a-zA-Z0-9]{3,20}$/;
  if (!usernameRegex.test(username)) {
    return res.render('register', { error: '用户名必须为 3~20 位英文字母或数字' });
  }

  // 密码基本长度检查（可选强化）
  if (!password || password.length < 6) {
    return res.render('register', { error: '密码长度不能小于 6 位' });
  }

  // 是否已存在
  const existing = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
  if (existing) {
    return res.render('register', { error: '用户名已存在' });
  }

  // 正常注册逻辑
  const hashed = bcrypt.hashSync(password, 10);
  db.prepare('INSERT INTO users (username, password) VALUES (?, ?)').run(username, hashed);

  res.redirect('/login');
});

app.get('/logout', (req, res) => {
  req.session.destroy(err => {
    res.clearCookie('connect.sid');
    res.redirect('/login');
  });
});

app.post('/upload', requireLogin, async (req, res) => {
  if (!req.files?.file) return res.status(400).send('未选择文件');

  const file = req.files.file;
  const fileName = Buffer.from(file.name, 'latin1').toString('utf8');
  const uploadPath = path.join(__dirname, 'public', 'uploads', fileName);

  if (file.size > MAX_SINGLE_FILE_SIZE) {
    return res.status(400).send(`文件大小超过${MAX_SINGLE_FILE_SIZE/1024/1024}MB限制`);
  }

  const storageCheck = checkStorageLimit(req.session.user.id, file.size);
  if (!storageCheck.canUpload) {
    return res.status(400).send(
      `存储空间不足 (已使用 ${formatFileSize(storageCheck.used)} / 配额 ${formatFileSize(storageCheck.quota)})`
    );
  }

  try {
    await file.mv(uploadPath);
    db.prepare('INSERT INTO files (name, path, size, user_id) VALUES (?, ?, ?, ?)')
      .run(fileName, `/uploads/${fileName}`, file.size, req.session.user.id);
    res.redirect('/');
  } catch (err) {
    console.error('上传失败:', err);
    res.status(500).send('上传失败: ' + err.message);
  }
});

app.get('/api/files', requireLogin, (req, res) => {
  const files = db.prepare('SELECT * FROM files WHERE user_id = ?').all(req.session.user.id);
  res.json(files.map(file => ({
    ...file,
    url: `/download/${encodeURIComponent(file.name)}`
  })));
});

app.get('/api/user/quota', requireLogin, (req, res) => {
  const storageCheck = checkStorageLimit(req.session.user.id);
  res.json({
    used: storageCheck.used,
    quota: storageCheck.quota,
    remaining: storageCheck.remaining
  });
});

app.get('/download/:filename', requireLogin, (req, res) => {
  const fileName = decodeURIComponent(req.params.filename);
  const file = db.prepare('SELECT * FROM files WHERE name = ? AND user_id = ?')
    .get(fileName, req.session.user.id);
  
  if (!file) return res.status(404).send('文件不存在或无权访问');

  const filePath = path.join(__dirname, 'public', file.path);
  if (fs.existsSync(filePath)) {
    res.download(filePath, fileName);
  } else {
    res.status(404).send('文件不存在');
  }
});

app.post('/delete/:id', requireLogin, (req, res) => {
  const file = db.prepare('SELECT * FROM files WHERE id = ? AND user_id = ?')
    .get(req.params.id, req.session.user.id);
  
  if (!file) return res.status(404).send('文件不存在或无权访问');

  fs.unlink(path.join(__dirname, 'public', file.path), (err) => {
    if (err) console.error('删除失败:', err);
    db.prepare('DELETE FROM files WHERE id = ?').run(req.params.id);
    res.sendStatus(200);
  });
});

app.get('/admin/files', requireAdmin, (req, res) => {
  const files = db.prepare(`
    SELECT f.*, u.username 
    FROM files f
    JOIN users u ON f.user_id = u.id
  `).all();
  
  res.locals.formatFileSize = formatFileSize;
  res.render('admin', { 
    files, 
    user: req.session.user 
  });
});

// 管理员查看所有用户
app.get('/admin/users', requireAdmin, (req, res) => {
  const users = db.prepare('SELECT id, username, is_admin, created_at FROM users').all();
  res.render('admin_users', { users, user: req.session.user });
});

// 管理员删除用户
app.post('/admin/users/delete/:id', requireAdmin, (req, res) => {
  const userId = parseInt(req.params.id);
  if (userId === req.session.user.id) {
    return res.status(400).send('不能删除自己');
  }

  const targetUser = db.prepare('SELECT * FROM users WHERE id = ?').get(userId);
  if (!targetUser || targetUser.is_admin) {
    return res.status(403).send('不能删除管理员或用户不存在');
  }

  db.prepare('DELETE FROM files WHERE user_id = ?').run(userId);
  db.prepare('DELETE FROM user_quota WHERE user_id = ?').run(userId);
  db.prepare('DELETE FROM users WHERE id = ?').run(userId);
  res.redirect('/admin/users');
});


app.listen(PORT, () => {
  console.log(`服务器运行在 http://localhost:${PORT}`);
  console.log(`默认管理员账户: admin/admin123`);
});