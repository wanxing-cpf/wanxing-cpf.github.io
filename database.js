const Database = require('better-sqlite3');

// 连接数据库（自动创建）
const db = new Database('files.db', {
  verbose: console.log, // 调试日志
  fileMustExist: false // 自动创建数据库文件
});

// 初始化表结构
db.exec(`
  CREATE TABLE IF NOT EXISTS files (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    path TEXT NOT NULL,
    upload_time DATETIME DEFAULT CURRENT_TIMESTAMP
  )
`);

module.exports = db;