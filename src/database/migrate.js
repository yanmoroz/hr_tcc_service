const db = require('./db');

// Создание таблицы пользователей
db.serialize(() => {
    db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    role TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

    // Создание таблицы сессий
    db.run(`CREATE TABLE IF NOT EXISTS sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    token TEXT NOT NULL,
    expires_at DATETIME NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  )`);

    // Создание индекса для быстрого поиска по токену
    db.run('CREATE INDEX IF NOT EXISTS idx_sessions_token ON sessions(token)');

    // Создание индекса для быстрого поиска по user_id
    db.run('CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id)');
});

console.log('Database migration completed');
db.close(); 