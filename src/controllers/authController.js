const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const db = require('../database/db');

const login = async (req, res) => {
    try {
        const { username, password } = req.body;

        if (!username || !password) {
            return res.status(400).json({ message: 'Username and password are required' });
        }

        // Поиск пользователя в базе данных
        db.get('SELECT * FROM users WHERE username = ?', [username], async (err, user) => {
            if (err) {
                console.error('Database error:', err);
                return res.status(500).json({ message: 'Internal server error' });
            }

            if (!user) {
                return res.status(401).json({ message: 'Invalid credentials' });
            }

            // Проверка пароля
            const isValidPassword = await bcrypt.compare(password, user.password);
            if (!isValidPassword) {
                return res.status(401).json({ message: 'Invalid credentials' });
            }

            // Создание JWT токена
            const token = jwt.sign(
                {
                    userId: user.id,
                    username: user.username,
                    role: user.role
                },
                process.env.JWT_SECRET || 'your-secret-key',
                { expiresIn: '1h' }
            );

            // Сохранение сессии в базе данных
            const expiresAt = new Date(Date.now() + 3600000); // 1 час
            db.run(
                'INSERT INTO sessions (user_id, token, expires_at) VALUES (?, ?, ?)',
                [user.id, token, expiresAt.toISOString()],
                (err) => {
                    if (err) {
                        console.error('Error saving session:', err);
                        return res.status(500).json({ message: 'Internal server error' });
                    }

                    res.json({
                        message: 'Login successful',
                        token,
                        user: {
                            id: user.id,
                            username: user.username,
                            role: user.role
                        }
                    });
                }
            );
        });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
};

// Функция для создания первого пользователя (админа)
const createInitialAdmin = async () => {
    const adminPassword = await bcrypt.hash('admin123', 10);

    db.run(
        'INSERT OR IGNORE INTO users (username, password, role) VALUES (?, ?, ?)',
        ['admin', adminPassword, 'admin'],
        (err) => {
            if (err) {
                console.error('Error creating initial admin:', err);
            } else {
                console.log('Initial admin user created or already exists');
            }
        }
    );
};

// Создаем первого пользователя при запуске
createInitialAdmin();

module.exports = {
    login
}; 