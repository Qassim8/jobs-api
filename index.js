
const express = require('express');
const bodyParser = require('body-parser');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { users } = require('./data');

const app = express();
const PORT = 5000;
const SECRET = 'mySecretKey123';

app.use(bodyParser.json());

// ✅ Register
app.post('/api/auth/register', async (req, res) => {
  const { name, email, password } = req.body;

  if (!name || !email || !password) {
    return res.status(400).json({ message: 'Name, email and password are required' });
  }

  if (users.find(u => u.email === email)) {
    return res.status(400).json({ message: 'User already exists' });
  }

  const passwordHash = await bcrypt.hash(password, 10);
  users.push({ name, email, passwordHash, favorites: [] });

  res.status(201).json({ message: 'User registered successfully' });
});

// ✅ Login
app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ message: 'Email and password are required' });
  }

  const user = users.find(u => u.email === email);
  if (!user) return res.status(400).json({ message: 'User not found' });

  const isMatch = await bcrypt.compare(password, user.passwordHash);
  if (!isMatch) return res.status(400).json({ message: 'Incorrect password' });

  const token = jwt.sign({ email }, 'mySecretKey123', { expiresIn: '1h' });
  res.json({ message: 'Login successful', token, user: { name: user.name, email: user.email } });
});

// Middleware for auth
function authMiddleware(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ message: 'Token required' });

  try {
    const token = authHeader.split(' ')[1];
    const decoded = jwt.verify(token, SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    res.status(401).json({ message: 'Invalid token' });
  }
}

// ✅ Favorites: GET, POST, DELETE
app.route('/api/favorites')
  .get(authMiddleware, (req, res) => {
    const user = users.find(u => u.email === req.user.email);
    res.json({ favorites: user.favorites });
  })
  .post(authMiddleware, (req, res) => {
    const { item } = req.body;
    const user = users.find(u => u.email === req.user.email);

    if (!user.favorites.includes(item)) {
      user.favorites.push(item);
    }

    res.json({ message: 'Added to favorites', favorites: user.favorites });
  })
  .delete(authMiddleware, (req, res) => {
    const { item } = req.body;
    const user = users.find(u => u.email === req.user.email);
    user.favorites = user.favorites.filter(fav => fav !== item);

    res.json({ message: 'Removed from favorites', favorites: user.favorites });
  });

app.listen(PORT, () => console.log(`✅ Server running at http://localhost:${PORT}`));
