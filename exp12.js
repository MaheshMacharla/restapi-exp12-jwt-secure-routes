require('dotenv').config();
const express = require('express');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'change_this_to_a_strong_secret';

app.use(express.json());
app.use(cookieParser());

// fake users
const users = [
  { id: 1, username: 'mahesh', password: '12345678' },
  { id: 2, username: 'gani', password: '12345678' },
  { id: 3, username: 'harini', password: '12345678' },
];

// helper: sign token
const signToken = payload => jwt.sign(payload, JWT_SECRET, { expiresIn: '1h' });

// middleware: require login
const requireLoggedIn = (req, res, next) => {
  const auth = req.headers.authorization || '';
  const token =
    auth.startsWith('Bearer ')
      ? auth.split(' ')[1]
      : (req.cookies && req.cookies.token) || null;

  if (!token) return res.status(401).json({ error: 'Authentication required' });

  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err) return res.status(401).json({ error: 'Invalid or expired token' });
    req.user = decoded;
    next();
  });
};

// routes
app.post('/login', (req, res) => {
  const { username, password } = req.body;
  const user = users.find(
    u => u.username === username && u.password === password
  );
  if (!user) return res.status(401).json({ error: 'Invalid credentials' });

  const token = signToken({ id: user.id, username: user.username });
  res
    .cookie('token', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production'
    })
    .json({ message: 'Logged in', token });
});

app.post('/logout', (req, res) =>
  res.clearCookie('token').json({ message: 'Logged out' })
);

app.get('/public', (req, res) =>
  res.json({ message: 'This route is public' })
);

app.get('/profile', requireLoggedIn, (req, res) =>
  res.json({ message: 'Protected profile', user: req.user })
);

app.get('/admin', requireLoggedIn, (req, res) => {
  if (req.user.username !== 'alice')
    return res.status(403).json({ error: 'Forbidden: admins only' });
  res.json({ message: 'Welcome admin', user: req.user });
});

app.listen(PORT, () =>
  console.log(`✅ Server running at http://localhost:${PORT}`)
);
