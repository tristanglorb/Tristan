const express = require('express');
const session = require('express-session');
const cors    = require('cors');
const path    = require('path');
const fs      = require('fs');

const app  = express();
const PORT = process.env.PORT || 3000;

const DB_FILE = path.join(__dirname, 'users.json');

function readUsers() {
  if (!fs.existsSync(DB_FILE)) fs.writeFileSync(DB_FILE, '[]');
  return JSON.parse(fs.readFileSync(DB_FILE, 'utf8'));
}

function writeUsers(users) {
  fs.writeFileSync(DB_FILE, JSON.stringify(users, null, 2));
}

// ── Middleware ──────────────────────────────────────────────────
app.use(cors({ origin: true, credentials: true }));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(session({
  secret: '676767676767676767',
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    maxAge: 1000 * 60 * 60 * 24   // 24 hours
  }
}));

// Serve static files (the combined HTML and any other assets)
app.use(express.static(path.join(__dirname, 'public')));

function requireAuth(req, res, next) {
  if (req.session?.userId) return next();
  res.status(401).json({ error: 'Not authenticated.' });
}

// ── AUTH ROUTES ─────────────────────────────────────────────────

app.post('/api/register', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password)
    return res.status(400).json({ error: 'Email and password are required.' });
  if (password.length < 8)
    return res.status(400).json({ error: 'Password must be at least 8 characters.' });

  const users = readUsers();
  if (users.find(u => u.email.toLowerCase() === email.toLowerCase()))
    return res.status(409).json({ error: 'An account with that email already exists.' });

  const newUser = {
    id: Date.now().toString(),
    email: email.toLowerCase(),
    password,                          // plain-text; swap for bcrypt hash in production
    createdAt: new Date().toISOString()
  };
  users.push(newUser);
  writeUsers(users);
  console.log(`[REGISTER] ${newUser.email}`);

  req.session.userId = newUser.id;
  req.session.email  = newUser.email;
  res.status(201).json({ message: 'Account created.', email: newUser.email });
});

app.post('/api/login', (req, res) => {
  const { email, password } = req.body;
  if (!email || !password)
    return res.status(400).json({ error: 'Email and password are required.' });

  const users = readUsers();
  const user  = users.find(u => u.email === email.toLowerCase());

  if (!user || user.password !== password) {
    console.log(`[LOGIN FAILED] ${email}`);
    return res.status(401).json({ error: 'Invalid email or password.' });
  }

  req.session.userId = user.id;
  req.session.email  = user.email;
  console.log(`[LOGIN] ${user.email}`);
  res.json({ message: 'Signed in.', email: user.email });
});

app.post('/api/logout', (req, res) => {
  const email = req.session?.email;
  req.session.destroy(() => {
    res.clearCookie('connect.sid');
    console.log(`[LOGOUT] ${email}`);
    res.json({ message: 'Signed out.' });
  });
});

app.get('/api/me', requireAuth, (req, res) => {
  res.json({ email: req.session.email });
});

// ── PAGE ROUTES ─────────────────────────────────────────────────

// Root — always serve the SPA (login is the first screen)
app.get('/', (req, res) => {
  const spa = path.join(__dirname, 'public', '1a3-class-server.html');
  if (fs.existsSync(spa)) {
    res.sendFile(spa);
  } else {
    res.send('Place 1a3-class-server.html inside the /public folder.');
  }
});

// /dashboard — serve SPA; the JS inside handles showing the dashboard view.
// If the user isn't authenticated we still send the SPA — the client will
// remain on the login screen because the server API calls will fail.
app.get('/dashboard', (req, res) => {
  const spa = path.join(__dirname, 'public', '1a3-class-server.html');
  if (fs.existsSync(spa)) {
    res.sendFile(spa);
  } else {
    res.redirect('/');
  }
});

// Catch-all: send the SPA for any unknown GET (allows future client-side routes)
app.get('*', (req, res) => {
  const spa = path.join(__dirname, 'public', '1a3-class-server.html');
  if (fs.existsSync(spa)) {
    res.sendFile(spa);
  } else {
    res.status(404).send('Not found.');
  }
});

// ── START ───────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`1A3 Class Server running on port ${PORT}`);
});
