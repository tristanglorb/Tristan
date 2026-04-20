const express = require('express');
const bcrypt  = require('bcryptjs');
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

app.use(cors({ origin: true, credentials: true }));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(session({
  secret: 'CHANGE-THIS-TO-A-LONG-RANDOM-STRING',
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure: false,
    maxAge: 1000 * 60 * 60 * 24
  }
}));

function requireAuth(req, res, next) {
  if (req.session?.userId) return next();
  res.status(401).json({ error: 'Not authenticated.' });
}

app.post('/api/register', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password)
    return res.status(400).json({ error: 'Email and password are required.' });
  if (password.length < 8)
    return res.status(400).json({ error: 'Password must be at least 8 characters.' });
  const users = readUsers();
  if (users.find(u => u.email.toLowerCase() === email.toLowerCase()))
    return res.status(409).json({ error: 'An account with that email already exists.' });
  const passwordHash = await bcrypt.hash(password, 12);
  const newUser = { id: Date.now().toString(), email: email.toLowerCase(), passwordHash, createdAt: new Date().toISOString() };
  users.push(newUser);
  writeUsers(users);
  console.log(`[REGISTER] ${newUser.email}`);
  req.session.userId = newUser.id;
  req.session.email  = newUser.email;
  res.status(201).json({ message: 'Account created.', email: newUser.email });
});

app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password)
    return res.status(400).json({ error: 'Email and password are required.' });
  const users = readUsers();
  const user  = users.find(u => u.email === email.toLowerCase());
  const dummyHash = '$2a$12$dummyhashusedtopreventimingtimingattacks00000000000';
  const match = await bcrypt.compare(password, user ? user.passwordHash : dummyHash);
  if (!user || !match) {
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

app.get('/dashboard', requireAuth, (req, res) => {
  res.send(`<!DOCTYPE html><html><head><title>Aurum Dashboard</title>
  <link href="https://fonts.googleapis.com/css2?family=Cormorant+Garamond:wght@300&family=Josefin+Sans:wght@300;400&display=swap" rel="stylesheet">
  <style>*{box-sizing:border-box;margin:0;padding:0}body{font-family:'Josefin Sans',sans-serif;background:#0e0c09;color:#faf7f2;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:40px}.card{background:#1a1713;border:1px solid rgba(201,169,110,.2);padding:48px 56px;max-width:480px;width:100%;text-align:center}h1{font-family:'Cormorant Garamond',serif;font-size:42px;font-weight:300;color:#e8d5a3;margin-bottom:12px}p{font-size:12px;letter-spacing:.15em;text-transform:uppercase;color:#8a8070;margin-bottom:32px}span{color:#c9a96e}button{background:transparent;border:1px solid #c9a96e;color:#e8d5a3;font-family:'Josefin Sans',sans-serif;font-size:11px;letter-spacing:.3em;text-transform:uppercase;padding:14px 32px;cursor:pointer;transition:background .3s,color .3s}button:hover{background:#c9a96e;color:#0e0c09}</style>
  </head><body><div class="card"><h1>Welcome</h1><p>Signed in as <span>${req.session.email}</span></p>
  <button onclick="logout()">Sign Out</button></div>
  <script>async function logout(){await fetch('/api/logout',{method:'POST',credentials:'include'});window.location.href='/';}</script>
  </body></html>`);
});

app.get('/', (req, res) => {
  const indexPath = path.join(__dirname, 'index.html');
  if (fs.existsSync(indexPath)) {
    res.sendFile(indexPath);
  } else {
    res.send('Server is running.');
  }
});

app.listen(PORT, () => {
  console.log(`Aurum server running on port ${PORT}`);
});
