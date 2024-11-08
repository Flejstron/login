const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const bodyParser = require('body-parser');
const fs = require('fs');

const app = express();
app.use(bodyParser.json());

const PORT = process.env.PORT || 3000;  // Railway automaticky nastaví PORT
const JWT_SECRET = process.env.JWT_SECRET || 'default_secret';  // Tajný klíč pro JWT, použij proměnnou prostředí

// Funkce pro ukládání a načítání uživatelů z .txt souboru
function loadUsers() {
  try {
    const data = fs.readFileSync('users.txt', 'utf8');
    return data ? JSON.parse(data) : [];
  } catch (err) {
    return [];
  }
}

function saveUsers(users) {
  fs.writeFileSync('users.txt', JSON.stringify(users));
}

// Registrace uživatele
app.post('/register', async (req, res) => {
  const { username, password } = req.body;
  const users = loadUsers();

  const existingUser = users.find((user) => user.username === username);
  if (existingUser) return res.status(400).json({ message: 'Uživatel již existuje' });

  const hashedPassword = await bcrypt.hash(password, 10);
  users.push({ username, password: hashedPassword });
  saveUsers(users);

  res.status(201).json({ message: 'Úspěšná registrace' });
});

// Přihlášení uživatele
app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  const users = loadUsers();

  const user = users.find((user) => user.username === username);
  if (!user) return res.status(400).json({ message: 'Nesprávné jméno nebo heslo' });

  const isPasswordValid = await bcrypt.compare(password, user.password);
  if (!isPasswordValid) return res.status(400).json({ message: 'Nesprávné jméno nebo heslo' });

  const token = jwt.sign({ username }, JWT_SECRET, { expiresIn: '1h' });
  res.json({ message: 'Přihlášení úspěšné', token });
});

// Ochráněný endpoint (přístupný jen s platným tokenem)
app.get('/protected', (req, res) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ message: 'Token chybí' });

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    res.json({ message: 'Přístup povolen', user: decoded });
  } catch (err) {
    res.status(401).json({ message: 'Neplatný token' });
  }
});

// Start serveru
app.listen(PORT, () => {
  console.log(`Server běží na portu ${PORT}`);
});
