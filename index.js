const express = require("express");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const bodyParser = require("body-parser");
const cors = require('cors');
const fs = require("fs");

const app = express(); // Initialize app here
app.use(cors()); // Apply CORS middleware
app.use(bodyParser.json());

const PORT = process.env.PORT || 3000; // Railway automatically sets the PORT
const JWT_SECRET = process.env.JWT_SECRET || "default_secret"; // Secret key for JWT, use environment variable

// Functions to load and save users from/to .txt file
function loadUsers() {
  try {
    const data = fs.readFileSync("users.txt", "utf8");
    return data ? JSON.parse(data) : [];
  } catch (err) {
    // If file doesn't exist or is empty, return an empty array
    return [];
  }
}

function saveUsers(users) {
  try {
    fs.writeFileSync("users.txt", JSON.stringify(users, null, 2));
  } catch (err) {
    console.error("Error saving users:", err);
  }
}

// User registration
app.post("/register", async (req, res) => {
  const { username, password } = req.body;

  // Validate input
  if (!username || !password) {
    return res.status(400).json({ message: "Username and password are required" });
  }

  const users = loadUsers();

  // Check if user already exists
  const existingUser = users.find((user) => user.username === username);
  if (existingUser) {
    return res.status(400).json({ message: "User already exists" });
  }

  try {
    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create the user object including the registration date
    const registrationDate = new Date().toISOString();  // Get current date in ISO 8601 format
    users.push({ username, password: hashedPassword, registrationDate });

    // Save the updated users list to the file
    saveUsers(users);

    res.status(201).json({ message: "Registration successful" });
  } catch (err) {
    console.error("Error during registration:", err);
    res.status(500).json({ message: "Internal server error" });
  }
});

// User login
app.post("/login", async (req, res) => {
  const { username, password } = req.body;

  // Validate input
  if (!username || !password) {
    return res.status(400).json({ message: "Username and password are required" });
  }

  const users = loadUsers();

  // Find the user
  const user = users.find((user) => user.username === username);
  if (!user) {
    return res.status(400).json({ message: "Incorrect username" });
  }

  // Check password
  try {
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(400).json({ message: "Incorrect password" });
    }

    // Generate JWT token
    const token = jwt.sign({ username }, JWT_SECRET, { expiresIn: "1h" });
    res.json({ message: "Login successful", token });
  } catch (err) {
    console.error("Error during login:", err);
    res.status(500).json({ message: "Internal server error" });
  }
});

// Protected endpoint (accessible only with a valid token)
app.get("/protected", (req, res) => {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) {
    return res.status(401).json({ message: "Token missing" });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    res.json({ message: "Access granted", user: decoded });
  } catch (err) {
    console.error("Error verifying token:", err);
    res.status(401).json({ message: "Invalid token" });
  }
});

// Start the server
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
