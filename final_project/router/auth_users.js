const express = require('express');
const jwt = require('jsonwebtoken');
let books = require("./booksdb.js");
const regd_users = express.Router();

let users = [
  {
    username: "mihir",
    password: "1234"
  }
];


// ✅ Check if username is already taken
const isValid = (username) => {
  return users.some(user => user.username === username);
};

// ✅ Check if user credentials are correct
const authenticatedUser = (username, password) => {
  return users.some(user => user.username === username && user.password === password);
};

// ✅ Task 7: Login Route
regd_users.post("/login", (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ message: "Username and password required" });
  }

  if (!authenticatedUser(username, password)) {
    return res.status(401).json({ message: "Invalid credentials" });
  }

  const accessToken = jwt.sign({ username }, 'access', { expiresIn: '1h' });

  req.session.authorization = {
    accessToken,
    username
  };

  return res.status(200).json({ message: "Login successful", accessToken });
});

// ✅ Task 8: Add/Modify Book Review
regd_users.put("/auth/review/:isbn", (req, res) => {
  const isbn = req.params.isbn;
  const review = req.query.review;

  const username = req.session.authorization?.username;
  if (!username) {
    return res.status(401).json({ message: "Unauthorized" });
  }

  if (!books[isbn]) {
    return res.status(404).json({ message: "Book not found" });
  }

  if (!review) {
    return res.status(400).json({ message: "Review text is required in query" });
  }

  if (!books[isbn].reviews) {
    books[isbn].reviews = {};
  }

  books[isbn].reviews[username] = review;

  return res.status(200).json({ message: "Review added/updated", reviews: books[isbn].reviews });
});

// ✅ Task 9: Delete Book Review
regd_users.delete("/auth/review/:isbn", (req, res) => {
  const isbn = req.params.isbn;
  const username = req.session.authorization?.username;

  if (!username) {
    return res.status(401).json({ message: "Unauthorized" });
  }

  if (!books[isbn]) {
    return res.status(404).json({ message: "Book not found" });
  }

  if (books[isbn].reviews && books[isbn].reviews[username]) {
    delete books[isbn].reviews[username];
    return res.status(200).json({ message: "Review deleted", reviews: books[isbn].reviews });
  } else {
    return res.status(404).json({ message: "Review not found for user" });
  }
});

module.exports.authenticated = regd_users;
module.exports.isValid = isValid;
module.exports.users = users;
