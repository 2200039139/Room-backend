const express = require('express');
const mysql = require('mysql2');
const cors = require('cors');
const bodyParser = require('body-parser');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { OAuth2Client } = require('google-auth-library');

const app = express();
const port = 5000;

// JWT Secret (use environment variable in production)
const JWT_SECRET = 'a4bf7c0d30d87039b415c39eb5afbf3dce4933e2d12382bc04eed9557420b1b9c98c27762fff2653d0cc260dec481f698d94957dc2f3ccac856b9e6385637a5b';

// Google OAuth Client
const googleClient = new OAuth2Client('37085501976-b54lfva9uchil1jq6boc6vt4jb1bqb5d.apps.googleusercontent.com');

// Middleware
app.use(cors());
app.use(bodyParser.json());

// MySQL Connection
const db = mysql.createConnection({
  host: 'mysql-n4va.railway.internal',
  user: 'root',       // replace with your MySQL username
  password: 'gSomAHMBNTNEzgODaOXOknNWBtBEAPvU',       // replace with your MySQL password
  database: 'railway'
});

// Connect to MySQL
db.connect(err => {
  if (err) {
    console.error('Error connecting to MySQL database:', err);
    return;
  }
  console.log('Connected to MySQL database');
  
  // Create tables if they don't exist
  const createUsersTable = `
    CREATE TABLE IF NOT EXISTS users (
      id INT AUTO_INCREMENT PRIMARY KEY,
      fullName VARCHAR(255) NOT NULL,
      email VARCHAR(255) NOT NULL UNIQUE,
      password VARCHAR(255),
      googleId VARCHAR(255),
      createdAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      userId int
    )
  `;
  
  // Updated roommates table with userId foreign key
  const createRoommatesTable = `
    CREATE TABLE IF NOT EXISTS roommates (
      id INT AUTO_INCREMENT PRIMARY KEY,
      name VARCHAR(255) NOT NULL,
      userId INT NOT NULL,
      FOREIGN KEY (userId) REFERENCES users(id) ON DELETE CASCADE
    )
  `;
  
  // Updated expenses table with userId foreign key
  const createExpensesTable = `
    CREATE TABLE IF NOT EXISTS expenses (
      id INT AUTO_INCREMENT PRIMARY KEY,
      description VARCHAR(255) NOT NULL,
      amount DECIMAL(10, 2) NOT NULL,
      paidBy INT NOT NULL,
      date DATE NOT NULL,
      userId INT NOT NULL,
      FOREIGN KEY (paidBy) REFERENCES roommates(id) ON DELETE CASCADE,
      FOREIGN KEY (userId) REFERENCES users(id) ON DELETE CASCADE
    )
  `;
  
  db.query(createUsersTable, (err) => {
    if (err) console.error('Error creating users table:', err);
    else console.log('Users table ready');
  });
  
  db.query(createRoommatesTable, (err) => {
    if (err) console.error('Error creating roommates table:', err);
    else console.log('Roommates table ready');
  });
  
  db.query(createExpensesTable, (err) => {
    if (err) console.error('Error creating expenses table:', err);
    else console.log('Expenses table ready');
  });
});

// Middleware to verify JWT token
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  
  if (!token) {
    return res.status(401).json({ error: 'Access denied. No token provided.' });
  }
  
  try {
    const verified = jwt.verify(token, JWT_SECRET);
    req.user = verified;
    next();
  } catch (error) {
    res.status(403).json({ error: 'Invalid token' });
  }
};

// API Routes

// USER AUTHENTICATION ROUTES
// User Registration Endpoint
app.post('/api/users/register', async (req, res) => {
  try {
    const { fullName, email, password } = req.body;
    
    // Validate required fields
    if (!fullName || !email || !password) {
      return res.status(400).json({ error: 'Please provide all required fields' });
    }
    
    // Validate email format
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      return res.status(400).json({ error: 'Please provide a valid email address' });
    }
    
    // Validate password length
    if (password.length < 8) {
      return res.status(400).json({ error: 'Password must be at least 8 characters long' });
    }
    
    // Check if user already exists
    db.query('SELECT * FROM users WHERE email = ?', [email], async (err, results) => {
      if (err) {
        console.error('Database error:', err);
        return res.status(500).json({ error: 'Server error' });
      }
      
      if (results.length > 0) {
        return res.status(400).json({ error: 'User with this email already exists' });
      }
      
      // Hash the password
      const salt = await bcrypt.genSalt(10);
      const hashedPassword = await bcrypt.hash(password, salt);
      
      // Insert new user
      db.query(
        'INSERT INTO users (fullName, email, password) VALUES (?, ?, ?)',
        [fullName, email, hashedPassword],
        (err, result) => {
          if (err) {
            console.error('Error creating user:', err);
            return res.status(500).json({ error: 'Failed to create user' });
          }
          
          const userId = result.insertId;
          
          // Create JWT token
          const token = jwt.sign(
            { id: userId, email, fullName },
            JWT_SECRET,
            { expiresIn: '24h' }
          );
          
          // Return user data (excluding password) and token
          const user = {
            id: userId,
            fullName,
            email
          };
          
          res.status(201).json({
            message: 'User registered successfully',
            user,
            token
          });
        }
      );
    });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Google Authentication Endpoint
app.post('/api/users/google-auth', async (req, res) => {
  try {
    const { token } = req.body;
    
    if (!token) {
      return res.status(400).json({ error: 'Token is required' });
    }
    
    // Verify Google token
    const ticket = await googleClient.verifyIdToken({
      idToken: token,
      audience: '37085501976-b54lfva9uchil1jq6boc6vt4jb1bqb5d.apps.googleusercontent.com'
    });
    
    const payload = ticket.getPayload();
    const { sub: googleId, email, name } = payload;
    
    // Check if user already exists with this Google ID or email
    db.query(
      'SELECT * FROM users WHERE googleId = ? OR email = ?',
      [googleId, email],
      (err, results) => {
        if (err) {
          console.error('Database error:', err);
          return res.status(500).json({ error: 'Server error' });
        }
        
        if (results.length > 0) {
          // User exists, update Google ID if needed and log them in
          const user = results[0];
          
          // If user exists with email but not with Google ID, update their record
          if (!user.googleId) {
            db.query(
              'UPDATE users SET googleId = ? WHERE id = ?',
              [googleId, user.id],
              (err) => {
                if (err) {
                  console.error('Error updating user with Google ID:', err);
                }
              }
            );
          }
          
          // Create JWT token
          const token = jwt.sign(
            { id: user.id, email: user.email, fullName: user.fullName },
            JWT_SECRET,
            { expiresIn: '24h' }
          );
          
          // Return user data and token
          const userData = {
            id: user.id,
            fullName: user.fullName,
            email: user.email
          };
          
          return res.json({
            message: 'Login successful',
            user: userData,
            token
          });
        } else {
          // Create new user with Google data
          db.query(
            'INSERT INTO users (fullName, email, googleId) VALUES (?, ?, ?)',
            [name, email, googleId],
            (err, result) => {
              if (err) {
                console.error('Error creating user with Google data:', err);
                return res.status(500).json({ error: 'Failed to create user' });
              }
              
              const userId = result.insertId;
              
              // Create JWT token
              const token = jwt.sign(
                { id: userId, email, fullName: name },
                JWT_SECRET,
                { expiresIn: '24h' }
              );
              
              // Return user data and token
              const userData = {
                id: userId,
                fullName: name,
                email
              };
              
              res.status(201).json({
                message: 'User registered successfully with Google',
                user: userData,
                token
              });
            }
          );
        }
      }
    );
  } catch (error) {
    console.error('Google authentication error:', error);
    res.status(500).json({ error: 'Failed to authenticate with Google' });
  }
});

// User Login Endpoint
app.post('/api/users/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    // Validate required fields
    if (!email || !password) {
      return res.status(400).json({ error: 'Please provide email and password' });
    }
    
    // Find user by email
    db.query('SELECT * FROM users WHERE email = ?', [email], async (err, results) => {
      if (err) {
        console.error('Database error:', err);
        return res.status(500).json({ error: 'Server error' });
      }
      
      if (results.length === 0) {
        return res.status(401).json({ error: 'Invalid credentials' });
      }
      
      const user = results[0];
      
      // Compare passwords
      const isMatch = await bcrypt.compare(password, user.password);
      
      if (!isMatch) {
        return res.status(401).json({ error: 'Invalid credentials' });
      }
      
      // Create JWT token
      const token = jwt.sign(
        { id: user.id, email: user.email, fullName: user.fullName },
        JWT_SECRET,
        { expiresIn: '24h' }
      );
      
      // Return user data (excluding password) and token
      const userData = {
        id: user.id,
        fullName: user.fullName,
        email: user.email
      };
      
      res.json({
        message: 'Login successful',
        user: userData,
        token
      });
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Get user profile
app.get('/api/users/me', authenticateToken, (req, res) => {
  db.query('SELECT id, fullName, email FROM users WHERE id = ?', [req.user.id], (err, results) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    
    if (results.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    res.json(results[0]);
  });
});

// ROOMMATE ROUTES

// Get all roommates (filtered by logged-in user)
app.get('/api/roommates', authenticateToken, (req, res) => {
  db.query('SELECT * FROM roommates WHERE userId = ?', [req.user.id], (err, results) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    res.json(results);
  });
});

// Add a new roommate (associated with logged-in user)
app.post('/api/roommates', authenticateToken, (req, res) => {
  const { name } = req.body;
  const userId = req.user.id;
  
  if (!name || name.trim() === '') {
    return res.status(400).json({ error: 'Roommate name is required' });
  }
  
  db.query('INSERT INTO roommates (name, userId) VALUES (?, ?)', [name, userId], (err, result) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    
    const id = result.insertId;
    res.status(201).json({ id, name, userId });
  });
});

// Remove a roommate (checking ownership)
app.delete('/api/roommates/:id', authenticateToken, (req, res) => {
  const id = req.params.id;
  const userId = req.user.id;
  
  // Check if roommate belongs to this user
  db.query('SELECT * FROM roommates WHERE id = ? AND userId = ?', [id, userId], (err, results) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    
    if (results.length === 0) {
      return res.status(404).json({ error: 'Roommate not found or not authorized' });
    }
    
    // If found and authorized, delete the roommate
    db.query('DELETE FROM roommates WHERE id = ?', [id], (err, result) => {
      if (err) {
        return res.status(500).json({ error: err.message });
      }
      
      res.json({ message: 'Roommate deleted successfully' });
    });
  });
});

// EXPENSE ROUTES

// Get all expenses (filtered by logged-in user)
app.get('/api/expenses', authenticateToken, (req, res) => {
  db.query('SELECT * FROM expenses WHERE userId = ?', [req.user.id], (err, results) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    res.json(results);
  });
});

// Add a new expense (associated with logged-in user)
app.post('/api/expenses', authenticateToken, (req, res) => {
  const { description, amount, paidBy, date } = req.body;
  const userId = req.user.id;
  
  if (!description || description.trim() === '') {
    return res.status(400).json({ error: 'Description is required' });
  }
  
  if (!amount || isNaN(parseFloat(amount)) || parseFloat(amount) <= 0) {
    return res.status(400).json({ error: 'Valid amount is required' });
  }
  
  if (!paidBy) {
    return res.status(400).json({ error: 'Paid by is required' });
  }
  
  if (!date) {
    return res.status(400).json({ error: 'Date is required' });
  }
  
  // Verify that the paidBy roommate belongs to this user
  db.query('SELECT * FROM roommates WHERE id = ? AND userId = ?', [paidBy, userId], (err, results) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    
    if (results.length === 0) {
      return res.status(400).json({ error: 'Invalid roommate selected' });
    }
    
    // Insert the expense with user ID
    db.query(
      'INSERT INTO expenses (description, amount, paidBy, date, userId) VALUES (?, ?, ?, ?, ?)',
      [description, amount, paidBy, date, userId],
      (err, result) => {
        if (err) {
          return res.status(500).json({ error: err.message });
        }
        
        const id = result.insertId;
        res.status(201).json({ id, description, amount, paidBy, date, userId });
      }
    );
  });
});

// Delete an expense (checking ownership)
app.delete('/api/expenses/:id', authenticateToken, (req, res) => {
  const id = req.params.id;
  const userId = req.user.id;
  
  // Check if expense belongs to this user
  db.query('SELECT * FROM expenses WHERE id = ? AND userId = ?', [id, userId], (err, results) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    
    if (results.length === 0) {
      return res.status(404).json({ error: 'Expense not found or not authorized' });
    }
    
    // If found and authorized, delete the expense
    db.query('DELETE FROM expenses WHERE id = ?', [id], (err, result) => {
      if (err) {
        return res.status(500).json({ error: err.message });
      }
      
      res.json({ message: 'Expense deleted successfully' });
    });
  });
});
// Google Authentication Endpoint
app.post('/api/users/google-auth', async (req, res) => {
  try {
    const { token } = req.body;
    
    console.log('Received Google auth request with token:', token ? 'Token received' : 'No token');
    
    if (!token) {
      return res.status(400).json({ error: 'Token is required' });
    }
    
    try {
      // Verify Google token
      const ticket = await googleClient.verifyIdToken({
        idToken: token,
        audience: '37085501976-b54lfva9uchil1jq6boc6vt4jb1bqb5d.apps.googleusercontent.com'
      });
      
      const payload = ticket.getPayload();
      console.log('Google payload received:', payload ? 'Payload valid' : 'No payload');
      
      if (!payload) {
        return res.status(400).json({ error: 'Invalid Google token' });
      }
      
      const { sub: googleId, email, name } = payload;
      
      // Check if user already exists with this Google ID or email
      db.query(
        'SELECT * FROM users WHERE googleId = ? OR email = ?',
        [googleId, email],
        (err, results) => {
          if (err) {
            console.error('Database error:', err);
            return res.status(500).json({ error: 'Server error' });
          }
          
          if (results.length > 0) {
            // User exists, update Google ID if needed and log them in
            const user = results[0];
            
            // If user exists with email but not with Google ID, update their record
            if (!user.googleId) {
              db.query(
                'UPDATE users SET googleId = ? WHERE id = ?',
                [googleId, user.id],
                (err) => {
                  if (err) {
                    console.error('Error updating user with Google ID:', err);
                  }
                }
              );
            }
            
            // Create JWT token
            const token = jwt.sign(
              { id: user.id, email: user.email, fullName: user.fullName },
              JWT_SECRET,
              { expiresIn: '24h' }
            );
            
            // Return user data and token
            const userData = {
              id: user.id,
              fullName: user.fullName,
              email: user.email
            };
            
            return res.json({
              message: 'Login successful',
              user: userData,
              token
            });
          } else {
            // Create new user with Google data
            db.query(
              'INSERT INTO users (fullName, email, googleId) VALUES (?, ?, ?)',
              [name, email, googleId],
              (err, result) => {
                if (err) {
                  console.error('Error creating user with Google data:', err);
                  return res.status(500).json({ error: 'Failed to create user' });
                }
                
                const userId = result.insertId;
                
                // Create JWT token
                const token = jwt.sign(
                  { id: userId, email, fullName: name },
                  JWT_SECRET,
                  { expiresIn: '24h' }
                );
                
                // Return user data and token
                const userData = {
                  id: userId,
                  fullName: name,
                  email
                };
                
                res.status(201).json({
                  message: 'User registered successfully with Google',
                  user: userData,
                  token
                });
              }
            );
          }
        }
      );
    } catch (verifyError) {
      console.error('Google token verification error:', verifyError);
      return res.status(401).json({ error: 'Invalid Google token' });
    }
  } catch (error) {
    console.error('Google authentication error:', error);
    res.status(500).json({ error: 'Failed to authenticate with Google' });
  }
});


// Start server
app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
