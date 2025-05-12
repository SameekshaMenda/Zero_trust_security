const express = require('express');
const bcrypt = require('bcryptjs');
const { generateToken } = require('../utils/auth');
const { verifyTOTP } = require('../utils/otp');
const { generateForUser, generateQRCode } = require('../utils/qr');
const User = require('../models/User');

const router = express.Router();

// Register
router.post('/register', async (req, res) => {
  try {
    const { username, password } = req.body;
    
    if (!username || !password) {
      return res.status(400).json({ error: 'Username and password required' });
    }

    if (await User.findOne({ username })) {
      return res.status(400).json({ error: 'User already exists' });
    }

    const { secret, qrImage } = await generateForUser(username);

    const user = new User({
      username,
      passwordHash: bcrypt.hashSync(password, 10),
      mfaSecret: secret,
      role: 'user'
    });

    await user.save();

    res.status(201).json({
      message: 'User registered successfully',
      mfa_secret: secret,
      qr_code: qrImage
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Login
router.post('/login', async (req, res) => {
  try {
    const { username, password, otp } = req.body;
    
    if (!username || !password || !otp) {
      return res.status(400).json({ error: 'Username, password and OTP required' });
    }

    const user = await User.findOne({ username });
    if (!user || !bcrypt.compareSync(password, user.passwordHash)) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    if (!verifyTOTP(user.mfaSecret, otp)) {
      return res.status(401).json({ error: 'Invalid OTP' });
    }

    const token = generateToken(user);

    res.cookie('token', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 300000 // 5 minutes
    }).json({
      message: 'Login successful',
      role: user.role,
      redirect: user.role === 'admin' ? '/admin-dashboard' : '/user-dashboard'
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// QR Code by username
router.get('/qr/:username', async (req, res) => {
  try {
    const user = await User.findOne({ username: req.params.username });
    if (!user) return res.status(404).json({ error: 'User not found' });

    const qrImage = await generateQRCode(user.mfaSecret, user.username);
    const base64Data = qrImage.replace(/^data:image\/png;base64,/, '');
    const img = Buffer.from(base64Data, 'base64');

    res.writeHead(200, {
      'Content-Type': 'image/png',
      'Content-Length': img.length
    });
    res.end(img);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Protected route example
router.get('/protected', (req, res) => {
  const token = req.cookies.token;
  if (!token) return res.status(401).json({ error: 'Token missing' });

  const decoded = verifyToken(token);
  if (!decoded) return res.status(401).json({ error: 'Invalid token' });

  res.json({ message: 'Access granted', user: decoded });
});

// Logout
router.post('/logout', (req, res) => {
  res.clearCookie('token').json({ message: 'Logged out successfully' });
});

module.exports = router;