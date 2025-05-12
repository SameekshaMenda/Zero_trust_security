const express = require('express');
const { authMiddleware } = require('../utils/auth');
const User = require('../models/User');

const router = express.Router();

// Make user admin
router.post('/make-admin', authMiddleware(['admin']), async (req, res) => {
  try {
    const { username } = req.body;
    const result = await User.updateOne(
      { username },
      { $set: { role: 'admin' } }
    );

    if (result.modifiedCount === 0) {
      return res.status(400).json({ error: 'User not found or already admin' });
    }

    res.json({ message: `User '${username}' promoted to admin` });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Admin-only endpoints
router.get('/access-hr-data', authMiddleware(['admin']), (req, res) => {
  res.json({ message: 'Accessing HR Data...' });
});

router.get('/access-admin-panel', authMiddleware(['admin']), (req, res) => {
  res.json({ message: 'Accessing Admin Panel...' });
});

router.get('/request-confidential-report', authMiddleware(), (req, res) => {
  res.json({ message: 'Requesting Confidential Report...' });
});

module.exports = router;