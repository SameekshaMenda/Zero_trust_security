const jwt = require('jsonwebtoken');

const generateToken = (user) => {
  return jwt.sign(
    {
      username: user.username,
      role: user.role
    },
    process.env.JWT_SECRET,
    { expiresIn: '5m' }
  );
};

const verifyToken = (token) => {
  try {
    return jwt.verify(token, process.env.JWT_SECRET);
  } catch (err) {
    return null;
  }
};

const authMiddleware = (roles = []) => {
  return (req, res, next) => {
    const token = req.cookies.token;
    if (!token) return res.status(401).json({ error: 'Authorization required' });

    const decoded = verifyToken(token);
    if (!decoded) return res.status(401).json({ error: 'Invalid or expired token' });

    if (roles.length && !roles.includes(decoded.role)) {
      return res.status(403).json({ error: 'Unauthorized access' });
    }

    req.user = decoded;
    next();
  };
};

module.exports = { generateToken, verifyToken, authMiddleware };