const jwt = require('jsonwebtoken');
const admin = require('firebase-admin');

// JWT Auth (for email/password login)
const authenticateJWT = (req, res, next) => {
    const authHeader = req.headers.authorization;
    
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ error: 'No token provided' });
    }
    
    const token = authHeader.split(' ')[1];
    
    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.user = decoded;
        next();
    } catch (error) {
        return res.status(403).json({ error: 'Invalid token' });
    }
};

// Firebase Auth (for Google/Phone OTP login)
const authenticateFirebase = async (req, res, next) => {
    const authHeader = req.headers.authorization;
    
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ error: 'No token provided' });
    }
    
    const token = authHeader.split(' ')[1];
    
    try {
        const decodedToken = await admin.auth().verifyIdToken(token);
        req.user = {
            uid: decodedToken.uid,
            email: decodedToken.email,
            phone: decodedToken.phone_number
        };
        next();
    } catch (error) {
        return res.status(403).json({ error: 'Invalid Firebase token' });
    }
};

module.exports = { authenticateJWT, authenticateFirebase };