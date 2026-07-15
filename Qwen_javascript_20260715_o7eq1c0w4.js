require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const admin = require('firebase-admin');
const OpenAI = require('openai');
const cloudinary = require('cloudinary').v2;
const multer = require('multer');

const User = require('./models/User');
const Chat = require('./models/Chat');
const { authenticateJWT, authenticateFirebase } = require('./middleware/auth');

const app = express();

// ============ SECURITY MIDDLEWARE ============
app.use(helmet());
app.use(cors({
    origin: process.env.FRONTEND_URL || '*',
    credentials: true
}));
app.use(express.json({ limit: '10mb' }));

// Rate Limiting
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // limit each IP to 100 requests per windowMs
    message: { error: 'Too many requests, please try again later' }
});
app.use('/api/', limiter);

// ============ FIREBASE ADMIN INIT ============
if (process.env.FIREBASE_PROJECT_ID) {
    admin.initializeApp({
        credential: admin.credential.cert({
            projectId: process.env.FIREBASE_PROJECT_ID,
            clientEmail: process.env.FIREBASE_CLIENT_EMAIL,
            privateKey: process.env.FIREBASE_PRIVATE_KEY.replace(/\\n/g, '\n')
        })
    });
    console.log('✅ Firebase Admin initialized');
}

// ============ OPENAI INIT ============
const openai = new OpenAI({
    apiKey: process.env.OPENAI_API_KEY
});

// ============ CLOUDINARY INIT ============
cloudinary.config({
    cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
    api_key: process.env.CLOUDINARY_API_KEY,
    api_secret: process.env.CLOUDINARY_API_SECRET
});

const upload = multer({ storage: multer.memoryStorage() });

// ============ MONGODB CONNECTION ============
mongoose.connect(process.env.MONGO_URI)
    .then(() => console.log('✅ MongoDB connected'))
    .catch(err => console.error('❌ MongoDB error:', err));

// ============ ROUTES ============

// Health Check
app.get('/', (req, res) => {
    res.json({ status: 'ok', message: 'NexusAI Backend is running' });
});

// ---------- AUTH ROUTES ----------

// Email/Password Signup
app.post('/api/auth/signup', async (req, res) => {
    try {
        const { name, email, phone, password } = req.body;
        
        if (!name || !password) {
            return res.status(400).json({ error: 'Name and password required' });
        }
        
        // Check existing user
        const existingUser = await User.findOne({
            $or: [{ email }, { phone }]
        });
        
        if (existingUser) {
            return res.status(400).json({ error: 'User already exists' });
        }
        
        const hashedPassword = await bcrypt.hash(password, 10);
        
        const user = await User.create({
            name,
            email: email || undefined,
            phone: phone || undefined,
            password: hashedPassword
        });
        
        const token = jwt.sign(
            { id: user._id, email: user.email, phone: user.phone },
            process.env.JWT_SECRET,
            { expiresIn: '7d' }
        );
        
        res.json({
            token,
            user: {
                id: user._id,
                name: user.name,
                email: user.email,
                phone: user.phone
            }
        });
    } catch (error) {
        console.error('Signup error:', error);
        res.status(500).json({ error: 'Signup failed' });
    }
});

// Email/Password Login
app.post('/api/auth/login', async (req, res) => {
    try {
        const { identifier, password } = req.body;
        
        const user = await User.findOne({
            $or: [
                { email: identifier },
                { phone: identifier }
            ]
        });
        
        if (!user || !user.password) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }
        
        const isValid = await bcrypt.compare(password, user.password);
        if (!isValid) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }
        
        user.lastLogin = new Date();
        await user.save();
        
        const token = jwt.sign(
            { id: user._id, email: user.email, phone: user.phone },
            process.env.JWT_SECRET,
            { expiresIn: '7d' }
        );
        
        res.json({
            token,
            user: {
                id: user._id,
                name: user.name,
                email: user.email,
                phone: user.phone
            }
        });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ error: 'Login failed' });
    }
});

// Firebase Token Verification (for Google/Phone login)
app.post('/api/auth/firebase', async (req, res) => {
    try {
        const { firebaseToken, name, email, phone } = req.body;
        
        // Verify Firebase token
        const decodedToken = await admin.auth().verifyIdToken(firebaseToken);
        const firebaseUid = decodedToken.uid;
        
        // Find or create user
        let user = await User.findOne({ firebaseUid });
        
        if (!user) {
            user = await User.create({
                firebaseUid,
                name: name || decodedToken.name || 'User',
                email: email || decodedToken.email,
                phone: phone || decodedToken.phone_number
            });
        }
        
        user.lastLogin = new Date();
        await user.save();
        
        // Issue our own JWT
        const token = jwt.sign(
            { id: user._id, firebaseUid: user.firebaseUid },
            process.env.JWT_SECRET,
            { expiresIn: '7d' }
        );
        
        res.json({
            token,
            user: {
                id: user._id,
                name: user.name,
                email: user.email,
                phone: user.phone
            }
        });
    } catch (error) {
        console.error('Firebase auth error:', error);
        res.status(401).json({ error: 'Firebase authentication failed' });
    }
});

// ---------- CHAT ROUTES ----------

// AI Chat (Protected)
app.post('/api/chat', authenticateJWT, async (req, res) => {
    try {
        const { messages, sessionId } = req.body;
        
        if (!messages || !Array.isArray(messages)) {
            return res.status(400).json({ error: 'Invalid messages format' });
        }
        
        // Call OpenAI
        const completion = await openai.chat.completions.create({
            model: "gpt-4o-mini",
            messages: messages,
            temperature: 0.7,
            max_tokens: 2000
        });
        
        const reply = completion.choices[0].message.content;
        
        // Save to database
        if (sessionId && req.user.id) {
            await Chat.findOneAndUpdate(
                { sessionId, userId: req.user.id.toString() },
                {
                    $push: { 
                        messages: { 
                            $each: [
                                { role: 'user', content: messages[messages.length-1].content },
                                { role: 'assistant', content: reply }
                            ]
                        }
                    },
                    updatedAt: new Date(),
                    title: messages[0]?.content?.substring(0, 50) || 'New Chat'
                },
                { upsert: true, new: true }
            );
        }
        
        res.json({ reply });
    } catch (error) {
        console.error('Chat error:', error);
        res.status(500).json({ error: error.message || 'AI request failed' });
    }
});

// Get Chat History
app.get('/api/chats', authenticateJWT, async (req, res) => {
    try {
        const chats = await Chat.find({ userId: req.user.id.toString() })
            .sort({ updatedAt: -1 })
            .limit(50)
            .select('sessionId title updatedAt');
        
        res.json({ chats });
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch chats' });
    }
});

// Get Specific Chat
app.get('/api/chats/:sessionId', authenticateJWT, async (req, res) => {
    try {
        const chat = await Chat.findOne({
            sessionId: req.params.sessionId,
            userId: req.user.id.toString()
        });
        
        if (!chat) {
            return res.status(404).json({ error: 'Chat not found' });
        }
        
        res.json({ chat });
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch chat' });
    }
});

// ---------- IMAGE UPLOAD ----------
app.post('/api/upload', authenticateJWT, upload.single('image'), async (req, res) => {
    try {
        if (!req.file) {
            return res.status(400).json({ error: 'No file uploaded' });
        }
        
        const result = await new Promise((resolve, reject) => {
            const uploadStream = cloudinary.uploader.upload_stream(
                { 
                    folder: 'nexusai',
                    transformation: [{ width: 1024, height: 1024, crop: 'limit' }]
                },
                (error, result) => error ? reject(error) : resolve(result)
            );
            uploadStream.end(req.file.buffer);
        });
        
        res.json({ url: result.secure_url });
    } catch (error) {
        console.error('Upload error:', error);
        res.status(500).json({ error: 'Upload failed' });
    }
});

// ---------- ERROR HANDLING ----------
app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).json({ error: 'Something went wrong!' });
});

// ============ START SERVER ============
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`🚀 Server running on port ${PORT}`);
    console.log(`📍 Environment: ${process.env.NODE_ENV}`);
});