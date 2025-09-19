const express = require('express');
const app = express();
app.use(express.json());
require('dotenv').config();

const { Note, User } = require('./db');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { z } = require('zod');
const multer = require('multer');
const path = require('path');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const http = require('http');
const { Server } = require('socket.io'); // ✅ fixed import

const SECRET_KEY = process.env.SECRET_KEY;
const port = process.env.PORT || 3000;

// Create HTTP + Socket.io server
const server = http.createServer(app);
const io = new Server(server, {
    cors: { origin: 'http://localhost:5173' }
});

// Security
app.use(helmet());
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100,
    message: 'Too many requests, try again later'
});
app.use(limiter);

// -------------------- Middlewares --------------------

// Auth Middleware
function authMiddleware(req, res, next) {
    try {
        const authHeader = req.headers['authorization'];
        if (!authHeader) return res.status(401).json({ error: 'No token provided' });

        const token = authHeader.split(" ")[1]; // Bearer <token>
        jwt.verify(token, SECRET_KEY, (err, decoded) => {
            if (err) return res.status(403).json({ error: "Invalid Token" });
            req.user = decoded; // contains id + role
            req.userId = decoded.id; // ✅ consistency fix
            next();
        });
    } catch (err) {
        next(err);
    }
}

// Role Middleware
function requireRole(role) {
    return (req, res, next) => {
        try {
            if (!req.user || req.user.role !== role) {
                return res.status(403).json({ message: 'Forbidden: Insufficient Rights' });
            }
            next();
        } catch (err) {
            next(err);
        }
    };
}

// Admin Check (alternate)
function checkAdmin(req, res, next) {
    try {
        if (req.user && req.user.role === 'admin') {
            return next();
        }
        return res.status(403).json({ error: 'Forbidden : Admins Only' });
    } catch (err) {
        next(err);
    }
}

// -------------------- File Upload --------------------
const storage = multer.diskStorage({
    destination: (req, file, cb) => cb(null, 'uploads'),
    filename: (req, file, cb) => cb(null, Date.now() + path.extname(file.originalname))
});
const upload = multer({ storage }); // ✅ fixed missing line

// -------------------- Validation --------------------
const signupSchema = z.object({
    username: z.string().min(3, 'Username must be at least 3 characters'),
    email: z.string().email('Invalid email format'),
    password: z.string().min(6, 'Password should be at least 6 characters')
});

function validateSchema(req, res, next) {
    try {
        req.body = signupSchema.parse(req.body);
        next();
    } catch (err) {
        next(err);
    }
}

// -------------------- Routes --------------------
app.get('/', (req, res) => {
    res.send('Welcome to Al-Hadi Notes');
});

// Notes CRUD
app.post("/notes", authMiddleware, upload.single('image'), async (req, res, next) => {
    try {
        const { title, content } = req.body;
        const note = new Note({
            title,
            content,
            userId: req.userId
        });

        await note.save();
        io.emit('noteCreated', note); // socket emit

        res.status(201).json({
            note,
            message: 'Note created successfully',
            file: req.file
        });
    } catch (err) {
        next(err);
    }
});

app.get('/notes', authMiddleware, async (req, res, next) => {
    try {
        const page = parseInt(req.query.page) || 1; // ✅ fixed default
        const limit = parseInt(req.query.limit, 10) || 5; // ✅ integer
        const skip = (page - 1) * limit;
        const search = req.query.search || "";

        const notes = await Note.find({
            userId: req.userId,
            title: { $regex: search, $options: "i" }
        }).skip(skip).limit(limit);

        res.json({ page, limit, count: notes.length, notes });
    } catch (err) {
        next(err);
    }
});

app.put("/notes/:id", authMiddleware, async (req, res, next) => {
    try {
        const note = await Note.findOneAndUpdate(
            { _id: req.params.id, userId: req.userId },
            { title: req.body.title || undefined, content: req.body.content || undefined },
            { new: true }
        );
        if (!note) return res.status(404).json({ error: "Note not found" });
        res.json(note);
    } catch (err) {
        next(err);
    }
});

app.delete("/notes/:id", authMiddleware, async (req, res, next) => {
    try {
        const note = await Note.findOneAndDelete({ _id: req.params.id, userId: req.userId });
        if (!note) return res.status(404).json({ error: "Note not found" });
        res.json({ message: "Note deleted successfully" });
    } catch (err) {
        next(err);
    }
});

// Note Sharing
app.post('/notes/:id/share', authMiddleware, async (req, res, next) => {
    try {
        const { userIdToShare } = req.body;
        const note = await Note.findById(req.params.id);
        if (!note) return res.status(404).json({ message: 'Note not Found' });
        if (note.userId.toString() !== req.userId) {
            return res.status(403).json({ message: 'Not Authorized' });
        }
        note.sharedWith.push(userIdToShare);
        await note.save();
        res.json({ message: 'Note Shared Successfully' });
    } catch (err) {
        next(err);
    }
});

app.get('/shared-notes', authMiddleware, async (req, res, next) => {
    try {
        const notes = await Note.find({ sharedWith: req.userId });
        res.json(notes);
    } catch (err) {
        next(err);
    }
});

// Admin Routes
app.get('/admin/notes', authMiddleware, requireRole('admin'), async (req, res, next) => {
    try {
        const notes = await Note.find(); // ✅ fixed (was User.find)
        res.json(notes);
    } catch (err) {
        next(err);
    }
});

app.get('/admin/users', authMiddleware, checkAdmin, async (req, res, next) => {
    try {
        const allUsers = await User.find();
        res.json(allUsers);
    } catch (err) {
        next(err);
    }
});

// Auth
app.post('/signup', validateSchema, async (req, res, next) => { // ✅ apply schema
    try {
        const { username, email, password } = req.body;
        const hashedPassword = await bcrypt.hash(password, 10);
        const user = new User({ username, email, password: hashedPassword });
        await user.save();
        res.status(201).json({ message: 'User Created Successfully' });
    } catch (err) {
        next(err);
    }
});

app.post('/signin', async (req, res, next) => {
    try {
        const { email, password } = req.body;
        const user = await User.findOne({ email });
        if (!user) return res.status(401).json({ error: 'Invalid Credentials' });

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) return res.status(401).json({ error: 'Invalid Credentials' });

        const token = jwt.sign({ id: user._id, role: user.role }, SECRET_KEY, { expiresIn: "3h" });
        res.json({ token });
    } catch (err) {
        next(err);
    }
});

app.get("/profile", authMiddleware, async (req, res) => {
    const user = await User.findById(req.userId).select("-password");
    res.json(user);
});

// -------------------- Error Handler --------------------
app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).json({
        error: 'Internal Server Error',
        message: err.message
    });
});

// -------------------- Start Server --------------------
server.listen(port, () => console.log(`🚀 Server Running at Port ${port}`));
