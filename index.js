const express = require('express');
const app = express();
app.use(express.json());
require('dotenv').config();
const Note = require('./db');
const User = require('./db');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const SECRET_KEY = process.env.SECRET_KEY;
const port = process.env.PORT || 3000;


app.get('/', (req, res) => {
    res.send('Welcome to Al-Hadi Notes');
});

app.post("/notes", authMiddleware, async (req, res, next) => {
    try {
        const { title, content } = req.body;

        const note = new Note({
            title,
            content,
            userId: req.userId
        });

        await note.save();
        res.status(201).json(note);
    } catch (err) {
        next(err);
    }
});

app.get('/notes', authMiddleware, async (req, res, next) => {
    try {
        const page = parseInt(req.query.page) || 2;
        const limit = parseFloat(req.query.limit) || 5;
        const skip = (page - 1) * limit;

        const search = req.query.search || "";

        const notes = await Note.find({
            userId: req.userId,
            title: { $regex: search, $options: "i" } //for case insensitive
        }).skip(skip).limit(limit);
        res.json({ page, limit, count: notes.length, notes });
    } catch (err) {
        next(err);
    }
});


// Update
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

// Delete
app.delete("/notes/:id", authMiddleware, async (req, res, next) => {
    try {
        const note = await Note.findOneAndDelete({
            _id: req.params.id,
            userId: req.userId
        });

        if (!note) return res.status(404).json({ error: "Note not found" });
        res.json({ message: "Note deleted successfully" });
    } catch (err) {
        next(err);
    }
});


//User Routing

app.post('/signup', async (req, res, next) => {
    try {
        const { username, email, password } = req.body;
        //Hash Password
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

        const token = jwt.sign({ id: user._id }, SECRET_KEY, { expiresIn: "3h" });
        console.log(token);

        res.json({ token });

    } catch (err) {
        next();
    }
});


function authMiddleware(req, res, next) {
    try {
        const authHeader = req.headers['authorization'];
        if (!authHeader) return res.status(401).json({ error: 'No token provided' });

        const token = authHeader.split(" ")[1]; //Bearer <token>
        jwt.verify(token, SECRET_KEY, (err, decoded) => {
            if (err) return res.status(403).json({ error: "Invalid Token" });
            req.userId = decoded.id;
            next();
        });
    } catch (err) {
        next(err);
    }
}

app.get("/profile", authMiddleware, async (req, res) => {
    const user = await User.findById(req.userId).select("-password");
    res.json(user);
});


app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).json({
        error: 'Internal Server Error',
        message: err.message
    });
});
app.listen(port, () => console.log(`Server Running at Port ${port}`));