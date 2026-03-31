// server.js
require('dotenv').config();
const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = process.env.PORT || 3001;
const JWT_SECRET = process.env.JWT_SECRET || 'taskpilot_secret_key_88';

app.use(cors());
app.use(express.json());

// --- MongoDB Connection ---
const MONGODB_URI = process.env.MONGODB_URI;
if (!MONGODB_URI) {
    console.error('Error: MONGODB_URI is not defined.');
    process.exit(1);
}

mongoose.connect(MONGODB_URI)
    .then(() => console.log('MongoDB connected'))
    .catch(err => { console.error('Connection error:', err); process.exit(1); });

// --- Schemas ---
const userSchema = new mongoose.Schema({
    name: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true }
});

const User = mongoose.model('User', userSchema);

const todoSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    text: { type: String, required: true },
    completed: { type: Boolean, default: false },
    list: { type: String, default: 'My Day' },
    subText: { type: String, default: '' },
    isImportant: { type: Boolean, default: false },
    color: { type: String, default: 'transparent' },
    createdAt: { type: Date, default: Date.now }
});

const Todo = mongoose.model('Todo', todoSchema);

// --- Auth Middleware ---
const auth = async (req, res, next) => {
    try {
        const token = req.header('Authorization')?.replace('Bearer ', '');
        if (!token) throw new Error();
        const decoded = jwt.verify(token, JWT_SECRET);
        req.user = await User.findById(decoded.userId);
        if (!req.user) throw new Error();
        next();
    } catch (e) {
        res.status(401).send({ error: 'Please authenticate.' });
    }
};

// --- Auth Endpoints ---
app.post('/signup', async (req, res) => {
    try {
        const { name, email, password } = req.body;
        const hashedPassword = await bcrypt.hash(password, 8);
        const user = new User({ name, email, password: hashedPassword });
        await user.save();
        const token = jwt.sign({ userId: user._id }, JWT_SECRET);
        res.status(201).send({ user: { name: user.name, email: user.email }, token });
    } catch (e) {
        res.status(400).send({ error: 'Email already exists or invalid data.' });
    }
});

app.post('/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        const user = await User.findOne({ email });
        if (!user || !(await bcrypt.compare(password, user.password))) {
            return res.status(400).send({ error: 'Invalid credentials' });
        }
        const token = jwt.sign({ userId: user._id }, JWT_SECRET);
        res.send({ user: { name: user.name, email: user.email }, token });
    } catch (e) {
        res.status(500).send();
    }
});

// --- Todo Endpoints ---
app.get('/todos/:id', auth, async (req, res) => {
    try {
        const todo = await Todo.findOne({ _id: req.params.id, userId: req.user._id });
        if (!todo) return res.status(404).json({ error: 'Not found' });
        res.json(todo);
    } catch (error) { res.status(500).json({ error: 'Failed to fetch todo' }); }
});

app.get('/todos', auth, async (req, res) => {
    try {
        const { list } = req.query;
        let query = { userId: req.user._id };
        if (list && list !== 'All') {
            if (list === 'Important') query.isImportant = true;
            else query.list = list;
        }
        // Pinned (isImportant) items first
        const todos = await Todo.find(query).sort({ isImportant: -1, completed: 1, createdAt: -1 });
        res.json(todos);
    } catch (error) { res.status(500).json({ error: 'Failed to fetch' }); }
});

app.post('/todos', auth, async (req, res) => {
    try {
        const data = { ...req.body };
        if (data.list) data.list = data.list.trim();
        const todo = new Todo({ ...data, userId: req.user._id });
        await todo.save();
        res.status(201).json(todo);
    } catch (error) { res.status(400).json({ error: 'Failed to add' }); }
});

app.put('/todos/:id', auth, async (req, res) => {
    try {
        const data = { ...req.body };
        if (data.list) data.list = data.list.trim();
        const todo = await Todo.findOneAndUpdate({ _id: req.params.id, userId: req.user._id }, data, { returnDocument: 'after' });
        if (!todo) return res.status(404).json({ error: 'Not found' });
        res.json(todo);
    } catch (error) { res.status(400).json({ error: 'Failed to update' }); }
});

app.delete('/todos/:id', auth, async (req, res) => {
    try {
        const todo = await Todo.findOneAndDelete({ _id: req.params.id, userId: req.user._id });
        if (!todo) return res.status(404).json({ error: 'Not found' });
        res.status(204).send();
    } catch (error) { res.status(500).json({ error: 'Failed to delete' }); }
});

app.get('/lists/summary', auth, async (req, res) => {
    try {
        const listCounts = await Todo.aggregate([
            { $match: { userId: req.user._id } },
            { $group: { _id: '$list', count: { $sum: 1 } } },
            { $project: { name: { $ifNull: ["$_id", "My Day"] }, count: 1, _id: 0 } }
        ]);
        const importantCount = await Todo.countDocuments({ userId: req.user._id, isImportant: true });
        const totalCount = await Todo.countDocuments({ userId: req.user._id });
        res.json({ listCounts, importantCount, totalCount, userName: req.user.name });
    } catch (error) { res.status(500).json({ error: 'Failed to fetch summary' }); }
});

const PREDEFINED_LISTS = ['My Day', 'Important', 'Planned', 'Work', 'Shopping', 'Personal', 'Learning', 'All'];

app.put('/lists/:oldName/rename', auth, async (req, res) => {
    try {
        if (PREDEFINED_LISTS.includes(req.params.oldName)) {
            return res.status(403).json({ error: 'Cannot rename predefined lists' });
        }
        const newName = req.body.newName ? req.body.newName.trim() : null;
        if (!newName) return res.status(400).json({ error: 'New name required' });
        const result = await Todo.updateMany({ userId: req.user._id, list: req.params.oldName }, { list: newName });
        res.json({ modifiedCount: result.modifiedCount });
    } catch (error) { res.status(500).json({ error: 'Internal Server Error', details: error.message }); }
});

app.delete('/lists/:name', auth, async (req, res) => {
    try {
        if (PREDEFINED_LISTS.includes(req.params.name)) {
            return res.status(403).json({ error: 'Cannot delete predefined lists' });
        }
        const result = await Todo.updateMany({ userId: req.user._id, list: req.params.name }, { list: 'My Day' });
        res.json({ modifiedCount: result.modifiedCount });
    } catch (error) { res.status(500).json({ error: 'Internal Server Error', details: error.message }); }
});

app.use(cors({
    origin: 'https://taskpilot-simple-todo-list.netlify.app/' // Replace with your actual Netlify URL
}));

// Start the server
app.listen(PORT, () => {
    console.log(`To-Do List Backend API running on http://localhost:${PORT}`);
    console.log('----------------------------------------------------');
    console.log('Frontend will connect to this server.');
    console.log('Data is now persisted in MongoDB.');
    console.log('----------------------------------------------------');
});