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

// Dynamic CORS origin based on environment, fallback to '*' for dev if not set
const corsOptions = {
    origin: process.env.FRONTEND_URL ? process.env.FRONTEND_URL.split(',') : '*', // Support multiple origins
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
    allowedHeaders: ['Content-Type', 'Authorization']
};
app.use(cors(corsOptions));app.use(express.json());

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
    password: { type: String, required: true },
    tagline: { type: String, default: '' }
});

const User = mongoose.model('User', userSchema);

const todoSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    text: { type: String, required: true },
    completed: { type: Boolean, default: false },
    list: { type: String, default: 'My Day' },
    subText: { type: String, default: '' },
    isImportant: { type: Boolean, default: false },
    dueDate: { type: Date, default: null }, // New: Due date for tasks
    // Removed isArchived, tasks will be hard deleted.
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
        if (!name || !email || !password) {
            return res.status(400).send({ error: 'Name, email, and password are required.' });
        }
        if (password.length < 6) { // Example: minimum password length
            return res.status(400).send({ error: 'Password must be at least 6 characters long.' });
        }
        const hashedPassword = await bcrypt.hash(password, 8);
        const user = new User({ name, email, password: hashedPassword });
        await user.save();
        const token = jwt.sign({ userId: user._id }, JWT_SECRET);
        res.status(201).send({ user: { name: user.name, email: user.email }, token });
    } catch (e) {
        if (e.code === 11000) { // Duplicate key error
            return res.status(400).send({ error: 'Email already exists.' });
        }
        console.error('Signup error:', e);
        res.status(400).send({ error: 'Invalid data provided.' });
    }
});

app.post('/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        if (!email || !password) {
            return res.status(400).send({ error: 'Email and password are required.' });
        }
        const user = await User.findOne({ email });
        if (!user || !(await bcrypt.compare(password, user.password))) {
            return res.status(400).send({ error: 'Invalid credentials' });
        }
        const token = jwt.sign({ userId: user._id }, JWT_SECRET);
        res.send({ user: { name: user.name, email: user.email, tagline: user.tagline }, token });
    } catch (e) {
        console.error('Login error:', e);
        res.status(500).send({ error: 'An unexpected error occurred during login.' });
    }
});

app.put('/user/profile', auth, async (req, res) => {
    try {
        const { tagline } = req.body;
        req.user.tagline = tagline;
        await req.user.save();
        res.json({ tagline: req.user.tagline });
    } catch (e) {
        res.status(500).json({ error: 'Failed to update profile' });
    }
});

// --- Todo Endpoints ---
// Reordered routes: Static routes (like /search) must come before parameterized routes (like /:id)
app.get('/todos/search', auth, async (req, res) => {
    try {
        const { q } = req.query;
        if (!q || q.trim() === '') {
            // Return empty array for empty query, instead of 400, for a smoother UX
            return res.json([]);
        }

        const query = {
            userId: req.user._id,
            // Tasks with a dueDate in the past but not completed are considered 'Overdue'
            // We'll exclude archived tasks once that system is removed
            $or: [
                { text: { $regex: q, $options: 'i' } },
                { subText: { $regex: q, $options: 'i' } }
            ]
        };
        // Removed `isArchived: false` from search query; will be irrelevant after archive system removal.
        // It's generally good for search to find all current tasks, regardless of their 'list' status,
        // but not archived/deleted ones.

        const todos = await Todo.find(query)
                                .sort({ isImportant: -1, dueDate: 1, completed: 1, createdAt: -1 });
        res.json(todos);
    } catch (error) {
        console.error('Search API error:', error); // Log the actual error
        res.status(500).json({ error: 'Failed to perform search', details: error.message });
    }
});

app.get('/todos', auth, async (req, res) => {
    try {
        const { list } = req.query; 
        let query = { userId: req.user._id };

        if (list === 'Important') {
            query.isImportant = true;
            query.completed = false; // Important tasks should typically be incomplete
        } else if (list === 'Planned') {
            query.dueDate = { $ne: null }; // Tasks with a due date
            query.completed = false; // Planned tasks should typically be incomplete
        } else if (list === 'Completed') {
            query.completed = true;
        } else if (list === 'Overdue') {
            query.dueDate = { $lt: new Date() };
            query.completed = false;
        } else if (list === 'My Day') { 
            query.list = 'My Day';
            query.completed = false; // My Day generally shows incomplete tasks
        } else if (list && list !== 'All') { // For custom lists
            query.list = list;
            query.completed = false; // Custom lists generally show incomplete tasks
        }
        // If list is 'All', query remains { userId: req.user._id } to show all tasks.
        // Sorting: Important first, then by earliest due date, then incomplete, then creation date
        const todos = await Todo.find(query)
                                .sort({ isImportant: -1, dueDate: 1, completed: 1, createdAt: -1 });
        res.json(todos);
    } catch (error) { console.error('Fetch Todos API error:', error); res.status(500).json({ error: 'Failed to fetch', details: error.message }); }
});

app.get('/todos/:id', auth, async (req, res) => {
    try {
        // Validate ID format to prevent Mongoose CastError if 'search' or other words hit this route
        if (!mongoose.Types.ObjectId.isValid(req.params.id)) {
            return res.status(400).json({ error: 'Invalid Task ID format' });
        }
        const todo = await Todo.findOne({ _id: req.params.id, userId: req.user._id });
        if (!todo) return res.status(404).json({ error: 'Not found' });
        res.json(todo);
    } catch (error) { res.status(500).json({ error: 'Failed to fetch todo' }); }
});


app.post('/todos', auth, async (req, res) => {
    try {
        const { text, list, subText, isImportant, dueDate, color, completed } = req.body; // Added 'completed' for new task creation
        if (!text || text.trim() === '') {
            return res.status(400).json({ error: 'Task text is required.' });
        }
        const data = {
            text: text.trim(),
            list: list ? list.trim() : 'My Day',
            subText: subText ? subText.trim() : '',
            isImportant: isImportant || false,
            dueDate: dueDate || null,
            color: color || 'transparent',
            completed: completed || false, // Default to false if not provided
            userId: req.user._id
        };
        const todo = new Todo(data);
        await todo.save();
        res.status(201).json(todo);
    } catch (error) { console.error('Add Todo API error:', error); res.status(400).json({ error: 'Failed to add', details: error.message }); }
});

app.put('/todos/:id', auth, async (req, res) => {
    try {
        const updates = req.body;
        // Ensure list is trimmed if provided
        if (updates.list) updates.list = updates.list.trim();
        const todo = await Todo.findOneAndUpdate({ _id: req.params.id, userId: req.user._id }, updates, { new: true });
        if (!todo) return res.status(404).json({ error: 'Not found' });
        res.json(todo);
    } catch (error) { res.status(400).json({ error: 'Failed to update', details: error.message }); }
});

// DELETE /todos/:id now performs a hard delete.
app.delete('/todos/:id', auth, async (req, res) => {
    try {
        // Validate ID format to prevent Mongoose CastError
        if (!mongoose.Types.ObjectId.isValid(req.params.id)) {
            return res.status(400).json({ error: 'Invalid Task ID format' });
        }
        const todo = await Todo.findOneAndDelete({ _id: req.params.id, userId: req.user._id });
        if (!todo) {
            return res.status(404).json({ error: 'Task not found or unauthorized' });
        }
        res.status(204).send(); // No content on successful deletion
    } catch (error) { console.error('Delete Todo API error:', error); res.status(500).json({ error: 'Failed to delete task', details: error.message }); }
});

app.get('/lists/summary', auth, async (req, res) => {
    try {
        // Aggregate list counts for non-archived items
        // Aggregate list counts for custom lists (excluding system view tasks that might have a 'list' property but are treated differently)
        // For My Day, only count incomplete tasks
        const listCounts = await Todo.aggregate([
            { $match: { userId: req.user._id, completed: false } }, // Only count incomplete for list counts
            { $group: { _id: '$list', count: { $sum: 1 } } },
            { $project: { name: { $ifNull: ["$_id", "My Day"] }, count: 1, _id: 0 } }
        ]);

        // Specific counts for system views
        const importantCount = await Todo.countDocuments({ userId: req.user._id, isImportant: true, completed: false });
        const completedCount = await Todo.countDocuments({ userId: req.user._id, completed: true });
        const overdueCount = await Todo.countDocuments({ userId: req.user._id, dueDate: { $lt: new Date() }, completed: false });
        const totalCount = await Todo.countDocuments({ userId: req.user._id }); // All tasks, including completed

        res.json({ 
            listCounts, 
            importantCount,
            completedCount, // NEW
            overdueCount,   // NEW
            totalCount, 
            userName: req.user.name,
            tagline: req.user.tagline
        });
    } catch (error) { res.status(500).json({ error: 'Failed to fetch summary', details: error.message }); }
});

// Update PREDEFINED_LISTS to include 'Archive' for frontend logic, but backend still enforces specific list behaviors
// Define system view list names to prevent user manipulation
const SYSTEM_VIEW_LIST_NAMES = ['All', 'My Day', 'Important', 'Planned', 'Completed', 'Overdue'];

app.put('/lists/:oldName/rename', auth, async (req, res) => {
    try {
        const { oldName } = req.params;
        const newName = req.body.newName ? req.body.newName.trim() : null;

        if (!newName) return res.status(400).json({ error: 'New name required.' });
        if (newName === oldName) return res.status(200).json({ message: 'No change needed.' });

        // Prevent renaming if it's a system view or if newName conflicts with a system view
        if (SYSTEM_VIEW_LIST_NAMES.includes(oldName) || SYSTEM_VIEW_LIST_NAMES.includes(newName)) {
            return res.status(403).json({ error: 'Cannot rename system views or to a system view name.' });
        }

        // Check if newName already exists for the user's custom lists
        const existingList = await Todo.findOne({ userId: req.user._id, list: newName });
        if (existingList) {
            return res.status(409).json({ error: `A list named "${newName}" already exists.` });
        }

        const result = await Todo.updateMany({ userId: req.user._id, list: oldName }, { list: newName });
        res.json({ modifiedCount: result.modifiedCount });
    } catch (error) { console.error('Rename List API error:', error); res.status(500).json({ error: 'Internal Server Error', details: error.message }); }
});

app.delete('/lists/:name', auth, async (req, res) => {
    try {
        const { name } = req.params;

        // Prevent deletion of system views
        if (SYSTEM_VIEW_LIST_NAMES.includes(name)) {
            return res.status(403).json({ error: 'Cannot delete system views.' });
        }
        
        // Move tasks from the deleted list to 'My Day'
        const result = await Todo.updateMany({ userId: req.user._id, list: name }, { list: 'My Day' });
        res.json({ modifiedCount: result.modifiedCount, message: `Tasks from list "${name}" moved to "My Day".` });
    } catch (error) { console.error('Delete List API error:', error); res.status(500).json({ error: 'Internal Server Error', details: error.message }); }
});

// Start the server
app.listen(PORT, () => {
    console.log(`To-Do List Backend API running on http://localhost:${PORT}`);
    console.log('----------------------------------------------------');
    console.log('Frontend will connect to this server.');
    console.log('Data is now persisted in MongoDB.');
    console.log('----------------------------------------------------');
});