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
app.use(cors(corsOptions));
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
    password: { type: String, required: true },
    tagline: { type: String, default: '' }
});

const User = mongoose.model('User', userSchema);

const todoSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    text: { type: String, required: true }, // Main title (note title or to-do list title)
    completed: { type: Boolean, default: false }, // Overall completion for to-do list (derived or manual)
    list: { type: String, default: 'My Day' }, // Category
    subText: { type: String, default: '' }, // Note content or to-do list description
    isImportant: { type: Boolean, default: false },
    dueDate: { type: Date, default: null }, // Due date for to-do lists
    color: { type: String, default: 'transparent' },
    type: { type: String, enum: ['todo', 'note'], default: 'todo' }, // 'todo' for checklist, 'note' for simple note
    checklistItems: [{ // Array for checklist items
        _id: { type: mongoose.Schema.Types.ObjectId, default: () => new mongoose.Types.ObjectId() }, // Unique ID for each item
        text: { type: String, required: true },
        completed: { type: Boolean, default: false },
        createdAt: { type: Date, default: Date.now }
    }],
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
app.get('/todos/search', auth, async (req, res) => {
    try {
        const { q } = req.query;
        if (!q || q.trim() === '') {
            return res.json([]);
        }

        const query = {
            userId: req.user._id,
            $or: [
                { text: { $regex: q, $options: 'i' } },
                { subText: { $regex: q, $options: 'i' } },
                { 'checklistItems.text': { $regex: q, $options: 'i' } } // Search within checklist items
            ]
        };

        const todos = await Todo.find(query)
                                .sort({ isImportant: -1, dueDate: 1, completed: 1, createdAt: -1 });
        res.json(todos);
    } catch (error) {
        console.error('Search API error:', error);
        res.status(500).json({ error: 'Failed to perform search', details: error.message });
    }
});

app.get('/todos', auth, async (req, res) => {
    try {
        const { list } = req.query; 
        let query = { userId: req.user._id };

        if (list === 'Important') {
            query.isImportant = true;
            query.completed = false;
        } else if (list === 'Planned') {
            query.dueDate = { $ne: null };
            query.completed = false;
        } else if (list === 'Completed') {
            query.completed = true;
        } else if (list === 'Overdue') {
            query.dueDate = { $lt: new Date() };
            query.completed = false;
        } else if (list === 'My Day') { 
            query.list = 'My Day';
            query.completed = false;
        } else if (list && list !== 'All') {
            query.list = list;
            query.completed = false;
        }
        // If All, show everything regardless of completion

        const todos = await Todo.find(query)
                                .sort({ isImportant: -1, dueDate: 1, completed: 1, createdAt: -1 });
        res.json(todos);
    } catch (error) { console.error('Fetch Todos API error:', error); res.status(500).json({ error: 'Failed to fetch', details: error.message }); }
});

app.get('/todos/:id', auth, async (req, res) => {
    try {
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
        const { text, list, subText, isImportant, dueDate, color, type, checklistItems } = req.body;
        if (!text || text.trim() === '') {
            return res.status(400).json({ error: 'Note/Task title is required.' });
        }

        const data = {
            text: text.trim(),
            list: list ? list.trim() : 'My Day',
            subText: subText ? subText.trim() : '',
            isImportant: isImportant || false,
            color: color || 'transparent',
            type: type || 'todo',
            userId: req.user._id
        };

        if (data.type === 'todo') {
            data.subText = subText ? subText.trim() : ''; 
            data.dueDate = dueDate || null;
            data.completed = false; // Default for new todo list
            // Ensure checklistItems are valid and have IDs
            data.checklistItems = (checklistItems || []).filter(item => item.text && item.text.trim() !== '')
                                                        .map(item => {
                                                            const newItem = { ...item, completed: !!item.completed };
                                                            if (!newItem._id || !mongoose.Types.ObjectId.isValid(newItem._id)) {
                                                                newItem._id = new mongoose.Types.ObjectId();
                                                            }
                                                            return newItem;
                                                        });
            // Set overall completed status if all checklist items are completed on creation
            if (data.checklistItems.length > 0 && data.checklistItems.every(item => item.completed)) {
                data.completed = true;
            }
        } else { // type === 'note'
            data.dueDate = null;
            data.completed = false;
            data.checklistItems = [];
        }

        const todo = new Todo(data);
        await todo.save();
        res.status(201).json(todo);
    } catch (error) { console.error('Add Todo API error:', error); res.status(400).json({ error: 'Failed to add', details: error.message }); }
});

app.put('/todos/:id', auth, async (req, res) => {
    try {
        const updates = req.body;
        const currentTodo = await Todo.findOne({ _id: req.params.id, userId: req.user._id });
        if (!currentTodo) return res.status(404).json({ error: 'Not found' });

        // If list is provided, trim it
        if (updates.list) updates.list = updates.list.trim();
        // If text is provided, trim it
        if (updates.text) updates.text = updates.text.trim();
        // If subText is provided, trim it
        if (updates.subText) updates.subText = updates.subText.trim();


        // Handle type change logic
        if (updates.type && updates.type !== currentTodo.type) {
            if (updates.type === 'note') {
                updates.completed = false;
                updates.dueDate = null;
                updates.checklistItems = [];
            } else if (updates.type === 'todo') {
                updates.subText = ''; // Clear description when converting to todo
                updates.completed = false; // Reset completion when converting to todo
                // Keep existing checklistItems if present, otherwise initialize empty
                if (!updates.checklistItems) updates.checklistItems = [];
            }
        }

        // SubText is allowed for both notes (content) and todos (description)

        // Handle checklistItems updates
        if (updates.checklistItems !== undefined) {
             updates.checklistItems = updates.checklistItems.filter(item => item.text && item.text.trim() !== '')
                                                            .map(item => {
                                                                const newItem = { ...item, completed: !!item.completed };
                                                                if (!newItem._id || !mongoose.Types.ObjectId.isValid(newItem._id)) {
                                                                    newItem._id = new mongoose.Types.ObjectId();
                                                                }
                                                                return newItem;
                                                            });
             // Update overall 'completed' status based on checklist items if it's a 'todo' type
             if (currentTodo.type === 'todo' || (updates.type && updates.type === 'todo')) {
                if (updates.checklistItems.length > 0 && updates.checklistItems.every(item => item.completed)) {
                    updates.completed = true;
                } else {
                    updates.completed = false;
                }
             }
        } else if (currentTodo.type === 'todo' && updates.completed !== undefined) {
            // If main completed status is updated, but checklistItems wasn't
            // And all sub items were completed, but now it's uncompleted manually
            // We should uncomplete all sub items too.
            // Or if all sub items are completed, and we manually complete the parent.
            if (updates.completed === true && currentTodo.checklistItems.length > 0) {
                 updates.checklistItems = currentTodo.checklistItems.map(item => ({...item.toObject(), completed: true}));
            } else if (updates.completed === false && currentTodo.checklistItems.length > 0 && currentTodo.checklistItems.every(item => item.completed)) {
                updates.checklistItems = currentTodo.checklistItems.map(item => ({...item.toObject(), completed: false}));
            }
        }


        const todo = await Todo.findOneAndUpdate({ _id: req.params.id, userId: req.user._id }, updates, { new: true, runValidators: true });
        if (!todo) return res.status(404).json({ error: 'Not found' });
        res.json(todo);
    } catch (error) { console.error('Update Todo API error:', error); res.status(400).json({ error: 'Failed to update', details: error.message }); }
});

app.delete('/todos/:id', auth, async (req, res) => {
    try {
        if (!mongoose.Types.ObjectId.isValid(req.params.id)) {
            return res.status(400).json({ error: 'Invalid Task ID format' });
        }
        const todo = await Todo.findOneAndDelete({ _id: req.params.id, userId: req.user._id });
        if (!todo) {
            return res.status(404).json({ error: 'Task not found or unauthorized' });
        }
        res.status(204).send();
    } catch (error) { console.error('Delete Todo API error:', error); res.status(500).json({ error: 'Failed to delete task', details: error.message }); }
});

// Define system view list names to prevent user manipulation (also used in frontend)
const SYSTEM_VIEW_LIST_NAMES = ['All', 'My Day', 'Important', 'Planned', 'Completed', 'Overdue'];

app.get('/lists/summary', auth, async (req, res) => {
    try {
        // Aggregate list counts for custom categories AND "My Day" (incomplete todos and all notes)
        const listCounts = await Todo.aggregate([
            { $match: { userId: req.user._id } },
            { 
                $project: {
                    _id: 0,
                    list: '$list',
                    isCountable: { // Logic for counting in custom lists/My Day
                        $cond: {
                            if: { 
                                $or: [
                                    { $eq: ["$type", "note"] },
                                    { $and: [{ $eq: ["$type", "todo"] }, { $eq: ["$completed", false] }] }
                                ]
                            },
                            then: 1,
                            else: 0
                        }
                    }
                }
            },
            { $group: { _id: '$list', count: { $sum: '$isCountable' } } },
            { $project: { name: { $ifNull: ["$_id", "My Day"] }, count: 1, _id: 0 } }
        ]);

        // Specific counts for system views
        const importantCount = await Todo.countDocuments({ userId: req.user._id, isImportant: true, completed: false });
        const completedCount = await Todo.countDocuments({ userId: req.user._id, completed: true });
        const plannedCount = await Todo.countDocuments({ userId: req.user._id, dueDate: { $ne: null }, completed: false });
        const overdueCount = await Todo.countDocuments({ userId: req.user._id, dueDate: { $lt: new Date() }, completed: false });
        const totalCount = await Todo.countDocuments({ userId: req.user._id }); // All notes and tasks

        res.json({ 
            listCounts, 
            importantCount,
            completedCount,
            plannedCount,
            overdueCount,
            totalCount, 
            userName: req.user.name,
            tagline: req.user.tagline
        });
    } catch (error) { console.error('Fetch Summary API error:', error); res.status(500).json({ error: 'Failed to fetch summary', details: error.message }); }
});

app.put('/lists/:oldName/rename', auth, async (req, res) => {
    try {
        const { oldName } = req.params;
        const newName = req.body.newName ? req.body.newName.trim() : null;

        if (!newName) return res.status(400).json({ error: 'New name required.' });
        if (newName === oldName) return res.status(200).json({ message: 'No change needed.' });

        if (SYSTEM_VIEW_LIST_NAMES.map(n => n.toLowerCase()).includes(oldName.toLowerCase()) || 
            SYSTEM_VIEW_LIST_NAMES.map(n => n.toLowerCase()).includes(newName.toLowerCase())) {
            return res.status(403).json({ error: 'Cannot rename system categories or to a system category name.' });
        }

        const existingList = await Todo.findOne({ userId: req.user._id, list: newName });
        if (existingList) {
            return res.status(409).json({ error: `A category named "${newName}" already exists.` });
        }

        const result = await Todo.updateMany({ userId: req.user._id, list: oldName }, { list: newName });
        res.json({ modifiedCount: result.modifiedCount });
    } catch (error) { console.error('Rename List API error:', error); res.status(500).json({ error: 'Internal Server Error', details: error.message }); }
});

app.delete('/lists/:name', auth, async (req, res) => {
    try {
        const { name } = req.params;

        if (SYSTEM_VIEW_LIST_NAMES.map(n => n.toLowerCase()).includes(name.toLowerCase())) {
            return res.status(403).json({ error: 'Cannot delete system categories.' });
        }
        
        const result = await Todo.updateMany({ userId: req.user._id, list: name }, { list: 'My Day' });
        res.json({ modifiedCount: result.modifiedCount, message: `Notes/tasks from category "${name}" moved to "My Day".` });
    } catch (error) { console.error('Delete List API error:', error); res.status(500).json({ error: 'Internal Server Error', details: error.message }); }
});

// --- Health Check & Monitoring ---
app.get('/health', (req, res) => {
    res.status(200).json({ 
        status: 'OK', 
        uptime: process.uptime(),
        timestamp: new Date().toISOString(),
        environment: process.env.NODE_ENV || 'development'
    });
});

// --- Global Error Handler ---
app.use((err, req, res, next) => {
    const timestamp = new Date().toISOString();
    const errorDetails = {
        message: err.message,
        stack: process.env.NODE_ENV === 'development' ? err.stack : undefined,
        path: req.path,
        method: req.method,
        timestamp
    };

    console.error(`[${timestamp}] Unhandled Exception:`, errorDetails);

    res.status(err.status || 500).json({
        error: 'Internal Server Error',
        ...errorDetails
    });
});

// Start the server
app.listen(PORT, () => {
    console.log(`To-Do List Backend API running on http://localhost:${PORT}`);
    console.log('----------------------------------------------------');
    console.log('Frontend will connect to this server.');
    console.log('Data is now persisted in MongoDB.');
    console.log(`Health check available at http://localhost:${PORT}/health`);
    console.log('----------------------------------------------------');
});