const express = require('express');
const { model } = require('./schema');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const bodyParser = require('body-parser');
const cors = require('cors');
require('dotenv').config();

const app = express();
app.use(cors());
app.use(bodyParser.json());

// MongoDB Connection
mongoose.connect(process.env.MONGO_URI).then(() => console.log('Connected to MongoDB'))
    .catch(err => console.error('Failed to connect to MongoDB', err));

// Define User Schema and Model
const userSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    role: { type: String, required: true, enum: ['admin', 'staff', 'student'] }
});

const User = mongoose.model('User', userSchema);
app.post('/api/register/rm', authenticateToken, authorizeRole('admin'), async (req, res) => {
    const { username, role } = req.body;

    // Validate input
    if (!username || !role) {
        return res.status(400).send("Username and role are required");
    }

    try {
        // Find user with the given username and role
        const user = await User.findOne({ username, role });

        // Check if user was found
        if (!user) {
            console.log(`User with username '${username}' and role '${role}' not found`);
            return res.status(404).send("User not found");
        }

        // Delete the user
        await User.deleteOne({ username, role });

        // Send success response
        res.send("Deleted");

    } catch (error) {
        // Log the error and send a server error response
        console.error(`Error occurred while deleting user: ${error.message}`);
        res.status(500).send("Internal Server Error");
    }
});

// Registration API
app.post('/api/register', authenticateToken, authorizeRole('admin'), async (req, res) => {
    const { username, password, role } = req.body;

    try {
        const existingUser = await User.findOne({ username });
        if (existingUser) {
            return res.status(400).json({ message: 'Username already exists' });
        }

        // Hash the password before saving
        const hashedPassword = await bcrypt.hash(password, 10);

        const newUser = new User({
            username,
            password: hashedPassword,
            role
        });

        await newUser.save();
        res.status(201).json({ message: 'User registered successfully' });
    } catch (err) {
        res.status(500).json({ message: 'Error registering user', error: err });
    }
});

// Delete All Documents API
app.post('/deleteAll', authenticateToken, authorizeRole('admin'), async (req, res) => {
    try {
        const result = await model.deleteMany({});

        if (result.deletedCount > 0) {
            res.status(200).send({ message: 'All documents deleted successfully', data: result });
        } else {
            res.status(404).send({ message: 'No documents found to delete' });
        }
    } catch (error) {
        res.status(500).send({ message: 'Error deleting documents', error: error.message });
    }
});

// Login API
app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;
    try {
        const user = await User.findOne({ username });

        if (!user) {
            return res.status(401).json({ message: 'Invalid credentials' });
        }

        // Compare the provided password with the hashed password in the database
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(401).json({ message: 'Invalid credentials' });
        }

        // Generate a JWT token
        const token = jwt.sign({ username: user.username, role: user.role }, process.env.JWT_SECRET, { expiresIn: '192h' });
        res.json({ token, role: user.role });
    } catch (err) {
        res.status(500).json({ message: 'Error during login', error: err });
    }
});

// POST Data AP
app.post('/post', async (req, res) => {
    const date = new Date();
    const options = {
        year: 'numeric',
        month: '2-digit',
        day: '2-digit',
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit',
        hour12: true,
        timeZone: 'Asia/Kolkata' // Adjust time zone as needed
    };

    const formattedTime = date.toLocaleString('en-US', options);

    const { name, registerNo, gender, graduate, hsc, myambition, dept, dob, arr } = req.body;

    const response = new model({
        name,
        registerNo,
        gender,
        graduate,
        hsc,
        myambition,
        dept,
        dob,
        date: formattedTime,
        arr,
        lastUpdated: Date.now()
    });

    try {
        const savedResponse = await response.save();
        res.json({ id: savedResponse._id, message: 'Data saved successfully', savedResponse });
    } catch (err) {
        res.status(400).send({ message: err.message });
    }
});

// Delete Document by ID API
app.delete('/delete/:id', authenticateToken, authorizeRole('admin'), async (req, res) => {
    try {
        const id = req.params.id;
        const response = await model.findByIdAndDelete(id);
        res.send("Deleted");
    } catch (err) {
        res.status(400).send({ message: err.message });
    }
});

// Update Document by ID API
app.put('/update/:id', authenticateToken, authorizeRoles(['student', 'admin']), async (req, res) => {
    const id = req.params.id;
    const { arr } = req.body;

    try {
        const response = await model.updateOne(
            { _id: id },
            { arr, lastUpdated: Date.now() }
        );
        res.send('Updated');
    } catch (err) {
        res.status(400).send({ message: err.message });
    }
});

// Authentication Middleware
function authenticateToken(req, res, next) {
    const token = req.header('Authorization')?.split(' ')[1];
    if (!token) return res.sendStatus(401);

    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) return res.sendStatus(403);
        req.user = user;
        next();
    });
}

// Role-based Authorization Middleware
function authorizeRole(role) {
    return (req, res, next) => {
        if (req.user.role !== role) return res.sendStatus(403);
        next();
    };
}

// Multiple Roles Authorization Middleware
function authorizeRoles(roles) {
    return (req, res, next) => {
        if (!roles.includes(req.user.role)) return res.sendStatus(403);
        next();
    };
}

// Protected Admin Data API
app.get('/api/admin', authenticateToken, authorizeRole('admin'), (req, res) => {
    res.json({ message: 'This is protected admin data' });
});


// // API to check if a student's name exists using URL params
app.get('/api/check-name/:registerNo',authenticateToken, authorizeRoles(['student', 'admin']), async (req, res) => {
    const { registerNo } = req.params;  // Get the name from the URL parameters
    console.log(registerNo)
    if (!registerNo) {
        return res.status(400).json({ message: 'Name is required' });
    }

    try {
        // Check if the student name exists in the database
        const student = await model.findOne({registerNo});
        console.log(student)
        if (student) {
            // If student exists, send a response indicating the name is taken
            return res.status(200).json({ exists: true, message: 'Name already exists' });
        } else {
            // If student does not exist, send a response indicating the name is available
            return res.status(200).json({ exists: false, message: 'Name is available' });
        }
    } catch (error) {
        console.error('Error checking name:', error);
        return res.status(500).json({ message: 'Internal server error' });
    }
});


// Get All Documents API
app.get('/get', authenticateToken, authorizeRoles(['staff', 'admin']), async (req, res) => {
    try {
        const response = await model.find({});
        res.json({ response });
    } catch (err) {
        res.status(500).send({ message: 'Error retrieving documents', error: err.message });
    }
});

// Server Setup
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});
