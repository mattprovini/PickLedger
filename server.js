const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const cors = require('cors');
const User = require('./models/User');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const session = require('express-session');
const logger = require('./logger');

const app = express();

app.use(cors({
	origin: 'http://192.168.56.102:3000',
	credentials: true
}));

app.use(express.json());
app.use(helmet());
app.use(session({
	secret: 'secretkey',
	resave: false,
	saveUninitialized: false,
	cookie: {
		httpOnly: true
	}
}));

// Could not get to work? 
const loginLimiter = rateLimit({
	windowMs: 15 * 60 * 1000,
	max: 10,
	message: { message: "Too many login attempts, try again later"}
	//logger.warn('Too many login attemps issued to $(username)');
});

// Connect to mongo
mongoose.connect('mongodb://192.168.56.103:27017/pickledger');

// Log connection
mongoose.connection.once('open', () => {
	logger.info('Connected to MongoDB');
	console.log("Connected to MongoDB");
});

// register
app.post('/api/register', async (req, res) => {
	let {username, email, password } = req.body;

	// Trim down input to eliminate SQL injection risk
	username = String(username).trim();
	email = String(email).trim();
	password = String(password);

	// Test input
	if(!username || !email || !password) {
		return res.status(400).json({ message: "All fields are required" });
	}
	
	if (username.length < 3 || username.length > 20) {
		return res.status(400).json({ message: "Username length invalid" });
	}
	if (password.length < 6) {
		return res.status(400).json({ message: "Password too short" });
	}

	// Hash password
	const hashedPassword = await bcrypt.hash(password, 10);

	const user = new User({
		username,
		email,
		password: hashedPassword
	});

	await user.save();

	logger.info(`New user registered: ${username}`);	
	
	res.json({ message: "User created" });
});

// Login
app.post('/api/login', async (req, res) => {
	const { username, password } = req.body;

	const user = await User.findOne({ username });

	if (!user) {
		logger.warn(`User not found: ${username}`);
		 return res.json({ message: "User not found" });
	}

	const valid = await bcrypt.compare(password, user.password);

	if(!valid) {
		logger.warn(`Invalid password attempt: ${username}`);
		return res.json({ message: "Invalid password" });		
	}
	// Store session
	req.session.userId = user._id;

	logger.info(`User login: ${username}`);
	
	res.json({ message: "Login successful" });
});

// Logout feature
app.get('/api/logout', (req, res) => {
	req.session.destroy(() => {
		logger.info(`User logged out: ${username}`);
		res.json({ message: "Logged out" });
	});
});

app.get('/api/check-auth', (req, res) => {
	if (req.session.userId) {
		res.json({ loggedIn: true });
	} else {
		res.json({ loggedIn: false });
	}
});

// Log connections
app.get('/api/test', (req, res) => {
	logger.info('Backend working');
	res.json({ message: "Backend working " });
});

app.listen(3000, '0.0.0.0', () => {
	logger.info('Server started on port 3000');
	console.log("Server running on port 3000");
});
