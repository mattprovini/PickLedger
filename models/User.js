const mongoose = require('mongoose');

const UserSchema = new mongoose.Schema({
	username: String,
	email: String,
	password: String,
	mfaCode: String,
	mfaCodeExpires: Date
});

module.exports = mongoose.model('User', UserSchema);
