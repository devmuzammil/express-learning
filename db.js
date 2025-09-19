const mongoose = require('mongoose');
require('dotenv').config();
mongoose.connect(process.env.MONGO_URI).then(() => console.log('DB connected')).catch(err => console.log(err));

const notesSchema = new mongoose.Schema({
    title: { type: String, required: true },
    content: { type: String, required: true },
    userId: {
        type: mongoose.Schema.Types.ObjectId, ref: 'User'
    },
    sharedWith:[{
        type: mongoose.Schema.Types.ObjectId, ref: 'User'
    }],
    createdAt: { type: Date, default: Date.now }
});

const userSchema = new mongoose.Schema({
    username: {
        type: String,
        required: true,
        unique: true
    },
    email: {
        type: String,
        required: true,
        unique: true
    },
    password: {
        type: String,
        required: true,
    },
    role: {
        type: String,
        enum: ['user', 'admin'],
        default: 'user'
    }
});

const profileSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', unique: true },
    bio: String,
    avatar: String
});

const Note = mongoose.model('Note', notesSchema);
const User = mongoose.model('User', userSchema);
const Profile = mongoose.model('Profile', profileSchema);

module.exports = {
    Note,
    User
};