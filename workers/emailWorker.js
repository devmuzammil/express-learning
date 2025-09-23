const nodemailer = require('nodemailer');
const emailQueue = require('../queues/emailQueue.js');
require('dotenv').config();


const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
    }
});


emailQueue.process(async (job) => {
    const { email, username } = job.data;

    const mailOptions = {
        from: process.env.EMAIL_USER,
        to: email,
        subject: "Welcome to Al Hadi Notes",
        text: `Hello ${username},\n\nThank you for signing up at Al-Hadi Notes. Start creating your notes today!\n\nBest,\nThe Team`
    };

    await transporter.sendMail(mailOptions);
    console.log(`Email sent to ${email}`);
});