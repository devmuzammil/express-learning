const Queue = require('bull');

// Create a queue, using Redis

const emailQueue = new Queue('email-queue', {
    redis: {
        host: '127.0.0.1',
        port: 6379
    }
});

module.exports = emailQueue;